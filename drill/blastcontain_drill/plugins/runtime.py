"""Rootless local Podman worker with host-owned budgets and broker bindings.

No host execution fallback, package installation, dynamic entry-point loading,
network grant, socket mount, or caller-provided container arguments.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import math
import shutil

# Only fixed local Podman argument vectors are executed.
import subprocess  # nosec B404
import sys
import time
from typing import Awaitable, Callable
import uuid

from ..contracts import AcceptanceRecord, ContractError, Injection, PluginManifest, ScenarioSpec
from .catalog import check_acceptance, check_profile
from .protocol import MAX_FRAME, ProtocolError, decode, encode


class WorkerError(RuntimeError):
    """Execution failed or could not establish its required isolation profile."""


class BudgetExceeded(WorkerError):
    pass


# This is a private container tmpfs, never a host temporary file.
_CONTAINER_TMP = "/tmp"  # nosec B108


@dataclass(frozen=True)
class WorkerLimits:
    wall_seconds: float = 30.0
    max_calls: int = 4
    max_messages: int = 128
    max_frame_bytes: int = MAX_FRAME
    max_stderr_bytes: int = 16384

    def __post_init__(self):
        if (
            type(self.wall_seconds) not in (int, float)
            or not math.isfinite(self.wall_seconds)
            or not 0 < self.wall_seconds <= 300
        ):
            raise ValueError("Worker wall time must be in (0, 300] seconds")
        for name, maximum in [
            ("max_calls", 1000),
            ("max_messages", 4096),
            ("max_frame_bytes", MAX_FRAME),
            ("max_stderr_bytes", MAX_FRAME),
        ]:
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"Invalid {name}")


@dataclass(frozen=True)
class BrokerContext:
    scenario_id: str
    deadline: float
    scope_id: str = ""

    def remaining(self):
        return max(0.0, self.deadline - time.monotonic())


BrokerHandler = Callable[[Injection, BrokerContext], Awaitable[dict]]
ConversationHandler = Callable[[dict, BrokerContext], Awaitable[dict]]


@dataclass(frozen=True)
class BrokerCall:
    channel: str
    call_id: int
    scenario_id: str
    injection: Injection | None
    result: dict | None
    error: str | None = None
    operation: str = "call"


@dataclass(frozen=True)
class WorkerResult:
    """Worker-supplied claims, separate from host-observed broker calls."""

    claims: dict
    calls: tuple[BrokerCall, ...]


async def _read_capped(stream, limit):
    chunks = bytearray()
    while True:
        chunk = await stream.read(min(8192, limit + 1 - len(chunks)))
        if not chunk:
            return bytes(chunks)
        chunks.extend(chunk)
        if len(chunks) > limit:
            raise WorkerError("Runtime output exceeded its byte limit")


async def _discard(stream):
    """Drain without retaining data, including while the container is being stopped."""
    while await stream.read(65536):
        pass


def _drain_pipes(process):
    return [
        asyncio.create_task(_discard(stream))
        for stream in (process.stdout, process.stderr)
        if stream is not None
    ]


async def _reap(process, drains=None):
    """Bound client termination even when its pipes are full or never reach EOF."""
    drains = _drain_pipes(process) if drains is None else drains
    try:
        if process.stdin is not None:
            process.stdin.close()
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        await asyncio.wait_for(asyncio.gather(process.wait(), *drains), 2)
    except TimeoutError as exc:
        raise WorkerError("Subprocess cleanup exceeded its two-second limit") from exc
    finally:
        for task in drains:
            if not task.done():
                task.cancel()
        await asyncio.gather(*drains, return_exceptions=True)
        # Process exposes no public pipe-close API. Close the asyncio transport
        # as well: a descendant may retain a pipe after its parent has exited.
        # This is tested on the supported Python 3.11/3.12 platforms.
        process._transport.close()


async def _control(command, timeout=10.0):
    process = await asyncio.create_subprocess_exec(
        *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    readers = [
        asyncio.create_task(_read_capped(process.stdout, 262144)),
        asyncio.create_task(_read_capped(process.stderr, 16384)),
    ]
    waiter = asyncio.create_task(process.wait())
    try:
        stdout, stderr, code = await asyncio.wait_for(
            asyncio.gather(*readers, waiter),
            timeout,
        )
        if code:
            raise WorkerError(
                f"Podman control operation failed ({code}): {stderr.decode(errors='replace')[:500]}"
            )
        return stdout
    finally:
        # gather does not cancel siblings when one capped reader fails.
        for task in [*readers, waiter]:
            if not task.done():
                task.cancel()
        await asyncio.gather(*readers, waiter, return_exceptions=True)
        await _reap(process)


@dataclass(frozen=True)
class LocalImageProbe:
    available: bool
    diagnostic: str


def probe_local_image(image_id: str) -> LocalImageProbe:
    """Read-only availability with bounded, non-sensitive failure diagnostics."""
    from ..contracts.plugins import artifact_digest

    artifact_digest(image_id)
    if sys.platform != "linux":
        return LocalImageProbe(False, "unsupported_platform")
    executable = shutil.which("podman")
    if not executable:
        return LocalImageProbe(False, "podman_unavailable")
    stage = "host_info"
    try:
        # Trusted binary and fixed read-only arguments.
        info = subprocess.run(  # nosec B603
            [executable, "--remote=false", "info", "--format={{json .Host}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            # A cold rootless engine can take more than three seconds on CI.
            # This is a read-only discovery query, not a worker execution grant.
            timeout=10,
            check=True,
        )
        host = json.loads(info.stdout)
        if type(host) is not dict or type(host.get("security")) is not dict:
            return LocalImageProbe(False, "host_info_invalid")
        controllers = host.get("cgroupControllers", [])
        if type(controllers) is not list or any(type(c) is not str for c in controllers):
            return LocalImageProbe(False, "host_info_invalid")
        checks = {
            "rootless_unavailable": host["security"].get("rootless") is True,
            "seccomp_unavailable": host["security"].get("seccompEnabled") is True,
            "cgroups_v2_unavailable": host.get("cgroupVersion") == "v2",
            "memory_controller_unavailable": "memory" in controllers,
            "pids_controller_unavailable": "pids" in controllers,
        }
        for diagnostic, available in checks.items():
            if not available:
                return LocalImageProbe(False, diagnostic)
        # Validated sha256 ID; no shell or caller-supplied command.
        stage = "image_exists"
        exists = subprocess.run(  # nosec B603
            [executable, "--remote=false", "image", "exists", image_id],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        available = exists.returncode == 0
        diagnostic = "available"
        if not available:
            diagnostic = "image_missing" if exists.returncode == 1 else "image_exists_failed"
        return LocalImageProbe(available, diagnostic)
    except subprocess.TimeoutExpired:
        return LocalImageProbe(False, stage + "_timeout")
    except (OSError, subprocess.SubprocessError, ValueError):
        return LocalImageProbe(False, stage + "_failed")


def local_image_available(image_id: str) -> bool:
    return probe_local_image(image_id).available


def validate_isolation(info, image_id, timeout_seconds):
    """Inspect the stopped container before allowing plugin code to start."""
    host, config = info.get("HostConfig", {}), info.get("Config", {})
    expected = {
        "NetworkMode": "none",
        "ReadonlyRootfs": True,
        "Privileged": False,
        "PidMode": "private",
        "IpcMode": "private",
        "UTSMode": "private",
        "Memory": 268435456,
        "MemorySwap": 268435456,
        "PidsLimit": 64,
        "AutoRemove": True,
    }
    if any(host.get(key) != value for key, value in expected.items()):
        raise WorkerError("Container inspection did not confirm the isolation profile")
    if (
        info.get("Image", "").removeprefix("sha256:") != image_id.removeprefix("sha256:")
        or config.get("User") != "65532:65532"
    ):
        raise WorkerError("Container image or user differs from the approved profile")
    if config.get("Timeout") != timeout_seconds or config.get("StopTimeout") != 0:
        raise WorkerError("Container timeout differs from the bounded profile")
    if host.get("RestartPolicy", {}).get("Name") != "no":
        raise WorkerError("Container restart policy must be disabled")
    if (
        host.get("Binds")
        or host.get("Devices")
        or host.get("VolumesFrom")
        or host.get("CapAdd")
        or info.get("Mounts")
        or info.get("EffectiveCaps")
        or host.get("PortBindings")
    ):
        raise WorkerError("Unexpected mounts, devices, privileges or published ports")
    if host.get("SecurityOpt") != ["no-new-privileges"]:
        raise WorkerError("Unexpected security options")
    tmpfs = host.get("Tmpfs", {})
    if set(tmpfs) != {_CONTAINER_TMP} or not {"noexec", "nosuid", "nodev", "size=16m"} <= set(
        tmpfs[_CONTAINER_TMP].split(",")
    ):
        raise WorkerError("Unexpected writable filesystem configuration")
    if host.get("LogConfig", {}).get("Type") != "none":
        raise WorkerError("Worker logging must be disabled outside bounded streams")


class PodmanWorker:
    def __init__(
        self,
        manifest: PluginManifest,
        acceptances: list[AcceptanceRecord],
        *,
        bindings: dict[str, BrokerHandler] | None = None,
        limits: WorkerLimits | None = None,
        conversations: dict[str, ConversationHandler] | None = None,
    ):
        # Detach caller-owned mutable metadata. Revalidate on launch as well.
        self.manifest = PluginManifest.from_dict(manifest.to_dict())
        self.acceptances = tuple(AcceptanceRecord.from_dict(a.to_dict()) for a in acceptances)
        self.bindings = dict(bindings or {})
        self.conversations = dict(conversations or {})
        self._scope_id = uuid.uuid4().hex
        self.limits = limits or WorkerLimits()
        self.name = "bc-drill-worker-" + uuid.uuid4().hex
        self.calls: list[BrokerCall] = []
        self.process = None
        self._stderr_task = None
        self._busy = False
        self._request_id = 0
        self._call_id = 0
        self._messages = 0
        self._deadline = 0.0
        self._scenario: ScenarioSpec | None = None
        self._prepared = False
        self._closed = False
        self._executable = None
        self._request_task = None
        self._cleanup_task = None
        self._watchdog = None
        self._expired = False

    def _remaining(self):
        value = self._deadline - time.monotonic()
        if value <= 0:
            raise BudgetExceeded("Worker wall-clock budget exhausted")
        return value

    def _command(self, *args):
        return [self._executable, "--remote=false", *args]

    async def start(self):
        if self.process is not None or self._closed:
            raise WorkerError("A worker instance can only be started once")
        check_profile(self.manifest)
        check_acceptance(self.manifest, self.acceptances)
        if set(self.bindings) - {"target", "attacker", "evaluator"}:
            raise ContractError("Unknown broker binding")
        if set(self.conversations) - {"target", "attacker", "evaluator"}:
            raise ContractError("Unknown conversation binding")
        for grant in self.manifest.access_requests:
            parts = grant.split(".")
            bindings = self.conversations if len(parts) == 3 else self.bindings
            if parts[1] not in bindings:
                raise ContractError(f"Missing trusted binding for {grant}")
        if sys.platform != "linux":
            raise WorkerError("This profile requires local Linux Podman; no host fallback")
        self._executable = shutil.which("podman")
        if not self._executable:
            raise WorkerError("This profile requires local Linux Podman; no host fallback")
        self._deadline = time.monotonic() + self.limits.wall_seconds
        try:
            info = json.loads(
                await _control(self._command("info", "--format=json"), self._remaining())
            )
            host = info.get("host", {})
            if (
                not host.get("security", {}).get("rootless")
                or host.get("cgroupVersion") != "v2"
                or not host.get("security", {}).get("seccompEnabled")
            ):
                raise WorkerError("This profile requires rootless Podman, cgroup v2 and seccomp")
            if not {"memory", "pids"} <= set(host.get("cgroupControllers", [])):
                raise WorkerError("Memory and PID controllers must be delegated")
            timeout_seconds = max(1, math.ceil(self._remaining()))
            command = self._command(
                "create",
                "-i",
                "--name",
                self.name,
                "--pull=never",
                "--rm",
                f"--timeout={timeout_seconds}",
                "--stop-timeout=0",
                "--restart=no",
                "--systemd=false",
                "--health-cmd=none",
                "--network=none",
                "--read-only",
                "--read-only-tmpfs=false",
                "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m",
                "--user=65532:65532",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit=64",
                "--memory=256m",
                "--memory-swap=256m",
                "--http-proxy=false",
                "--image-volume=ignore",
                "--ipc=private",
                "--pid=private",
                "--uts=private",
                "--cgroupns=private",
                "--log-driver=none",
                "--no-hosts",
                "--unsetenv-all",
                "--env=HOME=/tmp",
                "--env=PATH=/usr/local/bin:/usr/bin:/bin",
                "--env=PYTHONDONTWRITEBYTECODE=1",
                self.manifest.artifact_digest,
            )
            await _control(command, self._remaining())
            container = json.loads(
                await _control(self._command("inspect", self.name), self._remaining())
            )[0]
            validate_isolation(container, self.manifest.artifact_digest, timeout_seconds)
            self.process = await asyncio.create_subprocess_exec(
                *self._command("start", "-a", "-i", self.name),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=self.limits.max_frame_bytes,
            )
            self._stderr_task = asyncio.create_task(
                _read_capped(self.process.stderr, self.limits.max_stderr_bytes)
            )
            self._watchdog = asyncio.create_task(self._watch_deadline())
            return self
        except BaseException:
            await self.close()
            raise

    async def __aenter__(self):
        return await self.start()

    async def __aexit__(self, *exc):
        await self.close()

    async def _watch_deadline(self):
        await asyncio.sleep(max(0.0, self._deadline - time.monotonic()))
        self._expired = True
        await self.close()

    async def _write(self, message):
        self._messages += 1
        if self._messages > self.limits.max_messages:
            raise BudgetExceeded("Worker message budget exhausted")
        self.process.stdin.write(encode(message, self.limits.max_frame_bytes))
        await self.process.stdin.drain()

    async def _read(self):
        if self._stderr_task.done():
            self._stderr_task.result()  # surface stderr overflow, never let its pipe block unnoticed
        line_task = asyncio.create_task(self.process.stdout.readline())
        try:
            watched = {line_task}
            if not self._stderr_task.done():
                watched.add(self._stderr_task)
            done, _ = await asyncio.wait(
                watched, timeout=self._remaining(), return_when=asyncio.FIRST_COMPLETED
            )
            if not done:
                raise BudgetExceeded("Worker wall-clock budget exhausted")
            if self._stderr_task in done:
                self._stderr_task.result()
            data = await asyncio.wait_for(line_task, self._remaining())
        except (ValueError, asyncio.LimitOverrunError) as exc:
            raise ProtocolError("Worker frame exceeds byte limit") from exc
        finally:
            if not line_task.done():
                line_task.cancel()
            await asyncio.gather(line_task, return_exceptions=True)
        if not data:
            raise WorkerError("Worker exited before completing the request")
        self._messages += 1
        if self._messages > self.limits.max_messages:
            raise BudgetExceeded("Worker message budget exhausted")
        return decode(data, self.limits.max_frame_bytes)

    async def _broker(self, message):
        channel = message["channel"]
        if message["call_id"] != self._call_id + 1:
            raise ProtocolError("Replayed or out-of-order broker call")
        conversation = message["type"] == "conversation"
        if message["protocol"] != self.manifest.adapter_api:
            raise ProtocolError("Worker protocol differs from its reviewed adapter API")
        scope = f"broker.{channel}" + (".conversation" if conversation else "")
        bindings = self.conversations if conversation else self.bindings
        if scope not in self.manifest.access_requests or channel not in bindings:
            raise WorkerError("Broker channel not granted")
        if len(self.calls) >= self.limits.max_calls:
            raise BudgetExceeded("Worker target/model call budget exhausted")
        if self._messages >= self.limits.max_messages:
            raise BudgetExceeded("No message budget remains for a broker reply")
        injection = None if conversation else Injection.from_dict(message["payload"])
        payload = message["payload"] if conversation else injection
        self._call_id = message["call_id"]
        index = len(self.calls)
        context = BrokerContext(self._scenario.id, self._deadline, self._scope_id)
        self.calls.append(
            BrokerCall(
                channel,
                self._call_id,
                context.scenario_id,
                injection,
                None,
                "incomplete",
                message["type"],
            )
        )
        try:
            result = await asyncio.wait_for(bindings[channel](payload, context), self._remaining())
            reply = {
                "protocol": self.manifest.adapter_api,
                "type": "reply",
                "id": self._request_id,
                "call_id": self._call_id,
                "result": result,
            }
            encode(reply, self.limits.max_frame_bytes)  # cap trusted-handler output too
            self.calls[index] = BrokerCall(
                channel,
                self._call_id,
                context.scenario_id,
                injection,
                result,
                operation=message["type"],
            )
            await self._write(reply)
        except BaseException as exc:
            self.calls[index] = BrokerCall(
                channel,
                self._call_id,
                context.scenario_id,
                injection,
                None,
                type(exc).__name__,
                message["type"],
            )
            raise

    async def _request(self, method, params):
        if self.process is None or self._closed:
            raise WorkerError("Worker is not running")
        if self._busy:
            raise WorkerError("Concurrent worker requests are not supported")
        self._busy = True
        self._request_task = asyncio.current_task()
        try:
            async with asyncio.timeout(self._remaining()):
                self._request_id += 1
                await self._write(
                    {
                        "protocol": self.manifest.adapter_api,
                        "type": "request",
                        "id": self._request_id,
                        "method": method,
                        "params": params,
                    }
                )
                while True:
                    message = await self._read()
                    if message["protocol"] != self.manifest.adapter_api:
                        raise ProtocolError("Worker protocol differs from its reviewed adapter API")
                    if message["id"] != self._request_id:
                        raise ProtocolError("Response request ID mismatch")
                    if message["type"] == "result":
                        return message["result"]
                    if message["type"] in ("call", "conversation") and method == "execute":
                        await self._broker(message)
                    elif message["type"] == "error":
                        raise WorkerError("Plugin error: " + message["error"][:500])
                    else:
                        raise ProtocolError("Unexpected message for this lifecycle phase")
        except TimeoutError as exc:
            await self.close()
            raise BudgetExceeded("Worker wall-clock budget exhausted") from exc
        except asyncio.CancelledError as exc:
            await self.close()
            if self._expired:
                raise BudgetExceeded("Worker wall-clock budget exhausted") from exc
            raise
        except BaseException:
            await self.close()
            raise
        finally:
            self._busy = False
            self._request_task = None

    async def prepare(self, config=None):
        if config not in (None, {}):
            raise ContractError("This profile accepts empty configuration only")
        if self._prepared:
            raise WorkerError("Worker is already prepared")
        await self._request("prepare", {})
        self._prepared = True

    async def reset(self, scenario: ScenarioSpec):
        if not self._prepared:
            raise WorkerError("Prepare the worker before reset")
        await self._request("reset", scenario.to_dict())
        self._scenario = scenario
        self._scope_id = uuid.uuid4().hex

    async def execute(self):
        if self._scenario is None:
            raise WorkerError("Reset the worker with a scenario before execution")
        begin = len(self.calls)
        claims = await self._request("execute", {})
        return WorkerResult(claims, tuple(self.calls[begin:]))

    async def finish(self):
        try:
            await self._request("close", {})
        finally:
            await self.close()

    async def cancel(self):
        """Independent stop: does not ask the plugin to cooperate."""
        await self.close()

    async def close(self):
        request_task = self._request_task
        external = request_task is not None and request_task is not asyncio.current_task()
        if (
            external
            and not request_task.done()
            and not request_task.cancelling()
            and self._cleanup_task is None
        ):
            request_task.cancel()
        if self._cleanup_task is None:
            self._closed = True
            self._cleanup_task = asyncio.create_task(self._cleanup())
        await asyncio.shield(self._cleanup_task)
        if external:
            await asyncio.gather(request_task, return_exceptions=True)

    async def _cleanup(self):
        self._closed = True
        if self._watchdog is not None and not self._watchdog.done():
            self._watchdog.cancel()
            await asyncio.gather(self._watchdog, return_exceptions=True)
        if self._stderr_task is not None:
            if not self._stderr_task.done():
                self._stderr_task.cancel()
            await asyncio.gather(self._stderr_task, return_exceptions=True)
        # Drain before Podman removal: a blocked attach pipe can also prevent
        # the engine's stop/remove operation from completing.
        drains = _drain_pipes(self.process) if self.process is not None else []
        cleanup_error = None
        if self._executable:
            try:
                await _control(
                    self._command("rm", "-f", "--time=0", "--ignore", self.name), timeout=10
                )
            except Exception as exc:
                cleanup_error = exc
        if self.process is not None:
            try:
                await _reap(self.process, drains)
            except Exception as exc:
                cleanup_error = cleanup_error or exc
        if cleanup_error:
            raise WorkerError(
                f"Worker cleanup failed; inspect container {self.name}"
            ) from cleanup_error
