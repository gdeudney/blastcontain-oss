"""Thin lifecycle CLI over shared suite services."""

import asyncio
from functools import wraps
import os
from pathlib import Path
import re

import click
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from ..contracts import ContractError, ScenarioSpec
from .artifacts import canonical, read_document, safe_path, write_document
from .durable import (
    execute_run,
    inspect_run,
    legacy_projection,
    purge_expired_raw,
    rerun_run,
    verify_run,
)
from .lock import SuiteLock
from .privacy import mkdir_private, read_private, write_private
from .review import record_decision
from .run_store import request_cancel
from .service import ExecutionInputs
from .signatures import Signer

INPUT = click.Path(exists=True, dir_okay=False, path_type=Path)
OUTPUT = click.Path(dir_okay=False, path_type=Path)
DIRECTORY = click.Path(exists=True, file_okay=False, path_type=Path)
ROOT = click.Path(file_okay=False, path_type=Path)


def safe_errors(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (click.ClickException, click.exceptions.Exit):
            raise
        except ContractError as exc:
            raise click.ClickException(str(exc)) from None
        except (KeyboardInterrupt, asyncio.CancelledError):
            raise click.exceptions.Exit(130) from None
        except Exception:
            # Do not print paths, credentials, tracebacks or provider error bodies.
            raise click.ClickException(
                "Suite operation failed; check input files and private storage"
            ) from None

    return wrapped


def emit(value):
    click.echo(canonical(value).decode())


def credential_resolver(mappings):
    result = {}
    for entry in mappings:
        ref, separator, variable = entry.partition("=")
        if (
            not separator
            or not ref
            or ref in result
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", variable)
        ):
            raise ContractError("Credentials require unique REF=ENVIRONMENT_VARIABLE mappings")
        result[ref] = variable

    def resolve(ref):
        value = os.environ.get(result.get(ref, ""))
        if not value:
            raise ContractError("Credential reference is unavailable")
        return value

    return resolve


def signing_options(command):
    for option in (
        click.option(
            "--signing-key", type=INPUT, help="Private Ed25519 PEM in owner-only storage."
        ),
        click.option(
            "--require-signing", is_flag=True, help="Fail before dispatch without a configured key."
        ),
        click.option(
            "--raw-retention-seconds",
            type=click.IntRange(1, 31 * 86400),
            help="Opt in to private raw inputs with an explicit expiry.",
        ),
        click.option(
            "--storage-limit",
            type=click.IntRange(1024, 1024**3),
            default=64 * 1024**2,
            show_default=True,
        ),
        click.option(
            "--credential",
            multiple=True,
            help="REF=ENVIRONMENT_VARIABLE; values are never command arguments.",
        ),
        click.option(
            "--run-root", required=True, type=ROOT, help="New or existing owner-only run directory."
        ),
    ):
        command = option(command)
    return command


def verification_options(command):
    for option in (
        click.option(
            "--trusted-key", type=INPUT, help="Operator-trusted raw 32-byte Ed25519 public key."
        ),
        click.option(
            "--allow-advisory",
            is_flag=True,
            help="Explicitly allow integrity checking without operator attestation.",
        ),
        click.option(
            "--lock", "replay_lock", type=INPUT, help="Original lock for offline evidence replay."
        ),
        click.option(
            "--states",
            type=INPUT,
            help="Object mapping Agent checkpoint digests to original FixtureStates.",
        ),
        click.option(
            "--scenarios",
            type=INPUT,
            help="Object mapping adaptive attempt IDs to original ScenarioSpecs.",
        ),
    ):
        command = option(command)
    return command


def verification_kwargs(trusted_key, allow_advisory, replay_lock, scenarios, states=None):
    public = None
    if trusted_key:
        safe_path(trusted_key)
        # Public keys need no secrecy, but keep reads bounded and reject links/FIFOs.
        from .privacy import MAX_FILE
        import stat

        fd = os.open(
            trusted_key, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size != 32 or info.st_size > MAX_FILE:
                raise ContractError("Expected a raw 32-byte Ed25519 public key")
            public = stream.read(33)
        if len(public) != 32:
            raise ContractError("Expected a raw 32-byte Ed25519 public key")
    supplied = read_document(scenarios) if scenarios else {}
    if type(supplied) is not dict:
        raise ContractError("Expected an adaptive scenario map")
    from .fixture_state import FixtureState

    supplied_states = read_document(states) if states else {}
    if type(supplied_states) is not dict:
        raise ContractError("Expected an Agent checkpoint map")
    return dict(
        states={key: FixtureState.from_dict(value) for key, value in supplied_states.items()},
        trusted_public_key=public,
        allow_advisory=allow_advisory,
        lock=SuiteLock.from_dict(read_document(replay_lock)) if replay_lock else None,
        scenarios={key: ScenarioSpec.from_dict(value) for key, value in supplied.items()},
    )


def register(main, inputs, load_inputs):
    def current(source, plugin, probe, acceptances):
        def read():
            catalog, records, probes = load_inputs(source, plugin, probe, acceptances)
            return ExecutionInputs(catalog, tuple(records), probes)

        return read

    @main.command("accept")
    @click.argument("artifact", type=INPUT)
    @inputs
    @click.option(
        "--kind",
        type=click.Choice(["suite", "content", "plugin"]),
        default="suite",
        show_default=True,
    )
    @click.option("--expected-digest", required=True, help="Exact digest reviewed by the operator.")
    @click.option("--reviewer", required=True)
    @click.option("--reason", required=True)
    @click.option(
        "--decision", type=click.Choice(["accepted", "rejected", "revoked"]), default="accepted"
    )
    @click.option(
        "--grant-access", multiple=True, help="Repeat every requested plugin scope explicitly."
    )
    @click.option(
        "--output",
        required=True,
        type=OUTPUT,
        help="New decision-history file; never overwrites old history.",
    )
    @safe_errors
    def accept(
        artifact,
        source,
        plugin,
        probe,
        acceptances,
        kind,
        expected_digest,
        reviewer,
        reason,
        decision,
        grant_access,
        output,
    ):
        """Record a local decision on reviewed bytes and explicit scope."""
        history = record_decision(
            read_document(artifact),
            kind=kind,
            expected_digest=expected_digest,
            actor=reviewer,
            rationale=reason,
            decision=decision,
            grants=grant_access,
            current_inputs=current(source, plugin, probe, acceptances),
        )
        write_document(output, history)
        emit(
            {
                "decision": decision,
                "artifact_digest": expected_digest,
                "records": len(history["records"]),
            }
        )

    @main.command("keygen")
    @click.argument("directory", type=ROOT)
    @safe_errors
    def keygen(directory):
        """Create a private local signing-key directory. Never replaces existing keys."""
        mkdir_private(directory.absolute())
        signer = Signer(Ed25519PrivateKey.generate())
        write_private(
            directory / "signing-key.pem",
            signer.key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        )
        write_private(directory / "verification-key.pub", signer.public_key)
        emit({"key_id": signer.key_id, "directory": str(directory.absolute())})

    def perform_run(
        lock_path, *, parent_directory=None, trusted_key=None, allow_advisory=False, **options
    ):
        lock = SuiteLock.from_dict(read_document(lock_path))
        read = current(
            *(options.pop(name) for name in ("source", "plugin", "probe", "acceptances"))
        )
        key = options.pop("signing_key")
        signer = Signer.from_pem(read_private(key, 16384)) if key else None
        credentials = credential_resolver(options.pop("credential"))
        root = options.pop("run_root")
        kwargs = dict(
            current_inputs=read,
            signer=signer,
            credentials=credentials,
            on_created=lambda path: emit(
                {"event": "created", "run_id": path.name, "directory": str(path)}
            ),
            **options,
        )
        if parent_directory:
            trust = verification_kwargs(trusted_key, allow_advisory, None, None)
            operation = rerun_run(
                parent_directory,
                root,
                lock=lock,
                trusted_public_key=trust["trusted_public_key"],
                allow_advisory=allow_advisory,
                **kwargs,
            )
        else:
            operation = execute_run(lock, root, **kwargs)
        stored = asyncio.run(operation)
        emit(inspect_run(stored.directory))
        if not stored.run.passed:
            raise click.exceptions.Exit(2)

    @main.command("run")
    @click.argument("lock_path", type=INPUT)
    @inputs
    @signing_options
    @safe_errors
    def run(lock_path, **options):
        """Execute an accepted fixture lock and save its complete signed roster."""
        perform_run(lock_path, **options)

    @main.command("rerun")
    @click.argument("directory", type=DIRECTORY)
    @click.argument("lock_path", type=INPUT)
    @inputs
    @signing_options
    @click.option("--trusted-key", type=INPUT)
    @click.option("--allow-advisory", is_flag=True)
    @safe_errors
    def rerun(directory, lock_path, **options):
        """Check a completed parent and start a fresh run with current acceptance."""
        perform_run(lock_path, parent_directory=directory, **options)

    @main.command("inspect")
    @click.argument("directory", type=DIRECTORY)
    @safe_errors
    def inspect(directory):
        """Show sanitized outcomes. Inspection does not establish operator trust."""
        emit(inspect_run(directory))

    @main.command("verify")
    @click.argument("directory", type=DIRECTORY)
    @verification_options
    @safe_errors
    def verify(directory, **options):
        """Verify signed bytes and replay evidence; missing inputs cannot pass."""
        result = verify_run(directory, **verification_kwargs(**options))
        emit(
            {
                name: getattr(result, name)
                for name in (
                    "run_id",
                    "envelope_digest",
                    "trusted",
                    "replayed",
                    "reported_security_passed",
                    "security_passed",
                    "attested_pass",
                )
            }
        )
        if not result.replayed or not result.security_passed:
            raise click.exceptions.Exit(2)

    @main.command("cancel")
    @click.argument("directory", type=DIRECTORY)
    @safe_errors
    def cancel(directory):
        """Request a run-scoped stop; inspect the run to confirm terminal cleanup."""
        emit({"requested": request_cancel(directory)})

    @main.command("purge-raw")
    @click.argument("directory", type=DIRECTORY)
    @safe_errors
    def purge(directory):
        """Delete expired indexed raw inputs; keep signed normalized evidence."""
        emit({"removed": purge_expired_raw(directory)})

    @main.command("export-legacy")
    @click.argument("directory", type=DIRECTORY)
    @verification_options
    @click.option("--output", type=OUTPUT, required=True)
    @safe_errors
    def export(directory, output, **options):
        """Write an explicitly unsigned sanitized DrillReport projection."""
        write_document(output, legacy_projection(directory, **verification_kwargs(**options)))
        emit({"exported": True, "signed": False})
