"""Read-only runtime readiness failures remain bounded, explicit and fail-closed."""

import json
import subprocess
from types import SimpleNamespace

import pytest

from blastcontain_drill.plugins import runtime

IMAGE = "sha256:" + "a" * 64
HOST = {
    "security": {"rootless": True, "seccompEnabled": True},
    "cgroupVersion": "v2",
    "cgroupControllers": ["memory", "pids"],
}


def install(monkeypatch, *, host=HOST, failure=None, image_exit=0):
    calls = []
    monkeypatch.setattr(runtime.sys, "platform", "linux")
    monkeypatch.setattr(runtime.shutil, "which", lambda name: "/usr/bin/podman")

    def run(command, **kwargs):
        calls.append(command)
        assert kwargs["timeout"] == 3
        stage = "host_info" if "info" in command else "image_exists"
        if failure == stage:
            raise subprocess.TimeoutExpired(command, 3, output="SENSITIVE_OUTPUT")
        return SimpleNamespace(stdout=json.dumps(host).encode(), returncode=image_exit)

    monkeypatch.setattr(runtime.subprocess, "run", run)
    return calls


@pytest.mark.parametrize("stage", ["host_info", "image_exists"])
def test_timeout_has_stage_without_capturing_provider_or_host_output(monkeypatch, stage):
    calls = install(monkeypatch, failure=stage)
    result = runtime.probe_local_image(IMAGE)
    assert not result.available and result.diagnostic == stage + "_timeout"
    assert "SENSITIVE" not in repr(result)
    assert len(calls) == (1 if stage == "host_info" else 2)


@pytest.mark.parametrize(
    "host,diagnostic",
    [
        (None, "host_info_invalid"),
        ({**HOST, "security": []}, "host_info_invalid"),
        ({**HOST, "cgroupControllers": "memory,pids"}, "host_info_invalid"),
        ({**HOST, "security": {"rootless": False}}, "rootless_unavailable"),
        ({**HOST, "security": {"rootless": True}}, "seccomp_unavailable"),
        ({**HOST, "cgroupVersion": "v1"}, "cgroups_v2_unavailable"),
        ({**HOST, "cgroupControllers": ["pids"]}, "memory_controller_unavailable"),
        ({**HOST, "cgroupControllers": ["memory"]}, "pids_controller_unavailable"),
    ],
)
def test_incompatible_hosts_are_not_reported_as_image_or_timeout_failures(
    monkeypatch, host, diagnostic
):
    calls = install(monkeypatch, host=host)
    result = runtime.probe_local_image(IMAGE)
    assert not result.available and result.diagnostic == diagnostic
    assert len(calls) == 1


@pytest.mark.parametrize("image_exit", [0, 1, 125])
def test_boolean_compatibility_and_no_remote_or_mutating_commands(monkeypatch, image_exit):
    calls = install(monkeypatch, image_exit=image_exit)
    assert runtime.local_image_available(IMAGE) is (image_exit == 0)
    assert calls == [
        ["/usr/bin/podman", "--remote=false", "info", "--format={{json .Host}}"],
        ["/usr/bin/podman", "--remote=false", "image", "exists", IMAGE],
    ]
