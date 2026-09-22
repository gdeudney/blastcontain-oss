"""Read reviewed metadata without importing, installing or starting plugin code."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Callable, Iterable

from ..contracts import AcceptanceRecord, ContractError, PluginManifest

MAX_METADATA_BYTES = 65536
CONVERSATION_ACCESS = frozenset(
    f"broker.{channel}.{scope}"
    for channel in ("target", "attacker", "evaluator")
    for scope in ("conversation", "branch")
)
SUPPORTED_ACCESS = (
    frozenset({"broker.target", "broker.attacker", "broker.evaluator"}) | CONVERSATION_ACCESS
)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value):
    raise ContractError("Nonfinite JSON number")


def parse_json(data: bytes):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ContractError("Invalid JSON data") from exc


def read_metadata(path: Path):
    # Nonblocking prevents FIFO reads from hanging discovery. Refuse symlinks
    # where supported; all paths still come from operator-selected directories.
    if path.is_symlink():
        raise ContractError("Metadata symlinks are not supported")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_METADATA_BYTES:
            raise ContractError("Metadata must be a regular file of at most 64 KiB")
        data = stream.read(MAX_METADATA_BYTES + 1)
    if len(data) > MAX_METADATA_BYTES:
        raise ContractError("Metadata exceeds 64 KiB")
    return parse_json(data)


def review_digest(manifest: PluginManifest) -> str:
    """Bind acceptance to all metadata AND the immutable local image ID."""
    data = json.dumps(manifest.to_dict(), sort_keys=True, separators=(",", ":"), allow_nan=False)
    return "sha256:" + hashlib.sha256(data.encode()).hexdigest()


def read_acceptances(path: Path | None) -> list[AcceptanceRecord]:
    if path is None:
        return []
    data = read_metadata(path)
    if (
        type(data) is not dict
        or set(data) != {"schema_version", "records"}
        or type(data["schema_version"]) is not int
        or data["schema_version"] != 1
        or type(data["records"]) is not list
    ):
        raise ContractError("Expected acceptance document schema 1 with records array")
    return [AcceptanceRecord.from_dict(record) for record in data["records"]]


def check_acceptance(manifest: PluginManifest, records: Iterable[AcceptanceRecord]) -> None:
    # File order is authoritative. A subsequent rejection/revocation invalidates
    # prior acceptance even when it references an older image. No timestamp guesses.
    record = next(
        (r for r in reversed(list(records)) if r.kind == "plugin" and r.subject_id == manifest.id),
        None,
    )
    if record is None or record.decision != "accepted":
        raise ContractError("Plugin has no current acceptance")
    if record.artifact_digest != review_digest(manifest):
        raise ContractError("Acceptance is stale: image or manifest changed")
    if set(record.granted_access) != set(manifest.access_requests):
        raise ContractError("Granted scope must match the reviewed access requests")


def check_profile(manifest: PluginManifest) -> None:
    unsupported = set(manifest.access_requests) - SUPPORTED_ACCESS
    if unsupported:
        raise ContractError(f"Unsupported access requests: {sorted(unsupported)}")
    if set(manifest.access_requests) & CONVERSATION_ACCESS and manifest.adapter_api != 2:
        raise ContractError("Conversation access requires adapter API 2")
    for channel in ("target", "attacker", "evaluator"):
        if (
            f"broker.{channel}.branch" in manifest.access_requests
            and f"broker.{channel}.conversation" not in manifest.access_requests
        ):
            raise ContractError("Branch access requires conversation access")
    # Empty schemas and the strict empty-object schema are supported initially.
    # Never advertise a schema as enforced while silently ignoring it.
    if manifest.config_schema not in ({}, {"type": "object", "additionalProperties": False}):
        raise ContractError("This worker profile supports empty configuration only")


@dataclass(frozen=True)
class PluginStatus:
    path: str
    id: str
    installed: bool = True
    compatible: bool = False
    accepted: bool = False
    available: bool = False
    review_digest: str | None = None
    diagnostics: tuple[str, ...] = ()
    manifest: PluginManifest | None = None


def discover(
    directories: Iterable[Path], records=(), available: Callable[[str], bool] | None = None
):
    """Only *.drill-plugin.json files in explicit directories; no entry-point imports.

    Availability is an optional trusted runtime probe, never plugin-supplied code.
    A metadata file means registered/installed, not that an image is present.
    """
    found = []
    records = tuple(records)
    paths = sorted({p for directory in directories for p in directory.glob("*.drill-plugin.json")})
    for path in paths:
        raw_id = path.name
        try:
            data = read_metadata(path)
            if isinstance(data, dict) and isinstance(data.get("id"), str):
                raw_id = data["id"]
            manifest = PluginManifest.from_dict(data)
        except (ContractError, OSError) as exc:
            found.append(PluginStatus(str(path), raw_id, diagnostics=(str(exc),)))
            continue
        diagnostics = []
        compatible = accepted = False
        try:
            check_profile(manifest)
            compatible = True
        except ContractError as exc:
            diagnostics.append(str(exc))
        try:
            check_acceptance(manifest, records)
            accepted = True
        except ContractError as exc:
            diagnostics.append(str(exc))
        image_available = bool(available and available(manifest.artifact_digest))
        if not image_available:
            diagnostics.append("Local image/runtime unavailable or not probed")
        found.append(
            PluginStatus(
                str(path),
                manifest.id,
                compatible=compatible,
                accepted=accepted,
                available=image_available,
                review_digest=review_digest(manifest),
                diagnostics=tuple(diagnostics),
                manifest=manifest,
            )
        )
    ids = [item.id for item in found]
    return [
        replace(item, compatible=False, diagnostics=(*item.diagnostics, "Duplicate plugin ID"))
        if ids.count(item.id) > 1
        else item
        for item in found
    ]


def select(directories, plugin_id, records):
    matches = [p for p in discover(directories, records) if p.id == plugin_id]
    if len(matches) != 1 or not matches[0].compatible or not matches[0].accepted:
        raise ContractError("Plugin must be uniquely registered, compatible and accepted")
    return matches[0].manifest
