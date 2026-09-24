"""Append-only, case-scoped proof artifacts with generated names and bounded reads."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

from ..contracts import ContractError
from ..contracts.wire import _json_data
from ..plugins.catalog import parse_json
from ..suites.artifacts import canonical, safe_path, write_document
from .records import ArtifactRef


class ArtifactStore:
    """Host-owned directory. Store normalized proof data, never raw prompts by default."""

    def __init__(self, directory: Path, *, max_artifact_bytes=1_048_576):
        if type(max_artifact_bytes) is not int or not 1 <= max_artifact_bytes <= 16_000_000:
            raise ContractError("Invalid artifact byte limit")
        safe_path(directory)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory = directory
        self.max_artifact_bytes = max_artifact_bytes

    def put(self, case_id, scenario_digest, emitter, data) -> ArtifactRef:
        try:
            _json_data(data, "proof")
        except RecursionError as exc:
            raise ContractError("Proof data too deeply nested") from exc
        document = {
            "schema_version": 1,
            "case_id": case_id,
            "scenario_digest": scenario_digest,
            "emitter": emitter,
            "data": data,
        }
        encoded = canonical(document) + b"\n"
        if len(encoded) > self.max_artifact_bytes:
            raise ContractError("Proof artifact exceeds byte limit")
        ref = ArtifactRef(
            "sha256:" + hashlib.sha256(encoded).hexdigest(),
            case_id,
            scenario_digest,
            emitter,
            len(encoded),
        )
        path = self.directory / (ref.digest[7:] + ".json")
        try:
            write_document(path, document)
        except FileExistsError:
            self.read(ref)  # Existing bytes must match; never overwrite a conflicting file.
        return ref

    def read(self, ref: ArtifactRef):
        ref.to_dict()
        if ref.size_bytes > self.max_artifact_bytes:
            raise ContractError("Proof artifact exceeds byte limit")
        path = self.directory / (ref.digest[7:] + ".json")
        # Verify the actual retained bytes from one bounded descriptor read.
        safe_path(path)
        fd = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size != ref.size_bytes:
                raise ContractError("Proof artifact size mismatch")
            raw = stream.read(self.max_artifact_bytes + 1)
        if len(raw) != ref.size_bytes or "sha256:" + hashlib.sha256(raw).hexdigest() != ref.digest:
            raise ContractError("Proof artifact digest mismatch")
        document = parse_json(raw)
        try:
            _json_data(document, "proof artifact")
        except RecursionError as exc:
            raise ContractError("Proof data too deeply nested") from exc
        expected = {"schema_version", "case_id", "scenario_digest", "emitter", "data"}
        if (
            type(document) is not dict
            or set(document) != expected
            or type(document["schema_version"]) is not int
            or document["schema_version"] != 1
            or (document["case_id"], document["scenario_digest"], document["emitter"])
            != (ref.case_id, ref.scenario_digest, ref.emitter)
        ):
            raise ContractError("Proof artifact scope mismatch")
        return json.loads(canonical(document["data"]))
