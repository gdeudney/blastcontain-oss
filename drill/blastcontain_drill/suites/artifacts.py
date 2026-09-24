"""Bounded JSON files and canonical content hashes for offline planning."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

from ..contracts import ContractError
from ..plugins.catalog import parse_json

MAX_ARTIFACT_BYTES = 16 * 1024 * 1024


def canonical(data) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def digest(data) -> str:
    return "sha256:" + hashlib.sha256(canonical(data)).hexdigest()


def safe_path(path: Path) -> None:
    if ".." in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
        raise ContractError("Artifact paths cannot traverse parents or symlinks")


def read_document(path: Path):
    safe_path(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARTIFACT_BYTES:
            raise ContractError("Expected a regular artifact of at most 16 MiB")
        data = stream.read(MAX_ARTIFACT_BYTES + 1)
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ContractError("Artifact exceeds 16 MiB")
    return parse_json(data)


def write_document(path: Path, data) -> None:
    """Exclusive creation; never overwrite a lock or follow an existing link."""
    encoded = canonical(data) + b"\n"
    if len(encoded) > MAX_ARTIFACT_BYTES:
        raise ContractError("Artifact exceeds 16 MiB")
    safe_path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded)
