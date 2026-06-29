"""Unit tests for blastcontain_core.signing."""
from __future__ import annotations

import os

import pytest

from blastcontain_core.signing import (
    canonical_bytes,
    sign_packet,
    verify_packet,
)


@pytest.fixture
def isolated_env(monkeypatch):
    """Strip all BLASTCONTAIN_* env vars so tests don't pick up real keys."""
    for key in list(os.environ):
        if key.startswith("BLASTCONTAIN_"):
            monkeypatch.delenv(key, raising=False)
    return monkeypatch


def test_canonical_bytes_deterministic():
    a = {"b": 1, "a": 2}
    b = {"a": 2, "b": 1}
    assert canonical_bytes(a) == canonical_bytes(b)


def test_canonical_bytes_tight_separators():
    payload = {"a": 1, "b": [1, 2, 3]}
    # No whitespace anywhere in canonical form
    assert b" " not in canonical_bytes(payload)


def test_hmac_fallback_when_no_ed25519_key(isolated_env):
    isolated_env.setenv("BLASTCONTAIN_SIGNING_KEY", "test-key")
    sig = sign_packet({"hello": "world"}, signed_at="2026-01-01T00:00:00Z")
    assert sig["algorithm"] == "sha256-hmac"
    assert sig["value_encoding"] == "hex"
    assert len(sig["value"]) == 64  # SHA-256 hex


def test_hmac_round_trip(isolated_env):
    isolated_env.setenv("BLASTCONTAIN_SIGNING_KEY", "test-key")
    payload = {"agent_id": "a", "environment": "staging"}
    sig = sign_packet(payload, signed_at="2026-01-01T00:00:00Z")
    packet = {"packet": payload, "signature": sig}
    assert verify_packet(packet) is True


def test_hmac_tampered_payload_fails(isolated_env):
    isolated_env.setenv("BLASTCONTAIN_SIGNING_KEY", "test-key")
    payload = {"agent_id": "a"}
    sig = sign_packet(payload, signed_at="2026-01-01T00:00:00Z")
    packet = {"packet": {"agent_id": "a-TAMPERED"}, "signature": sig}
    assert verify_packet(packet) is False


def test_default_key_marks_packet_advisory(isolated_env):
    """The shared default HMAC key proves integrity, not provenance — the
    signature must say so machine-readably so downstream gates can refuse it."""
    sig = sign_packet({"hello": "world"}, signed_at="2026-01-01T00:00:00Z")
    assert sig["algorithm"] == "sha256-hmac"
    assert sig["advisory"] is True
    # Advisory packets still round-trip — integrity checking still works.
    assert verify_packet({"packet": {"hello": "world"}, "signature": sig}) is True


def test_real_hmac_key_is_not_advisory(isolated_env):
    isolated_env.setenv("BLASTCONTAIN_SIGNING_KEY", "a-real-secret")
    sig = sign_packet({"hello": "world"}, signed_at="2026-01-01T00:00:00Z")
    assert "advisory" not in sig


def test_ed25519_round_trip(isolated_env, tmp_path):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, NoEncryption,
    )

    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    key_path = tmp_path / "signing.key"
    key_path.write_bytes(pem)

    isolated_env.setenv("BLASTCONTAIN_SIGNING_KEY_PATH", str(key_path))
    payload = {"agent_id": "a", "environment": "staging"}
    sig = sign_packet(payload, signed_at="2026-01-01T00:00:00Z")
    assert sig["algorithm"] == "ed25519"
    assert sig["value_encoding"] == "base64"
    assert sig["public_key_encoding"] == "base64-raw"

    packet = {"packet": payload, "signature": sig}
    assert verify_packet(packet) is True


def test_ed25519_tampered_payload_fails(isolated_env, tmp_path):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, NoEncryption,
    )

    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        encoding=Encoding.PEM, format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    key_path = tmp_path / "signing.key"
    key_path.write_bytes(pem)
    isolated_env.setenv("BLASTCONTAIN_SIGNING_KEY_PATH", str(key_path))

    payload = {"agent_id": "a"}
    sig = sign_packet(payload, signed_at="2026-01-01T00:00:00Z")
    packet = {"packet": {"agent_id": "a-TAMPERED"}, "signature": sig}
    assert verify_packet(packet) is False
