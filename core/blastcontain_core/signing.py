"""
blastcontain_core.signing — Audit Packet signing and verification.

Signing algorithms (in priority order):

  1. Ed25519 — preferred. Asymmetric, signatures verifiable with just
     the public key (embedded in the packet). Used when a key source
     is set via environment:
       BLASTCONTAIN_SIGNING_KEY_PATH   — path to PEM-encoded private key
       BLASTCONTAIN_SIGNING_KEY_PEM    — PEM contents directly

  2. SHA-256 HMAC — fallback. Symmetric, whoever can verify can also
     sign. Acceptable for local development and CI artifact integrity.
     Used when:
       BLASTCONTAIN_SIGNING_KEY  is set with arbitrary string
       — or no key source at all (uses 'local-verify-default' with warning)

Canonical encoding:
  json.dumps(payload, sort_keys=True, separators=(",", ":"))

This deterministic byte string is what any verifier reproduces. Different
whitespace, key order, or escape conventions would yield different
signatures. The canonical scheme is recorded in `signature.canonical`.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
from typing import Optional


def canonical_bytes(payload: dict) -> bytes:
    """Return the canonical byte representation of a payload for signing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _load_ed25519_key():
    """
    Load an Ed25519 private key from environment configuration.

    Returns (private_key, public_key_b64) on success, or None if no key
    source is configured or the `cryptography` package is not installed.
    """
    key_path = os.environ.get("BLASTCONTAIN_SIGNING_KEY_PATH")
    key_pem = os.environ.get("BLASTCONTAIN_SIGNING_KEY_PEM")

    if not key_path and not key_pem:
        return None

    try:
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key,
            Encoding,
            PublicFormat,
        )
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        print(
            "Warning: BLASTCONTAIN_SIGNING_KEY_PATH/_PEM is set but the "
            "`cryptography` package is not installed. Falling back to HMAC. "
            "Install with: pip install cryptography",
            file=sys.stderr,
        )
        return None

    pem_bytes: bytes
    if key_path:
        try:
            with open(key_path, "rb") as f:
                pem_bytes = f.read()
        except OSError as exc:
            print(
                f"Warning: cannot read signing key at {key_path}: {exc}. "
                "Falling back to HMAC.",
                file=sys.stderr,
            )
            return None
    else:
        pem_bytes = key_pem.encode() if isinstance(key_pem, str) else key_pem

    try:
        private_key = load_pem_private_key(pem_bytes, password=None)
    except Exception as exc:
        print(
            f"Warning: cannot parse Ed25519 key: {exc}. Falling back to HMAC.",
            file=sys.stderr,
        )
        return None

    if not isinstance(private_key, Ed25519PrivateKey):
        print(
            "Warning: signing key is not Ed25519. Falling back to HMAC. "
            "Generate one with: openssl genpkey -algorithm Ed25519",
            file=sys.stderr,
        )
        return None

    public_key_raw = private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    public_key_b64 = base64.b64encode(public_key_raw).decode("ascii")
    return private_key, public_key_b64


def _sign_ed25519(payload_bytes: bytes, private_key) -> str:
    sig_bytes = private_key.sign(payload_bytes)
    return base64.b64encode(sig_bytes).decode("ascii")


def sign_packet(payload: dict, signed_at: str, key_id: Optional[str] = None) -> dict:
    """
    Produce a `signature` block for the given payload.

    The signature block conforms to schema_version 1.1:
      {
        "algorithm": "ed25519" | "sha256-hmac",
        "key_id": "<identifier>",
        "value": "<signature>",
        "value_encoding": "base64" | "hex",
        "canonical": "json-sort-keys-tight",
        "signed_at": "<iso8601>",
        # ed25519 only:
        "public_key": "<base64 of 32-byte raw key>",
        "public_key_encoding": "base64-raw",
        # default-HMAC-key only (additive field):
        "advisory": true,   # integrity-only — key is public knowledge, not attestation
      }
    """
    payload_bytes = canonical_bytes(payload)
    sign_key_id = key_id or os.environ.get("BLASTCONTAIN_SIGNING_KEY_ID", "local")

    ed25519 = _load_ed25519_key()
    if ed25519 is not None:
        private_key, public_key_b64 = ed25519
        return {
            "algorithm":           "ed25519",
            "key_id":              sign_key_id,
            "public_key":          public_key_b64,
            "public_key_encoding": "base64-raw",
            "value":               _sign_ed25519(payload_bytes, private_key),
            "value_encoding":      "base64",
            "canonical":           "json-sort-keys-tight",
            "signed_at":           signed_at,
        }

    # HMAC fallback
    sign_key_raw = os.environ.get("BLASTCONTAIN_SIGNING_KEY", "local-verify-default")
    advisory = sign_key_raw == "local-verify-default"
    if advisory:
        print(
            "Warning: signing audit packet with default HMAC key "
            "'local-verify-default'. Signatures are advisory only and cannot "
            "be independently verified. Set BLASTCONTAIN_SIGNING_KEY_PATH to "
            "a PEM-encoded Ed25519 key for production attestation.",
            file=sys.stderr,
        )
    sig = {
        "algorithm":      "sha256-hmac",
        "key_id":         sign_key_id,
        "value":          hmac.new(sign_key_raw.encode(), payload_bytes, hashlib.sha256).hexdigest(),
        "value_encoding": "hex",
        "canonical":      "json-sort-keys-tight",
        "signed_at":      signed_at,
    }
    if advisory:
        # Machine-readable honesty: the default key is shared knowledge, so this
        # signature proves integrity, not provenance. Downstream tooling (the
        # Ledger, CI gates) can refuse advisory packets mechanically instead of
        # parsing a stderr warning. Absent on Ed25519 and real-key HMAC packets.
        sig["advisory"] = True
    return sig


def verify_packet(packet: dict, public_key_b64: Optional[str] = None) -> bool:
    """
    Verify an audit packet's signature.

    For Ed25519 packets, `public_key_b64` defaults to the public key embedded
    in the packet. For HMAC packets, BLASTCONTAIN_SIGNING_KEY must be set in
    the environment.

    Returns True if the signature is valid, False otherwise.
    """
    sig = packet.get("signature", {})
    payload = packet.get("packet", {})
    algorithm = sig.get("algorithm", "")
    payload_bytes = canonical_bytes(payload)

    if algorithm == "ed25519":
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            return False
        pk_b64 = public_key_b64 or sig.get("public_key", "")
        if not pk_b64:
            return False
        try:
            pk_bytes = base64.b64decode(pk_b64)
            sig_bytes = base64.b64decode(sig.get("value", ""))
            pk = Ed25519PublicKey.from_public_bytes(pk_bytes)
            pk.verify(sig_bytes, payload_bytes)
            return True
        except Exception:
            return False

    if algorithm == "sha256-hmac":
        key_raw = os.environ.get("BLASTCONTAIN_SIGNING_KEY", "local-verify-default")
        expected = hmac.new(key_raw.encode(), payload_bytes, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig.get("value", ""))

    return False
