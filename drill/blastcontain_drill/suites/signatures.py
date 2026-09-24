"""Explicit suite signing. No environment lookup or fallback to a shared HMAC key."""

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
)

from ..contracts import ContractError
from .artifacts import canonical, digest


@dataclass(frozen=True)
class Signer:
    key: Ed25519PrivateKey

    @classmethod
    def from_pem(cls, pem: bytes):
        try:
            key = load_pem_private_key(pem, password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError
            return cls(key)
        except Exception:
            raise ContractError("An explicit, readable Ed25519 private key is required") from None

    @property
    def public_key(self):
        return self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def key_id(self):
        return digest(base64.b64encode(self.public_key).decode())

    def sign(self, payload):
        return {
            "payload": payload,
            "signature": {
                "algorithm": "ed25519",
                "public_key": base64.b64encode(self.public_key).decode(),
                "value": base64.b64encode(self.key.sign(canonical(payload))).decode(),
            },
        }


def verify_signature(envelope, *, trusted_public_key=None, allow_advisory=False):
    try:
        if set(envelope) != {"payload", "signature"}:
            raise ValueError
        signature = envelope["signature"]
        if (
            set(signature) != {"algorithm", "public_key", "value"}
            or signature["algorithm"] != "ed25519"
        ):
            raise ValueError
        embedded = base64.b64decode(signature["public_key"], validate=True)
        trusted = trusted_public_key is not None and embedded == trusted_public_key
        if trusted_public_key is not None and not trusted:
            raise ValueError
        if not trusted and not allow_advisory:
            raise ContractError("Verification requires an operator-trusted public key")
        Ed25519PublicKey.from_public_bytes(embedded).verify(
            base64.b64decode(signature["value"], validate=True), canonical(envelope["payload"])
        )
        if envelope["payload"]["key_id"] != digest(signature["public_key"]):
            raise ValueError
        if envelope["payload"]["signing"] == "advisory" and not allow_advisory:
            raise ContractError("Advisory signing is not operator attestation")
        return trusted and envelope["payload"]["signing"] == "configured"
    except ContractError:
        raise
    except Exception:
        raise ContractError("Suite signature verification failed") from None
