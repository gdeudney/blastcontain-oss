"""Server test fixtures — in-memory DB, isolated signing env, TestClient."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parents[2] / "server"
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))


@pytest.fixture
def signing_env(monkeypatch):
    """Strip BLASTCONTAIN_* and sign with a real (non-default) HMAC test key."""
    for key in list(os.environ):
        if key.startswith("BLASTCONTAIN_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("BLASTCONTAIN_SIGNING_KEY", "platform-test-key")
    # Skip Presidio's slow NLP init; the regex scrub baseline is what tests assert.
    monkeypatch.setenv("BLASTCONTAIN_SCRUB_PRESIDIO", "0")
    return monkeypatch


@pytest.fixture
def app(signing_env):
    from blastcontain.app import create_app

    return create_app(db_url="sqlite:///:memory:")


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        yield c


CHARTER_BODY = {
    "agent_id": "invoice-bot",
    "environment": "prod",
    "version": "1.0.0",
    "trust_tier": 1,
    "permitted_tools": ["query_invoice", "send_receipt"],
    "autonomy_mode": "interactive",
    "base_strictness": "balanced",
    "objectives": [{"id": "no-prod-data-mutation"}, {"id": "no-pii-egress"}],
    "environment_constraints": {
        "read_only_rootfs": True,
        "egress_blocked": False,
        "max_trust_tier": 1,
        "verify_required": True,
    },
    "owner": "alice@example.com",
}


@pytest.fixture
def charter_body():
    import copy

    return copy.deepcopy(CHARTER_BODY)
