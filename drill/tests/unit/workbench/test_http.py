"""Real loopback requests exercise session, origin, body and route boundaries."""

import http.client
import json
import threading

import pytest

from blastcontain_drill.workbench.research import Research
from blastcontain_drill.workbench.server import WorkbenchServer
from blastcontain_drill.workbench.service import Runs, Workspace


@pytest.fixture
def server(tmp_path):
    workspace = Workspace(tmp_path / "workspace")
    runs = Runs(workspace)
    server = WorkbenchServer(workspace, runs, Research())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(5)
    server.server_close()
    runs.close()
    workspace.close()


def request(server, path="/api/state", *, method="GET", data=None, token=None, headers=None):
    connection = http.client.HTTPConnection(*server.server_address, timeout=5)
    values = {"Origin": server.origin}
    if token:
        values["Authorization"] = "Bearer " + token
    body = None if data is None else json.dumps(data)
    if body is not None:
        values["Content-Type"] = "application/json"
    values.update(headers or {})
    try:
        connection.request(method, path, body, values)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def session(server):
    status, headers, body = request(
        server, "/api/session", method="POST", data={"token": server.bootstrap}
    )
    assert status == 200 and "Set-Cookie" not in headers
    return json.loads(body)["token"]


def test_bootstrap_is_single_use_expiring_and_assets_are_hardened(server):
    launch = server.bootstrap
    assert request(server)[0] == 401
    token = session(server)
    assert request(server, token=token)[0] == 200
    assert request(server, "/api/session", method="POST", data={"token": launch})[0] == 400
    for path in ("/", "/app.js", "/app.css"):
        status, headers, body = request(server, path)
        assert status == 200 and len(body) > 100
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
        assert headers["Cache-Control"] == "no-store"
        assert headers["Referrer-Policy"] == "no-referrer"
        assert "Set-Cookie" not in headers
    server.session = None
    server.bootstrap = "expired"
    server.bootstrap_expires = 0
    assert request(server, "/api/session", method="POST", data={"token": "expired"})[0] == 400


@pytest.mark.parametrize(
    "headers",
    [{"Host": "attacker.example"}, {"Origin": "https://attacker.example"}, {"Origin": "null"}],
)
def test_forged_origin_or_host_denied_even_with_token(server, headers):
    token = session(server)
    assert request(server, token=token, headers=headers)[0] == 403
    assert (
        request(
            server,
            "/api/lock",
            method="POST",
            token=token,
            data={"expected_revision": "x"},
            headers=headers,
        )[0]
        == 403
    )


def test_unknown_execution_paths_and_stale_mutations(server):
    token = session(server)
    state = json.loads(request(server, token=token)[2])
    payload = {"document": state["suite"], "expected_revision": state["revision"]}
    payload["document"]["id"] = "new-suite"
    assert request(server, "/api/suite", method="POST", token=token, data=payload)[0] == 200
    assert request(server, "/api/suite", method="POST", token=token, data=payload)[0] == 409
    for route in (
        "/api/shell",
        "/api/install",
        "/api/file",
        "/api/state?file=/etc/passwd",
        "/../server.py",
    ):
        assert request(server, route, token=token)[0] == 404
        assert request(server, route, method="POST", token=token, data={})[0] == 404
    assert (
        request(
            server, "/api/suite", method="POST", token=token, data={**payload, "command": "no"}
        )[0]
        == 400
    )
    assert request(server, method="OPTIONS", token=token)[0] == 403


@pytest.mark.parametrize(
    "extra,body,expected",
    [
        ([("Host", "attacker.example")], b"{}", 403),
        ([("Origin", "https://attacker.example")], b"{}", 403),
        ([("Content-Length", "2")], b"{}", 400),
        ([("Transfer-Encoding", "chunked")], b"{}", 400),
        ([], b'{"token":"one","token":"two"}', 400),
        ([], b'{"token":NaN}', 400),
    ],
)
def test_duplicate_headers_and_ambiguous_json_rejected(server, extra, body, expected):
    connection = http.client.HTTPConnection(*server.server_address, timeout=5)
    connection.putrequest("POST", "/api/session")
    connection.putheader("Origin", server.origin)
    connection.putheader("Content-Type", "application/json")
    connection.putheader("Content-Length", str(len(body)))
    for key, value in extra:
        connection.putheader(key, value)
    connection.endheaders(body)
    response = connection.getresponse()
    assert response.status == expected
    response.read()
    connection.close()


def test_secret_provider_error_is_generic(server, monkeypatch):
    token = session(server)

    def fail(*args, **kwargs):
        raise RuntimeError("SECRET_API_KEY_SENTINEL")

    monkeypatch.setattr(server.runs, "verify", fail)
    status, _, body = request(
        server, "/api/verify", method="POST", token=token, data={"run_id": "1" * 32}
    )
    assert status == 500 and b"SECRET_API_KEY_SENTINEL" not in body
