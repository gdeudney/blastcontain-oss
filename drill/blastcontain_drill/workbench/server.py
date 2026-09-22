"""Loopback-only HTTP UI with origin checks and explicit per-tab bearer sessions."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
import json
import re
import secrets
import threading
import time
from urllib.parse import urlsplit

from ..contracts import ContractError
from ..plugins.catalog import parse_json
from .service import MAX_DOCUMENT

CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}


class WorkbenchServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 16

    def __init__(self, workspace, runs, research, *, port=0):
        self.workspace, self.runs, self.research = workspace, runs, research
        self.bootstrap = secrets.token_urlsafe(32)
        self.bootstrap_expires = time.monotonic() + 300
        self.session = None
        self.authentication_guard = threading.Lock()
        self.capacity = threading.BoundedSemaphore(16)
        super().__init__(("127.0.0.1", port), Handler)
        self.authority = "127.0.0.1:" + str(self.server_address[1])
        self.origin = "http://" + self.authority

    @property
    def launch_url(self):
        return self.origin + "/#session=" + self.bootstrap

    def exchange(self, token):
        with self.authentication_guard:
            if (
                not self.bootstrap
                or time.monotonic() > self.bootstrap_expires
                or type(token) is not str
                or not secrets.compare_digest(token.encode(), self.bootstrap.encode())
            ):
                raise ContractError("Launch session expired or already used; restart the local UI")
            self.bootstrap = ""
            self.session = secrets.token_urlsafe(32)
            return self.session

    def authorized(self, header):
        return bool(
            self.session
            and secrets.compare_digest((header or "").encode(), ("Bearer " + self.session).encode())
        )

    def process_request(self, request, client_address):
        if not self.capacity.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.capacity.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.capacity.release()


class Handler(BaseHTTPRequestHandler):
    server: WorkbenchServer
    server_version = "DrillWorkbench"
    timeout = 10

    def log_message(self, *args):
        # Authentication, prompts and request bodies never enter HTTP logs.
        pass

    def respond(self, status, body, content_type="application/json; charset=utf-8"):
        if type(body) is not bytes:
            body = json.dumps(body, ensure_ascii=True, allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def boundary(self, *, mutation=False):
        if self.headers.get_all("Host") != [self.server.authority]:
            self.respond(403, {"error": "Unexpected host"})
            return False
        origins = self.headers.get_all("Origin") or []
        if origins not in ([], [self.server.origin]) or (
            mutation and origins != [self.server.origin]
        ):
            self.respond(403, {"error": "Requests must originate in this local workbench"})
            return False
        return True

    def authenticated(self):
        headers = self.headers.get_all("Authorization") or []
        if len(headers) != 1 or not self.server.authorized(headers[0]):
            self.respond(401, {"error": "Open the authenticated launch link printed by the CLI"})
            return False
        return True

    def body(self):
        if self.headers.get("Transfer-Encoding") is not None:
            raise ContractError("Transfer encoding is not supported")
        if self.headers.get_all("Content-Type") != ["application/json"]:
            raise ContractError("Expected application/json")
        lengths = self.headers.get_all("Content-Length") or []
        if (
            len(lengths) != 1
            or not re.fullmatch(r"[0-9]{1,8}", lengths[0])
            or not 1 <= int(lengths[0]) <= MAX_DOCUMENT
        ):
            raise ContractError("Request body must be between 1 byte and 2 MiB")
        size = int(lengths[0])
        data = self.rfile.read(size)
        if len(data) != size:
            raise ContractError("Incomplete request")
        value = parse_json(data)
        if type(value) is not dict:
            raise ContractError("Expected a JSON object")
        return value

    def do_GET(self):
        if not self.boundary():
            return
        path = urlsplit(self.path)
        if path.query or path.fragment or path.path != self.path:
            self.respond(404, {"error": "Unknown route"})
            return
        if self.path in ASSETS:
            name, kind = ASSETS[self.path]
            self.respond(
                200,
                files("blastcontain_drill.workbench").joinpath("assets", name).read_bytes(),
                kind,
            )
            return
        if not self.authenticated():
            return
        try:
            if self.path == "/api/state":
                result = self.server.workspace.snapshot()
            elif self.path == "/api/runs":
                result = self.server.runs.snapshot()
            elif self.path == "/api/export":
                result = self.server.workspace.export()
            elif self.path == "/api/research":
                result = self.server.research.snapshot()
            elif self.path == "/api/mappings":
                result = self.server.research.mappings()
            else:
                self.respond(404, {"error": "Unknown route"})
                return
            self.respond(200, result)
        except ContractError as error:
            self.respond(400, {"error": str(error)[:512]})
        except Exception:
            self.respond(
                500,
                {"error": "Cannot read workspace data; check the selected files and permissions"},
            )

    def do_POST(self):
        if not self.boundary(mutation=True):
            return
        if self.path != "/api/session" and not self.authenticated():
            return
        try:
            data = self.body()
            routes = {
                "/api/import": (
                    {"kind", "document", "expected_revision"},
                    lambda: self.server.workspace.import_artifact(
                        data["kind"], data["document"], data["expected_revision"]
                    ),
                ),
                "/api/suite": (
                    {"document", "expected_revision"},
                    lambda: self.server.workspace.save_suite(
                        data["document"], data["expected_revision"]
                    ),
                ),
                "/api/decision": (
                    {
                        "kind",
                        "subject",
                        "expected_digest",
                        "actor",
                        "rationale",
                        "decision",
                        "grants",
                        "expected_revision",
                    },
                    lambda: self.server.workspace.decide(**data),
                ),
                "/api/probe": (
                    {"plugin_id", "expected_revision"},
                    lambda: self.server.workspace.probe(**data),
                ),
                "/api/lock": ({"expected_revision"}, lambda: self.server.workspace.lock(**data)),
                "/api/run": (
                    {"expected_revision", "request_id", "raw_retention_seconds"},
                    lambda: self.server.runs.start(**data),
                ),
                "/api/cancel": ({"job_id"}, lambda: self.server.runs.cancel(data["job_id"])),
                "/api/verify": (
                    {"run_id"},
                    lambda: self.server.runs.verify(data["run_id"], research=self.server.research),
                ),
                "/api/research/review": (
                    {"paper_id", "status", "actor", "note", "expected_revision"},
                    lambda: self.server.research.review(**data),
                ),
                "/api/session": ({"token"}, lambda: {"token": self.server.exchange(data["token"])}),
            }
            route = routes.get(self.path)
            if route is None:
                self.respond(404, {"error": "Unknown route"})
                return
            fields, operation = route
            if set(data) != fields:
                raise ContractError("Request fields differ from this operation's schema")
            self.respond(200, operation())
        except ContractError as error:
            status = (
                409 if "reload" in str(error).lower() or "changed" in str(error).lower() else 400
            )
            self.respond(status, {"error": str(error)[:512]})
        except Exception:
            self.respond(500, {"error": "Operation failed; check its inputs and private workspace"})

    def do_OPTIONS(self):
        self.respond(403, {"error": "Cross-origin access is not supported"})
