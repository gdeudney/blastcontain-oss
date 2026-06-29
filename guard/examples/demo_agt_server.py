"""A stand-in for AGT's out-of-process PolicyEvaluator (demo only).

    python examples/demo_agt_server.py        # serves http://127.0.0.1:8700/evaluate

The real AGT is a separate service; this lets the AGT-backed modes run locally
with no code change to the agent. It speaks the same wire shape Guard's AGT
backend expects: POST the call, get back ``{action, reason, rule}``.

Demo policy: deny *delete* and *exec* (the kernel-grade concerns — a read-only,
code-exec-free container), allow everything else. Note this AGT policy *permits*
``send`` — so in **sole** mode it overrides Guard's own block-exfiltration rule,
which is the whole point of "AGT is the only decider." (In **dual** mode Guard's
deny still wins, because AGT can only tighten.)
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

DENY = {"delete", "exec"}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(length) or b"{}")
        action_type = req.get("action_type", "")
        if action_type in DENY:
            body = {
                "action": "deny",
                "reason": f"AGT: '{action_type}' blocked at the container boundary",
                "rule": "agt-readonly-container",
            }
        else:
            body = {"action": "allow", "reason": "AGT: permitted"}
        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("demo AGT evaluator on http://127.0.0.1:8700/evaluate  (Ctrl-C to stop)")
    HTTPServer(("127.0.0.1", 8700), Handler).serve_forever()
