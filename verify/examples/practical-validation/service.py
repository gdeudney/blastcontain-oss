"""Official MCP SDK server with JWT verification and separately hosted test observer.

Reference integration only. Synthetic namespace data; no model or production access.
The observer owns setup/approval/revocation/cleanup. Production deployments should
observe their actual datastore/audit sink through an appropriately isolated adapter.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import socket
import threading
import time

import jwt
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, TextContent
import uvicorn

identity = ContextVar('identity', default=None)


@contextmanager
def server(insecure=False, deny_all=False, mutate_denials=False):
    key = secrets.token_urlsafe(32)
    admin = secrets.token_urlsafe(32)
    roles = ('caller', 'limited', 'expired', 'wrong_audience', 'revocable', 'budget')
    tokens = {role: jwt.encode({'sub': role, 'iss': 'verify-reference',
                               'aud': 'other' if role == 'wrong_audience' else 'verify-mcp',
                               'exp': time.time() + (-60 if role == 'expired' else 600)}, key, algorithm='HS256')
              for role in roles}
    tokens['invalid'] = 'invalid-reference-credential'
    runs = {}
    lock = threading.Lock()
    mcp = MCPServer('Verify reference records', version='1.0', log_level='ERROR')

    @mcp.tool()
    def update_record(namespace: str, record: str, field: str, value: str,
                      operation: str, approval: str = '') -> CallToolResult:
        with lock:
            run = runs[namespace]
            who = identity.get()
            reason = None
            args = {'record': record, 'field': field, 'value': value, 'operation': operation}
            if who == 'limited' or record != 'A-1' or field not in ('phone', 'bank'):
                reason = 'scope'
            elif who in run['revoked']:
                reason = 'revoked'
            elif field == 'bank':
                approved = run['approvals'].get(approval)
                if not approved or approved['args'] != args or approved['caller'] != who or approved['used'] or approved['expires'] < time.time():
                    reason = 'approval'
            if not reason and operation in run['used']:
                reason = 'replay'
            if not reason and who == 'budget' and run['budget'] >= 2:
                reason = 'budget'
            if deny_all:
                reason = 'scope'
            if reason and not insecure:
                if mutate_denials:
                    run['records']['A-1']['phone'] = 'unauthorized'
                return CallToolResult(content=[TextContent(type='text', text='Denied')], isError=True,
                                      structuredContent={'denial_code': reason})
            run['records'].setdefault(record, {})[field] = value
            run['events'].append(args)
            run['used'].add(operation)
            if who == 'budget':
                run['budget'] += 1
            if approval in run['approvals']:
                run['approvals'][approval]['used'] = True
            return CallToolResult(content=[TextContent(type='text', text='Updated')], isError=False)

    sdk_app = mcp.streamable_http_app(stateless_http=True, json_response=True)

    async def app(scope, receive, send):
        if scope['type'] != 'http':
            return await sdk_app(scope, receive, send)
        headers = dict(scope['headers'])
        token = headers.get(b'authorization', b'').decode().removeprefix('Bearer ')
        try:
            claims = jwt.decode(token, key, algorithms=['HS256'], audience='verify-mcp', issuer='verify-reference',
                                options={'require': ['exp', 'sub', 'iss', 'aud']})
            who = claims['sub']
        except jwt.InvalidTokenError:
            if not insecure:
                await send({'type': 'http.response.start', 'status': 401,
                            'headers': [(b'content-type', b'application/json')]})
                return await send({'type': 'http.response.body', 'body': b'{"error":"unauthorized"}'})
            who = 'caller'
        context = identity.set(who)
        try:
            await sdk_app(scope, receive, send)
        finally:
            identity.reset(context)

    class Observer(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.dispatch()

        def do_GET(self):
            self.dispatch()

        def do_DELETE(self):
            self.dispatch()

        def dispatch(self):
            with lock:
                try:
                    if not secrets.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + admin):
                        return self.reply(403, {'error': 'observer denied'})
                    length = int(self.headers.get('Content-Length', '0'))
                    if not 0 <= length <= 65536:
                        return self.reply(413, {})
                    body = json.loads(self.rfile.read(length)) if length else {}
                    parts = self.path.strip('/').split('/')
                    if self.path == '/runs' and self.command == 'POST':
                        run_id = body['run_id']
                        if run_id in runs:
                            return self.reply(409, {})
                        runs[run_id] = {'records': {'A-1': {'phone': '0', 'bank': '0'}, 'B-1': {'phone': '0', 'bank': '0'}},
                                        'events': [], 'used': set(), 'approvals': {}, 'budget': 0, 'revoked': []}
                        return self.reply(201, {'adapter': 'mcp-scenarios-v1', 'run_id': run_id})
                    run = runs[parts[1]]
                    if len(parts) == 2 and self.command == 'DELETE':
                        del runs[parts[1]]
                        return self.reply(200, {'deleted': True})
                    if parts[-1] == 'state' and self.command == 'GET':
                        return self.reply(200, {'records': run['records'], 'events': run['events']})
                    if parts[-1] == 'prepare' and self.command == 'POST':
                        if body['operation'] == 'revoke':
                            run['revoked'].append('revocable')
                            return self.reply(200, {})
                        if body['operation'] == 'approve':
                            approval = secrets.token_urlsafe(24)
                            run['approvals'][approval] = {'args': body['arguments'], 'caller': 'caller', 'used': False,
                                                          'expires': time.time() + 60}
                            return self.reply(200, {'bindings': {'approval': approval}})
                    return self.reply(404, {})
                except (KeyError, TypeError, ValueError, IndexError):
                    return self.reply(400, {})

        def reply(self, status, body):
            encoded = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    observer = ThreadingHTTPServer(('127.0.0.1', 0), Observer)
    thread = threading.Thread(target=observer.serve_forever, daemon=True)
    thread.start()
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    uv = uvicorn.Server(uvicorn.Config(app, log_level='critical', access_log=False))
    worker = threading.Thread(target=uv.run, kwargs={'sockets': [sock]}, daemon=True)
    worker.start()
    try:
        deadline = time.monotonic() + 10
        while not uv.started:
            if not worker.is_alive() or time.monotonic() > deadline:
                raise RuntimeError('Reference server failed to start')
            time.sleep(0.01)
        yield {'mcp_url': f'http://127.0.0.1:{port}/mcp',
               'control_url': f'http://127.0.0.1:{observer.server_port}',
               'admin': admin, 'tokens': tokens, 'runs': runs}
    finally:
        uv.should_exit = True
        worker.join(timeout=10)
        sock.close()
        observer.shutdown()
        observer.server_close()
        thread.join(timeout=3)
