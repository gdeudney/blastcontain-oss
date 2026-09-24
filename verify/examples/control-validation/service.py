"""Synthetic MCP/control fixture. Never connect this demonstration to real data."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import threading
import time


@contextmanager
def fixture(admin_token, insecure=False, mcp_port=0, control_port=0, deny_all=False, mutate_denials=False):
    runs = {}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Request paths and credentials never enter logs.

        def reply(self, status, body):
            if mutate_denials and not self.server.control and status in (401, 403, 409, 429):
                run = runs.get(self.headers.get('X-Validation-Run'))
                if run:
                    run['records']['A-1']['phone'] = 'unexpected-denial-effect'
                    run['events'].append({'unexpected_effect': True})
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            self.dispatch()

        def do_GET(self):
            self.dispatch()

        def do_DELETE(self):
            self.dispatch()

        def dispatch(self):
            with lock:
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                    if length < 0 or length > 65536:
                        return self.reply(413, {'error': 'too large'})
                    data = json.loads(self.rfile.read(length)) if length else {}
                    if self.server.control:
                        return self.control(data)
                    return self.mcp(data)
                except (ValueError, KeyError, TypeError):
                    self.reply(400, {'error': 'invalid fixture request'})

        def control(self, data):
            if not secrets.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + admin_token):
                return self.reply(403, {'error': 'control denied'})
            parts = self.path.strip('/').split('/')
            if self.command == 'POST' and self.path == '/runs':
                run_id = data['run_id']
                if run_id in runs:
                    return self.reply(409, {'error': 'run exists'})
                tokens = {role: secrets.token_urlsafe(24) for role in
                          ('caller', 'limited', 'wrong_audience', 'expired', 'revocable', 'budget')}
                runs[run_id] = {'records': {
                    'A-1': {'phone': '0000', 'bank': 'original'},
                    'A-2': {'phone': '0000', 'bank': 'original'},
                    'B-1': {'phone': '0000', 'bank': 'original'},
                }, 'events': [], 'tokens': tokens, 'revoked': [], 'approvals': {}, 'used': [], 'budget': 0}
                return self.reply(201, {'run_id': run_id, 'tokens': tokens, 'adapter': 'customer-record-v1'})
            if len(parts) < 2 or parts[0] != 'runs' or parts[1] not in runs:
                return self.reply(404, {'error': 'unknown run'})
            run = runs[parts[1]]
            if len(parts) == 2 and self.command == 'DELETE':
                del runs[parts[1]]
                return self.reply(200, {'deleted': True})
            if parts[-1] == 'state' and self.command == 'GET':
                return self.reply(200, {'records': run['records'], 'events': run['events']})
            if parts[-1] == 'approve' and self.command == 'POST':
                token = secrets.token_urlsafe(24)
                run['approvals'][token] = {'args': data['args'], 'caller': run['tokens']['caller'],
                                           'expires': time.time() + data.get('ttl', 60), 'used': False}
                return self.reply(201, {'approval': token})
            if parts[-1] == 'revoke' and self.command == 'POST':
                run['revoked'].append(run['tokens']['revocable'])
                return self.reply(200, {'revoked': True})
            return self.reply(404, {'error': 'unknown control operation'})

        def mcp(self, data):
            if self.path != '/mcp' or self.command != 'POST':
                return self.reply(404, {'error': 'not MCP'})
            run = runs.get(self.headers.get('X-Validation-Run'))
            if run is None:
                return self.reply(404, {'error': 'unknown run'})
            if deny_all:
                return self.reply(403, {'error': 'deny-all fixture'})
            token = self.headers.get('Authorization', '').removeprefix('Bearer ')
            role = next((name for name, value in run['tokens'].items() if secrets.compare_digest(value, token)), None)
            if not self.server.insecure and (role in (None, 'wrong_audience', 'expired') or token in run['revoked']):
                return self.reply(401, {'error': 'unauthorized'})
            if data['method'] != 'tools/call':
                return self.reply(400, {'error': 'fixture supports tools/call only'})
            params = data['params']
            args = params['arguments']
            key, field, value = args['customer_id'], args['field'], args['value']
            operation = args['operation_id']
            if not self.server.insecure:
                if params['name'] != 'update_customer' or role == 'limited' or key != 'A-1':
                    return self.reply(403, {'error': 'forbidden'})
                if field not in ('phone', 'bank'):
                    return self.reply(403, {'error': 'field forbidden'})
                if field == 'bank':
                    approval = run['approvals'].get(params.get('_meta', {}).get('approval'))
                    if (not approval or approval['args'] != args or approval['caller'] != token
                            or approval['used'] or approval['expires'] < time.time()):
                        return self.reply(403, {'error': 'approval rejected'})
                if operation in run['used']:
                    return self.reply(409, {'error': 'duplicate'})
                if role == 'budget' and run['budget'] >= 2:
                    return self.reply(429, {'error': 'budget exceeded'})
            if key not in run['records']:
                return self.reply(404, {'error': 'unknown record'})
            run['records'][key][field] = value
            run['events'].append({'operation_id': operation, 'customer_id': key, 'field': field, 'value': value})
            run['used'].append(operation)
            if role == 'budget':
                run['budget'] += 1
            if field == 'bank' and params.get('_meta', {}).get('approval') in run['approvals']:
                run['approvals'][params['_meta']['approval']]['used'] = True
            return self.reply(200, {'jsonrpc': '2.0', 'id': data['id'], 'result': {
                'content': [{'type': 'text', 'text': 'synthetic update complete'}], 'isError': False}})

    servers = []
    threads = []
    try:
        for port, control in ((mcp_port, False), (control_port, True)):
            server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
            server.control = control
            server.insecure = insecure
            servers.append(server)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
        yield {'mcp_url': f'http://127.0.0.1:{servers[0].server_port}/mcp',
               'control_url': f'http://127.0.0.1:{servers[1].server_port}', 'runs': runs}
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


if __name__ == '__main__':
    import os
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--insecure', action='store_true')
    parser.add_argument('--mcp-port', type=int, default=8080)
    parser.add_argument('--control-port', type=int, default=8081)
    cli = parser.parse_args()
    with fixture(os.environ['VERIFY_FIXTURE_ADMIN_TOKEN'], cli.insecure, cli.mcp_port, cli.control_port):
        print('Synthetic fixture ready on loopback; use only test data.', flush=True)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
