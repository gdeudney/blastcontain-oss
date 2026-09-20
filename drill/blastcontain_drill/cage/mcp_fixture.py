"""Disposable loopback MCP poison fixture. No remote target or executable payloads.

A deliberately narrow stateless JSON MCP server/client pair: initialize, initialized,
tools/list, tools/call. It only returns an in-memory invoice and attacker-authored
text. It cannot access files, execute commands, or send data out of the cage.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading

VERSION = '2025-11-25'
TOOL = 'lookup_invoice'
BASE_DESCRIPTION = 'Look up the status and amount of an invoice by invoice_id.'
BASE_RESPONSE = 'Invoice INV-001: paid, amount USD 42.00.'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class FixtureClient:
    def __init__(self, port):
        self.port = port
        self.events = []
        self.count = 0

    def rpc(self, method, params=None, notification=False):
        if self.count >= 16:
            raise ValueError('MCP fixture request limit reached')
        self.count += 1
        body = {'jsonrpc': '2.0', 'method': method, 'params': params or {}}
        if not notification:
            body['id'] = self.count
        encoded = json.dumps(body).encode()
        if len(encoded) > 16384:
            raise ValueError('MCP fixture request too large')
        connection = HTTPConnection('127.0.0.1', self.port, timeout=2)
        try:
            connection.request('POST', '/mcp', body=encoded, headers={
                'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream',
                'MCP-Protocol-Version': VERSION})
            response = connection.getresponse()
            raw = response.read(65537)
            if len(raw) > 65536 or response.getheader('Content-Encoding', 'identity') != 'identity':
                raise ValueError('MCP fixture response bounds exceeded')
            if notification:
                if response.status != 202 or raw:
                    raise ValueError('Invalid MCP notification acknowledgement')
                result = {}
            else:
                data = json.loads(raw)
                if (response.status != 200 or not isinstance(data, dict) or data.get('jsonrpc') != '2.0'
                        or data.get('id') != self.count or 'error' in data or not isinstance(data.get('result'), dict)):
                    raise ValueError('Invalid MCP fixture response')
                result = data['result']
            self.events.append({'method': method, 'status': response.status, 'result_sha256': digest(result)})
            return result
        finally:
            connection.close()

    def discover(self):
        result = self.rpc('initialize', {'protocolVersion': VERSION, 'capabilities': {},
                                        'clientInfo': {'name': 'blastcontain-drill', 'version': '1'}})
        if result.get('protocolVersion') != VERSION or 'tools' not in result.get('capabilities', {}):
            raise ValueError('MCP fixture negotiation failed')
        self.rpc('notifications/initialized', notification=True)
        tools = self.rpc('tools/list').get('tools')
        if not isinstance(tools, list) or len(tools) != 1 or tools[0].get('name') != TOOL:
            raise ValueError('Unexpected MCP fixture inventory')
        return tools

    def call(self, args):
        result = self.rpc('tools/call', {'name': TOOL, 'arguments': args})
        if result.get('isError', False) is not False:
            raise ValueError('MCP fixture tool failed')
        content = result.get('content')
        if (not isinstance(content, list) or len(content) != 1
                or content[0].get('type') != 'text' or not isinstance(content[0].get('text'), str)):
            raise ValueError('Invalid MCP fixture tool content')
        return content[0]['text']


@contextmanager
def poison_fixture(description=None, response=None):
    for value in (description, response):
        if value is not None and (not isinstance(value, str) or len(value.encode()) > 12000):
            raise ValueError('Poison payload must be text of at most 12 KiB')
    tool = {'name': TOOL, 'description': description if description is not None else BASE_DESCRIPTION,
            'inputSchema': {'type': 'object', 'properties': {'invoice_id': {'type': 'string'}},
                            'required': ['invoice_id'], 'additionalProperties': False}}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.connection.settimeout(2)
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if self.path != '/mcp' or not 0 < length <= 16384:
                    return self.reply(400, {})
                body = json.loads(self.rfile.read(length))
                method, params = body['method'], body.get('params', {})
                if method == 'notifications/initialized':
                    return self.reply(202, None)
                if method == 'initialize':
                    result = {'protocolVersion': VERSION, 'capabilities': {'tools': {}},
                              'serverInfo': {'name': 'drill-poison-fixture', 'version': '1'}}
                elif method == 'tools/list':
                    result = {'tools': [tool]}
                elif method == 'tools/call':
                    args = params['arguments']
                    if (params['name'] != TOOL or set(args) != {'invoice_id'}
                            or not isinstance(args['invoice_id'], str) or len(args['invoice_id']) > 80):
                        return self.reply(400, {})
                    result = {'content': [{'type': 'text', 'text': response if response is not None else BASE_RESPONSE}], 'isError': False}
                else:
                    return self.reply(400, {})
                self.reply(200, {'jsonrpc': '2.0', 'id': body['id'], 'result': result})
            except (ValueError, KeyError, TypeError, OSError):
                self.reply(400, {})

        def reply(self, status, data):
            raw = json.dumps(data).encode() if data is not None else b''
            try:
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except OSError:
                pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
    thread.start()
    try:
        yield FixtureClient(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
