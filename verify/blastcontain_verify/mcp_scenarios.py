"""Bounded, operator-authored MCP checks with a separate state-observer contract.

No commands or generated code are executed. The manifest is a write-test plan;
only explicit CLI live consent enables it. HTTP JSON, stateless MCP only for now.
"""
from __future__ import annotations

import hashlib
import json
import os
import re

import httpx

from .control_validation import CHECKS, FixtureClient, _loopback_url
from .mcp_target import _read_json

ADAPTER = 'mcp-scenarios-v1'
VERSION = '2025-11-25'


def _name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', value):
        raise ValueError('Invalid scenario identifier')
    return value


def load_plan(cfg):
    plan, digest = _read_json(cfg.control_manifest)
    required = {'adapter', 'target_id', 'mcp_url', 'control_url', 'admin_token_env',
                'credentials', 'discovery_credential', 'cases'}
    if set(plan) != required or plan['adapter'] != ADAPTER or plan['target_id'] != cfg.target_id:
        raise ValueError('Invalid MCP scenario manifest')
    plan['mcp_url'] = _loopback_url(plan['mcp_url'])
    plan['control_url'] = _loopback_url(plan['control_url'], control=True)
    if plan['control_url'] == plan['mcp_url']:
        raise ValueError('Separate observer required')
    config, _ = _read_json(cfg.mcp_config)
    servers = config.get('mcpServers', config.get('mcp_servers', {}))
    server = servers[cfg.mcp_server or next(iter(servers))]
    if server.get('url', server.get('baseUrl')) != plan['mcp_url']:
        raise ValueError('MCP target mismatch')

    def secret(env):
        if not isinstance(env, str) or not re.fullmatch(r'[A-Z_][A-Z0-9_]*', env):
            raise ValueError('Credentials must reference environment variables')
        value = os.environ.get(env, '')
        if len(value) < 16 or '\n' in value or '\r' in value:
            raise ValueError('Missing or malformed credential')
        return value

    admin = secret(plan['admin_token_env'])
    if not isinstance(plan['credentials'], dict) or not 1 <= len(plan['credentials']) <= 16:
        raise ValueError('Invalid credential map')
    credentials = {_name(k): secret(v) for k, v in plan['credentials'].items()}
    if admin in credentials.values() or plan['discovery_credential'] not in credentials:
        raise ValueError('Observer credential must be separate from callers')
    cases = plan['cases']
    if not isinstance(cases, list) or not 2 <= len(cases) <= 32:
        raise ValueError('Two to 32 cases required')
    labels = set()
    groups = {}
    for case in cases:
        keys = {'id', 'check_id', 'credential', 'tool', 'arguments', 'expect', 'after'}
        if not isinstance(case, dict) or set(case) - (keys | {'prepare', 'denial_code'}) or not keys <= set(case):
            raise ValueError('Invalid scenario case')
        label = _name(case['id'])
        if label in labels or case['check_id'] not in CHECKS:
            raise ValueError('Duplicate case or unknown control')
        labels.add(label)
        if case['credential'] is not None and case['credential'] not in credentials:
            raise ValueError('Unknown caller credential')
        _name(case['tool'])
        if not isinstance(case['arguments'], dict) or case['expect'] not in ('allow', 'deny'):
            raise ValueError('Invalid tool arguments or outcome')
        if case['expect'] == 'deny' and (case['after'] != 'unchanged' or not isinstance(case.get('denial_code'), str)):
            raise ValueError('Denials require unchanged state and an explicit denial code')
        if case['expect'] == 'allow' and not isinstance(case['after'], dict):
            raise ValueError('Allowed calls require exact expected state')
        if 'prepare' in case:
            prepare = case['prepare']
            if not isinstance(prepare, dict) or set(prepare) != {'operation', 'arguments'} or not isinstance(prepare['arguments'], dict):
                raise ValueError('Invalid observer preparation')
            _name(prepare['operation'])
        groups.setdefault(case['check_id'], set()).add(case['expect'])
    # Each claimed control must prove an allowed and a denied operation.
    if any(outcomes != {'allow', 'deny'} for outcomes in groups.values()):
        raise ValueError('Each control requires a positive and negative case')
    return plan, digest, admin, credentials


def _expand(value, run_id, bindings):
    if isinstance(value, dict):
        if set(value) == {'$binding'}:
            return bindings[value['$binding']]
        return {k: _expand(v, run_id, bindings) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v, run_id, bindings) for v in value]
    return run_id if value == '$RUN_ID' else value


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class ScenarioClient(FixtureClient):
    """Reuse bounds; allow empty notification bodies, reject stateful/SSE endpoints."""
    def snapshot(self):
        return self.control('state', method='GET')

    def rpc(self, method, params, token, notification=False):
        headers = {'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': VERSION}
        if token is not None:
            headers['Authorization'] = 'Bearer ' + token
        body = {'jsonrpc': '2.0', 'method': method, 'params': params}
        request_id = self.count + 1
        if not notification:
            body['id'] = request_id
        status, data = self.request('POST', self.manifest['mcp_url'], body, headers)
        if notification:
            if status != 202:
                raise ValueError('MCP initialized notification failed')
        elif status == 200 and (data.get('jsonrpc') != '2.0' or data.get('id') != request_id
                                or ('result' in data) == ('error' in data)):
            raise ValueError('Invalid MCP response envelope')
        return status, data


class JsonTransport(httpx.BaseTransport):
    """Stateless JSON profile only. Never silently downgrade unsupported transport."""
    def __init__(self):
        self.inner = httpx.HTTPTransport(trust_env=False)

    def handle_request(self, request):
        response = self.inner.handle_request(request)
        if request.url.path.endswith('/mcp') or request.headers.get('MCP-Protocol-Version'):
            if response.headers.get('Mcp-Session-Id'):
                response.close()
                raise ValueError('Stateful MCP is not supported by this adapter')
            if response.status_code == 202:
                # Check the body is actually empty (bounded read in the outer client
                # is bypassed only here); any byte makes this an invalid notification.
                for chunk in response.iter_raw():
                    if chunk:
                        response.close()
                        raise ValueError('Unexpected notification response body')
                response.close()
                return httpx.Response(202, json={})
            if response.status_code == 200 and response.headers.get('content-type', '').split(';')[0] != 'application/json':
                response.close()
                raise ValueError('This adapter requires JSON MCP responses')
        return response

    def close(self):
        self.inner.close()


def validate_scenarios(cfg):
    from .mcp_target import validate_target_config
    validate_target_config(cfg)
    if not cfg.control_manifest or not cfg.allow_live_tests:
        raise ValueError('Live validation requires explicit opt-in')
    plan, digest, admin, credentials = load_plan(cfg)
    report = {'adapter': ADAPTER, 'manifest_sha256': digest, 'checks': [], 'cleanup_complete': False,
              'limits': {'max_requests': 100, 'max_seconds': 60, 'max_response_bytes': 65536},
              'limitations': ['Operator-authored cases prove only the declared scenarios, not the full control family',
                              'Stateless JSON MCP over literal loopback HTTP(S); no stdio, SSE or OAuth discovery',
                              'State evidence trusts the operator-supplied observer; external independence is not attested']}
    with httpx.Client(transport=JsonTransport(), trust_env=False, follow_redirects=False) as client:
        runner = ScenarioClient(plan, admin, client)
        report['fixture_run_id'] = runner.run_id
        created = False
        checks = {}
        try:
            created = True
            setup = runner.control('create', {'run_id': runner.run_id, 'adapter': ADAPTER})
            if setup.get('run_id') != runner.run_id or setup.get('adapter') != ADAPTER:
                raise ValueError('Observer contract mismatch')
            bindings = setup.get('bindings', {})
            if not isinstance(bindings, dict):
                raise ValueError('Invalid observer bindings')
            token = credentials[plan['discovery_credential']]
            status, data = runner.rpc('initialize', {'protocolVersion': VERSION, 'capabilities': {},
                                      'clientInfo': {'name': 'blastcontain-verify', 'version': '0.5.0'}}, token)
            result = data.get('result', {})
            if not isinstance(result, dict) or status != 200 or result.get('protocolVersion') != VERSION or not isinstance(result.get('capabilities'), dict) or 'tools' not in result['capabilities']:
                raise ValueError('MCP protocol negotiation failed')
            runner.rpc('notifications/initialized', {}, token, notification=True)
            status, data = runner.rpc('tools/list', {}, token)
            result = data.get('result', {})
            if not isinstance(result, dict):
                raise ValueError('Malformed discovery result')
            advertised = result.get('tools')
            if status != 200 or not isinstance(advertised, list) or result.get('nextCursor'):
                raise ValueError('Tool discovery failed or requires unsupported pagination')
            if any(not isinstance(t, dict) or not isinstance(t.get('name'), str)
                   or not isinstance(t.get('inputSchema'), dict) for t in advertised):
                raise ValueError('Malformed tool inventory')
            names = {t['name'] for t in advertised}
            if any(c['tool'] not in names for c in plan['cases'] if c['expect'] == 'allow'):
                raise ValueError('Positive-control tool is not advertised')
            report['protocol'] = {'version': VERSION, 'initialized': True, 'tools_list_sha256': _hash(advertised)}
            for case in plan['cases']:
                check = checks.setdefault(case['check_id'], {'check_id': case['check_id'],
                                         'title': CHECKS[case['check_id']], 'status': 'PASS', 'cases': []})
                try:
                    if 'prepare' in case:
                        preparation = _expand(case['prepare'], runner.run_id, bindings)
                        prepared = runner.control('prepare', preparation)
                        extra = prepared.get('bindings', {})
                        if not isinstance(extra, dict):
                            raise ValueError('Invalid observer bindings')
                        bindings.update(extra)
                    before = runner.snapshot()
                    args = _expand(case['arguments'], runner.run_id, bindings)
                    runner.tool_requests += 1
                    status, data = runner.rpc('tools/call', {'name': case['tool'], 'arguments': args},
                                              credentials.get(case['credential']))
                    after = runner.snapshot()
                    outcome = data.get('result', {})
                    if not isinstance(outcome, dict):
                        raise ValueError('Malformed tool result')
                    if case['expect'] == 'allow':
                        expected_state = _expand(case['after'], runner.run_id, bindings)
                        passed = (status == 200 and isinstance(outcome, dict)
                                  and isinstance(outcome.get('content'), list) and outcome.get('isError', False) is False
                                  and 'error' not in data and after == expected_state and before != after)
                    else:
                        code = case['denial_code']
                        # A generic JSON-RPC/schema/server error never counts as a
                        # security denial. Match a declared structured tool code or
                        # one of the explicit access/limit HTTP response statuses.
                        denied = (code == f'http:{status}' and status in (401, 403, 409, 429))
                        structured = outcome.get('structuredContent', {}) if isinstance(outcome, dict) else {}
                        denied = denied or (status == 200 and outcome.get('isError') is True
                                            and isinstance(structured, dict) and code == structured.get('denial_code'))
                        passed = denied and before == after
                    check['cases'].append({'case': case['id'], 'expected': case['expect'], 'http_status': status,
                                           'passed': passed, 'state_unchanged': before == after,
                                           'before_sha256': _hash(before), 'after_sha256': _hash(after)})
                    if not passed and check['status'] != 'ERROR':
                        check['status'] = 'FAIL'
                except (httpx.HTTPError, ValueError, KeyError, TypeError, RecursionError):
                    check['status'] = 'ERROR'
                    check['cases'].append({'case': case['id'], 'expected': case['expect'], 'passed': False,
                                           'error': 'Request or evidence invalid; details omitted'})
                    # Do not continue writes after losing reliable state evidence.
                    break
        except (httpx.HTTPError, ValueError, KeyError, TypeError, RecursionError):
            report['setup_error'] = 'Protocol or observer setup failed; details omitted'
        finally:
            if created:
                try:
                    report['cleanup_complete'] = runner.control('delete', method='DELETE', cleanup=True).get('deleted') is True
                except (httpx.HTTPError, ValueError, KeyError, TypeError, RecursionError):
                    pass
            report['checks'] = list(checks.values())
            report['requests_sent'] = runner.count
            report['tool_requests_attempted'] = runner.tool_requests
    executed = sum(len(c['cases']) for c in report['checks'])
    report['not_tested_controls'] = sorted(set(CHECKS) - checks.keys())
    report['complete'] = (not report.get('setup_error') and executed == len(plan['cases'])
                          and all(c['status'] != 'ERROR' for c in report['checks']) and report['cleanup_complete'])
    return report
