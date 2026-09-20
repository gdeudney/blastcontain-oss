"""Explicitly opted-in, bounded control validation against synthetic loopback fixtures.

The customer-record-v1 adapter is a fixture contract, not a generic MCP/OAuth test.
Only the independently authenticated control endpoint supplies state observations.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import os
import re
import time
from urllib.parse import urlsplit
import uuid

import httpx

from .models import InfraFinding, ScanStatus, Severity
from .mcp_target import _read_json, validate_target_config

CHECKS = {
    'CTL-01': 'Authentication', 'CTL-02': 'Tool/resource/field authorization',
    'CTL-03': 'Exact-action approval', 'CTL-04': 'Replay protection',
    'CTL-05': 'Cumulative call budget', 'CTL-06': 'Revocation',
}


def _loopback_url(value, control=False):
    if not isinstance(value, str):
        raise ValueError('Fixture URL must be a string')
    parsed = urlsplit(value)
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or not ipaddress.ip_address(parsed.hostname).is_loopback):
        raise ValueError('Fixture URLs must use literal loopback IPs without credentials or query strings')
    parsed.port
    if control and parsed.path not in ('', '/'):
        raise ValueError('Control URL must be an origin without a path')
    return value.rstrip('/') if control else value


def load_manifest(cfg):
    manifest, digest = _read_json(cfg.control_manifest)
    if set(manifest) != {'adapter', 'target_id', 'mcp_url', 'control_url', 'admin_token_env'}:
        raise ValueError('Control manifest requires adapter, target_id, mcp_url, control_url and admin_token_env')
    if manifest['adapter'] != 'customer-record-v1' or manifest['target_id'] != cfg.target_id:
        raise ValueError('Unsupported fixture adapter or mismatched target ID')
    manifest['mcp_url'] = _loopback_url(manifest['mcp_url'])
    manifest['control_url'] = _loopback_url(manifest['control_url'], control=True)
    if not isinstance(manifest['admin_token_env'], str) or not re.fullmatch(r'[A-Z_][A-Z0-9_]*', manifest['admin_token_env']):
        raise ValueError('admin_token_env must name an environment variable')
    admin = os.environ.get(manifest['admin_token_env'])
    if not admin or len(admin) < 16:
        raise ValueError('Fixture admin credential must be supplied via the named environment variable (16+ characters)')
    config, _ = _read_json(cfg.mcp_config)
    servers = config.get('mcpServers', config.get('mcp_servers', {}))
    server = servers[cfg.mcp_server or next(iter(servers))]
    if server.get('url', server.get('baseUrl')) != manifest['mcp_url']:
        raise ValueError('Manifest MCP URL must exactly match the selected target configuration')
    if manifest['control_url'] == manifest['mcp_url']:
        raise ValueError('Control endpoint must be separate from the MCP endpoint')
    return manifest, digest, admin


class FixtureClient:
    def __init__(self, manifest, admin, client):
        self.manifest, self.admin, self.client = manifest, admin, client
        self.run_id = uuid.uuid4().hex
        self.deadline = time.monotonic() + 60
        self.count = 0
        self.tokens = {}
        self.steps = []
        self.tool_requests = 0

    def request(self, method, url, body=None, headers=None, cleanup=False):
        remaining = self.deadline - time.monotonic()
        if self.count >= (100 if cleanup else 99) or (remaining <= 0 and not cleanup):
            raise ValueError('Validation request/time budget exhausted')
        self.count += 1
        request_deadline = time.monotonic() + min(3, max(0.1, remaining)) if not cleanup else time.monotonic() + 3
        with self.client.stream(method, url, json=body, headers={"Accept-Encoding": "identity", **(headers or {})},
                                timeout=min(3, max(0.1, remaining)) if not cleanup else 3) as response:
            if response.headers.get("Content-Encoding", "identity") != "identity":
                raise ValueError("Compressed fixture responses are not supported")
            chunks = bytearray()
            for chunk in response.iter_bytes():
                chunks.extend(chunk)
                if len(chunks) > 65536 or (time.monotonic() > request_deadline):
                    raise ValueError('Fixture response exceeded bounds')
            data = json.loads(chunks)
            if not isinstance(data, dict):
                raise ValueError('Invalid fixture response')
            return response.status_code, data

    def control(self, operation, body=None, method='POST', cleanup=False):
        path = '/runs' if operation == 'create' else f'/runs/{self.run_id}' + ('' if operation == 'delete' else '/' + operation)
        status, data = self.request(method, self.manifest['control_url'] + path, body,
                                    {'Authorization': 'Bearer ' + self.admin}, cleanup=cleanup)
        if status not in (200, 201):
            raise ValueError('Fixture control operation failed')
        return data

    def state(self):
        data = self.control('state', method='GET')
        if not isinstance(data.get('records'), dict) or not isinstance(data.get('events'), list):
            raise ValueError('Invalid state observation')
        return data

    def call(self, label, args, role='caller', expected=True, tool='update_customer', approval=None,
             denied_codes=(401, 403, 409, 429)):
        before = self.state()
        headers = {'X-Validation-Run': self.run_id}
        if role is not None:
            headers['Authorization'] = 'Bearer ' + self.tokens.get(role, 'invalid-fixture-credential')
        params = {'name': tool, 'arguments': args}
        if approval:
            params['_meta'] = {'approval': approval}
        self.tool_requests += 1
        request_id = self.count
        status, data = self.request('POST', self.manifest['mcp_url'], {
            'jsonrpc': '2.0', 'id': request_id, 'method': 'tools/call', 'params': params,
        }, headers)
        after = self.state()
        if expected:
            wanted = copy.deepcopy(before)
            wanted['records'][args['customer_id']][args['field']] = args['value']
            wanted['events'].append(dict(args))
            # Fixture events carry the action's four fields, not tokens or raw responses.
            success = (status == 200 and data.get('jsonrpc') == '2.0' and data.get('id') == request_id
                       and isinstance(data.get('result'), dict)
                       and data['result'].get('isError') is False and after == wanted)
        else:
            success = status in denied_codes and before == after
        self.steps.append({'case': label, 'expected': 'allow' if expected else 'deny',
                           'http_status': status, 'state_unchanged': before == after,
                           'before_sha256': hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
                           'after_sha256': hashlib.sha256(json.dumps(after, sort_keys=True).encode()).hexdigest(),
                           'passed': success})
        return success


def validate_controls(cfg):
    validate_target_config(cfg)
    if not cfg.control_manifest or not cfg.allow_live_tests:
        raise ValueError("Live fixture validation requires explicit opt-in")
    selected, _ = _read_json(cfg.control_manifest)
    if selected.get('adapter') == 'mcp-scenarios-v1':
        from .mcp_scenarios import validate_scenarios
        return validate_scenarios(cfg)
    manifest, digest, admin = load_manifest(cfg)
    report = {'adapter': manifest['adapter'], 'manifest_sha256': digest,
              'checks': [], 'cleanup_complete': False,
              'limits': {'max_requests': 100, 'max_seconds': 60, 'max_response_bytes': 65536},
              'limitations': ['Synthetic customer-record fixture only; not generic MCP/OAuth conformance',
                              'No concurrency, egress, delegation or agent behavior tests',
                              'State evidence trusts the separately authenticated fixture control endpoint']}
    # Proxies and redirects could send fixture credentials outside the approved target.
    with httpx.Client(trust_env=False, follow_redirects=False) as client:
        fixture = FixtureClient(manifest, admin, client)
        report["fixture_run_id"] = fixture.run_id
        created = False
        try:
            # Mark attempted creation for cleanup even if its response is lost.
            created = True
            setup = fixture.control('create', {'run_id': fixture.run_id})
            if setup.get('run_id') != fixture.run_id or setup.get('adapter') != manifest['adapter']:
                raise ValueError('Fixture contract mismatch')
            fixture.tokens = setup['tokens']
            roles = {'caller', 'limited', 'wrong_audience', 'expired', 'revocable', 'budget'}
            if (not isinstance(fixture.tokens, dict) or set(fixture.tokens) != roles
                    or any(not isinstance(t, str) or len(t) < 16 for t in fixture.tokens.values())
                    or len(set(fixture.tokens.values())) != len(roles) or admin in fixture.tokens.values()):
                raise ValueError('Invalid fixture credentials')

            def args(label, **overrides):
                return {'customer_id': 'A-1', 'field': 'phone', 'value': label,
                        'operation_id': label, **overrides}

            for check_id, title in CHECKS.items():
                start = len(fixture.steps)
                try:
                    if check_id == 'CTL-01':
                        fixture.call('auth-allowed', args('auth-allowed'))
                        for role in (None, 'invalid', 'wrong_audience', 'expired'):
                            fixture.call('auth-' + str(role), args('auth-' + str(role)), role=role, expected=False,
                                         denied_codes=(401, 403))
                    elif check_id == 'CTL-02':
                        fixture.call('scope-allowed', args('scope-allowed'))
                        fixture.call('tool-denied', args('tool-denied'), tool='delete_customer', expected=False, denied_codes=(403,))
                        fixture.call('role-denied', args('role-denied'), role='limited', expected=False, denied_codes=(403,))
                        fixture.call('record-denied', args('record-denied', customer_id='A-2'), expected=False, denied_codes=(403,))
                        fixture.call('tenant-denied', args('tenant-denied', customer_id='B-1'), expected=False, denied_codes=(403,))
                        fixture.call('field-denied', args('field-denied', field='notes'), expected=False, denied_codes=(403,))
                    elif check_id == 'CTL-03':
                        action = args('approved-bank', field='bank')
                        fixture.call('approval-missing', action, expected=False, denied_codes=(403,))
                        before = fixture.state()
                        status, _ = fixture.request('POST', manifest['control_url'] + f'/runs/{fixture.run_id}/approve',
                                                    {'args': action}, {'Authorization': 'Bearer ' + fixture.tokens['caller']})
                        unchanged = before == fixture.state()
                        fixture.steps.append({'case': 'caller-cannot-mint-approval', 'expected': 'deny',
                                              'http_status': status, 'state_unchanged': unchanged,
                                              'passed': status in (401, 403) and unchanged})
                        approval = fixture.control('approve', {'args': action})['approval']
                        fixture.call('approval-substitution', {**action, 'value': 'different-bank'}, approval=approval, expected=False, denied_codes=(403,))
                        fixture.call('approval-wrong-caller', action, role='revocable', approval=approval, expected=False, denied_codes=(403,))
                        fixture.call('approval-allowed', action, approval=approval)
                        fixture.call('approval-reuse', action, approval=approval, expected=False)
                        expired = args('expired-approval', field='bank')
                        token = fixture.control('approve', {'args': expired, 'ttl': -1})['approval']
                        fixture.call('approval-expired', expired, approval=token, expected=False, denied_codes=(403,))
                    elif check_id == 'CTL-04':
                        action = args('replay-operation')
                        fixture.call('replay-first', action)
                        fixture.call('replay-repeat', action, expected=False, denied_codes=(409,))
                    elif check_id == 'CTL-05':
                        for index in range(3):
                            fixture.call('budget-' + str(index), args('budget-' + str(index)), role='budget',
                                         expected=index < 2, denied_codes=(429,))
                    elif check_id == 'CTL-06':
                        fixture.call('before-revocation', args('before-revocation'), role='revocable')
                        fixture.control('revoke')
                        fixture.call('after-revocation', args('after-revocation'), role='revocable', expected=False, denied_codes=(401, 403))
                    steps = fixture.steps[start:]
                    status = 'PASS' if steps and all(s['passed'] for s in steps) else 'FAIL'
                except (httpx.HTTPError, ValueError, KeyError, TypeError, RecursionError):
                    status = 'ERROR'
                report['checks'].append({'check_id': check_id, 'title': title, 'status': status,
                                         'cases': fixture.steps[start:]})
        except (httpx.HTTPError, ValueError, KeyError, TypeError, RecursionError):
            report['setup_error'] = 'Fixture setup failed; credentials and response bodies omitted'
        finally:
            if created:
                try:
                    report['cleanup_complete'] = fixture.control('delete', method='DELETE', cleanup=True).get('deleted') is True
                except (httpx.HTTPError, ValueError, KeyError, TypeError, RecursionError):
                    pass
            report['requests_sent'] = fixture.count
            report['tool_requests_attempted'] = fixture.tool_requests
    report['complete'] = (len(report['checks']) == len(CHECKS)
                          and all(c['status'] != 'ERROR' for c in report['checks']) and report['cleanup_complete'])
    return report


def attach_validation(cfg, result):
    if not result.coverage['complete']:
        result.validation = {'complete': False, 'reason': 'Passive assessment coverage must be complete before live validation'}
        return result
    try:
        result.validation = validate_controls(cfg)
    except (ValueError, KeyError, TypeError, OSError, RecursionError):
        result.validation = {'complete': False, 'reason': 'Invalid control manifest or missing fixture credentials'}
    for check in result.validation.get('checks', []):
        if check['status'] == 'PASS':
            result.passed.append(check['check_id'])
        elif check['status'] == 'FAIL':
            result.findings.append(InfraFinding(
                check_id=check['check_id'], finding_type='blastcontain.control.validation_failed',
                severity=Severity.HIGH, title=check['title'] + ' validation failed',
                detail='One or more bounded validation cases violated the expected response or trusted state transition.',
                remediation='Inspect the recorded cases and fix the enforcement boundary before retesting.',
                evidence='Live control validation; response bodies and credentials omitted',
            ))
    result.coverage['required_checks'].extend(CHECKS)
    observed = {c['check_id'] for c in result.validation.get('checks', []) if c['status'] != 'ERROR'}
    result.coverage['missing_required_checks'].extend(sorted(set(CHECKS) - observed))
    practical = result.validation.get('adapter') == 'mcp-scenarios-v1'
    evidence = 'live_operator_scenarios' if practical else 'live_fixture_validation'
    scope = 'operator scenarios' if practical else 'synthetic fixture'
    result.coverage['check_evidence'].update({check: evidence for check in observed})
    result.coverage['profile'] = 'mcp-passive-v1+' + result.validation.get('adapter', 'unknown')
    statuses = {c['check_id']: c['status'] for c in result.validation.get('checks', [])}
    mapping = {'scoped_authorization': ['CTL-02'], 'identity_and_credentials': ['CTL-01'],
               'exact_action_approval': ['CTL-03'], 'replay_and_cumulative_limits': ['CTL-04', 'CTL-05'],
               'audit_and_independent_stopping': ['CTL-06']}
    for feature, checks in mapping.items():
        if any(check in statuses for check in checks):
            result.coverage['feature_coverage'][feature] = 'Passive: ' + result.coverage['feature_coverage'][feature] + '; ' + scope + ': ' + ', '.join(
                check + '=' + statuses.get(check, 'NOT_RUN') for check in checks)
    result.coverage['fixture_authentication_validated'] = not practical and statuses.get('CTL-01') == 'PASS'
    result.coverage['scenario_authentication_validated'] = practical and statuses.get('CTL-01') == 'PASS'
    result.coverage['control_validation_complete'] = result.validation['complete']
    result.coverage['tools_invoked'] = result.validation.get('tool_requests_attempted', 0) > 0
    result.coverage['complete'] = result.coverage['complete'] and result.validation['complete'] and not result.coverage['missing_required_checks']
    result.status = result.derive_status() if result.coverage['complete'] else ScanStatus.ERROR
    return result
