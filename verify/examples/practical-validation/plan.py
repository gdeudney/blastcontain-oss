"""Example operator-authored case plan; customize for your server and observer."""
import copy


def manifest(endpoints):
    state = {'records': {'A-1': {'phone': '0', 'bank': '0'}, 'B-1': {'phone': '0', 'bank': '0'}}, 'events': []}
    cases = []

    def add(label, check, expect='allow', credential='caller', denial_code=None, prepare=None, **overrides):
        arguments = {'namespace': '$RUN_ID', 'record': 'A-1', 'field': 'phone', 'value': label, 'operation': label, **overrides}
        if expect == 'allow':
            state['records'][arguments['record']][arguments['field']] = arguments['value']
            state['events'].append({key: arguments[key] for key in ('record', 'field', 'value', 'operation')})
        case = {'id': label, 'check_id': check, 'credential': credential, 'tool': 'update_record',
                'arguments': arguments, 'expect': expect, 'after': copy.deepcopy(state) if expect == 'allow' else 'unchanged'}
        if denial_code:
            case['denial_code'] = denial_code
        if prepare:
            case['prepare'] = prepare
        cases.append(case)

    add('valid-token', 'CTL-01')
    for role in (None, 'invalid', 'expired', 'wrong_audience'):
        add('auth-' + str(role), 'CTL-01', 'deny', credential=role, denial_code='http:401')
    add('allowed-scope', 'CTL-02')
    add('limited-role', 'CTL-02', 'deny', credential='limited', denial_code='scope')
    add('different-record', 'CTL-02', 'deny', record='A-2', denial_code='scope')
    add('other-tenant', 'CTL-02', 'deny', record='B-1', denial_code='scope')
    add('forbidden-field', 'CTL-02', 'deny', field='notes', denial_code='scope')
    add('missing-approval', 'CTL-03', 'deny', field='bank', denial_code='approval')
    action = {'record': 'A-1', 'field': 'bank', 'value': 'approved-bank', 'operation': 'approved-bank'}
    add('substituted-approval', 'CTL-03', 'deny', field='bank', value='different-bank', operation='approved-bank',
        approval={'$binding': 'approval'}, denial_code='approval', prepare={'operation': 'approve', 'arguments': action})
    add('approved-bank', 'CTL-03', field='bank', approval={'$binding': 'approval'})
    add('reused-approval', 'CTL-03', 'deny', field='bank', value='approved-bank', operation='approved-bank',
        approval={'$binding': 'approval'}, denial_code='approval')
    add('first-operation', 'CTL-04')
    add('repeated-operation', 'CTL-04', 'deny', value='first-operation', operation='first-operation', denial_code='replay')
    add('budget-one', 'CTL-05', credential='budget')
    add('budget-two', 'CTL-05', credential='budget')
    add('budget-three', 'CTL-05', 'deny', credential='budget', denial_code='budget')
    add('before-revocation', 'CTL-06', credential='revocable')
    add('after-revocation', 'CTL-06', 'deny', credential='revocable', denial_code='revoked',
        prepare={'operation': 'revoke', 'arguments': {}})
    return {'adapter': 'mcp-scenarios-v1', 'target_id': 'reference-mcp', 'mcp_url': endpoints['mcp_url'],
            'control_url': endpoints['control_url'], 'admin_token_env': 'VERIFY_OBSERVER_TOKEN',
            'credentials': {role: 'VERIFY_CALLER_' + role.upper() for role in endpoints['tokens']},
            'discovery_credential': 'caller', 'cases': cases}
