"""User-to-resource policy. These synthetic assignments are server-owned.

The six-per-ten-second HR threshold is a teaching policy, not a NIST value.
Authentication assurance and behavioral quarantine are independent gates.
"""
import re
import time

DIRECTORY = {
    'alice': {'role': 'employee', 'employees': ['alice'], 'can_adjust': False},
    'bob': {'role': 'hr', 'employees': ['alice', 'bob'], 'can_adjust': True},
    'carol': {'role': 'employee', 'employees': ['carol'], 'can_adjust': False},
}
HR_LIMIT = 6
WINDOW = 10
STEP_UP_AGE = 60


def evaluate_resource(claims, path, method, state, count):
    def result(reason, allow=False):
        return {'decision': 'ALLOW' if allow else 'DENY', 'reason': reason, 'policy_version': 1}
    match = re.fullmatch(r'/api/(salary|profile)/([a-z][a-z0-9-]{0,63})(/adjust)?', path)
    if not match:
        return result('invalid_resource')
    resource, owner, adjustment = match.groups()
    if method != ('POST' if adjustment else 'GET') or adjustment and resource != 'salary':
        return result('operation_denied')
    user = DIRECTORY.get(claims['sub'])
    if not user or claims['role'] != user['role']:
        return result('directory_assignment_denied')
    if state.get('device_blocked'):
        return result('device_risk_denied')
    if state.get('subject_blocked'):
        return result('subject_risk_denied')
    if state.get('quarantined') or user['role'] == 'hr' and count >= HR_LIMIT:
        return result('behavioral_quarantine')
    if resource+(':write' if adjustment else ':read') not in claims['scope'].split():
        return result('scope_denied')
    if owner not in user['employees']:
        return result('resource_ownership_denied')
    if adjustment:
        if not user['can_adjust']:
            return result('salary_adjustment_role_required')
        if time.time()-claims['auth_time'] > STEP_UP_AGE:
            return result('step_up_required')
    return result('resource_grant_matched', True)
