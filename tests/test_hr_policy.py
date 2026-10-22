import pytest
from tests.test_user_tokens import claims


def evaluate(payload=None, owner='alice', resource='salary', method='GET', state=None, count=0):
    from app.hr_policy import evaluate_resource
    return evaluate_resource(payload or claims(), '/api/'+resource+'/'+owner,
                             method, state or {}, count)


def test_ownership_hr_scope_and_server_directory():
    assert evaluate()['decision'] == 'ALLOW'
    assert evaluate(owner='bob')['reason'] == 'resource_ownership_denied'
    bob = {**claims(), 'sub': 'bob', 'role': 'hr'}
    assert evaluate(bob)['decision'] == 'ALLOW'
    assert evaluate(bob, owner='carol')['decision'] == 'DENY'
    assert evaluate({**claims(), 'role': 'hr'}, owner='bob')['decision'] == 'DENY'
    assert evaluate({**bob, 'scope': 'profile:read'})['decision'] == 'DENY'


def test_risk_and_behavioral_quarantine_are_distinct_from_assurance():
    bob = {**claims(), 'sub': 'bob', 'role': 'hr'}
    assert evaluate(bob, state={'device_blocked': True})['reason'] == 'device_risk_denied'
    assert evaluate(bob, count=6)['reason'] == 'behavioral_quarantine'
    assert evaluate(bob, state={'quarantined': True})['reason'] == 'behavioral_quarantine'
    write = {**bob, 'scope': 'salary:write'}
    from app.hr_policy import evaluate_resource
    assert evaluate_resource(write, '/api/salary/alice/adjust', 'POST', {}, 0)['decision'] == 'ALLOW'
    assert evaluate_resource({**write, 'auth_time': 1}, '/api/salary/alice/adjust', 'POST', {}, 0)['reason'] == 'step_up_required'
    assert evaluate_resource(write, '/api/salary/alice/adjust', 'POST', {'quarantined': True}, 0)['reason'] == 'behavioral_quarantine'


@pytest.mark.parametrize('path', ['/api/salary', '//api/salary/alice', '/api/salary/%61lice',
                                '/api/salary/alice/', '/api/salary/alice?owner=bob'])
def test_ambiguous_resources_deny(path):
    from app.hr_policy import evaluate_resource
    assert evaluate_resource(claims(), path, 'GET', {}, 0)['decision'] == 'DENY'
