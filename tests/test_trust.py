import pytest
from app.trust import evaluate

def snapshot():
    return {'identity': {'valid': True, 'subject': 'alice'},
            'device': {'managed': True, 'compromised': False, 'os_current': True},
            'context': {'high_risk_ip': False, 'abnormal': False},
            'policy': {'threshold': 60, 'grants': {'alice': ['GET /api/salary', 'GET /api/profile', 'GET /api/stream']}}}

def test_allow_and_least_privilege():
    s = snapshot()
    assert evaluate(s, {'method':'GET','path':'/api/salary'})['decision'] == 'ALLOW'
    assert evaluate(s, {'method':'POST','path':'/api/salary'})['decision'] == 'DENY'

@pytest.mark.parametrize('section,key,risk', [('device','os_current',30),('context','high_risk_ip',70),('context','abnormal',60)])
def test_risk(section,key,risk):
    s = snapshot(); s[section][key] = key != 'os_current'
    r = evaluate(s, {'method':'GET','path':'/api/salary'})
    assert r['risk_score'] == risk
    assert r['trust_score'] == 100-risk
    assert r['decision'] == ('ALLOW' if risk == 30 else 'DENY')

@pytest.mark.parametrize('section,key,value', [('identity','valid',False),('device','managed',False),('device','compromised',True)])
def test_hard_gate_and_revoke(section,key,value):
    s = snapshot(); s[section][key] = value
    assert evaluate(s, {'method':'GET','path':'/api/salary'})['decision'] == 'DENY'
    assert evaluate(s, {'method':'GET','path':'/api/salary'}, active=True)['decision'] == 'REVOKE'

def test_dynamic_policy():
    s = snapshot(); s['policy']['grants']['alice'] = []
    assert evaluate(s, {'method':'GET','path':'/api/salary'}, active=True)['decision'] == 'REVOKE'
