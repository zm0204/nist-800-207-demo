"""Demo-specific trust algorithm; the numeric weights are not prescribed by NIST."""
def evaluate(snapshot: dict, request: dict, active: bool = False) -> dict:
    identity, device, context, policy = (snapshot[k] for k in ('identity','device','context','policy'))
    reasons = []
    if not identity.get('valid'): reasons.append('human_identity_invalid_or_expired')
    if not device.get('managed'): reasons.append('unmanaged_device')
    if device.get('compromised'): reasons.append('device_compromised')
    scope = f"{request['method']} {request['path']}"
    if scope not in policy.get('grants', {}).get(identity.get('subject'), []):
        reasons.append('least_privilege')
    risk = 0
    for flag, weight, label in [(not device.get('os_current'),30,'outdated_os'),
                                (context.get('high_risk_ip'),70,'high_risk_ip'),
                                (context.get('abnormal'),60,'abnormal_behavior')]:
        if flag: risk += weight; reasons.append(label)
    risk = min(risk, 100)
    hard = any(x in reasons for x in ['human_identity_invalid_or_expired','unmanaged_device','device_compromised','least_privilege'])
    denied = hard or 100-risk < policy['threshold']
    return {'decision': ('REVOKE' if active else 'DENY') if denied else 'ALLOW',
            'risk_score':risk, 'trust_score':100-risk, 'threshold':policy['threshold'],
            'reasons':reasons or ['required_conditions_met'], 'request':request,
            'subject':identity.get('subject'), 'device':device, 'context':context,
            'policy_version':policy.get('version',1)}
