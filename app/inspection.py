"""Evidence classification: absence is never proof that a component was skipped."""


def inspect_attempt(attempt_id, events, proxy_logs, executions):
    events = [e for e in events if e.get('attempt_id') == attempt_id]
    logs = [e for e in proxy_logs if e.get('attempt_id') == attempt_id]
    stages = []
    for name in ('device-gateway', 'frontend', 'salary', 'profile'):
        observed = [e for e in logs if e.get('component') == name]
        state = 'NOT_OBSERVED'
        if observed:
            details = [e.get('response_code_details', '') for e in observed]
            if any('denied' in d or 'jwt' in d or 'ext_authz_error' in d for d in details):
                state = 'VERIFIED_BLOCK'
            elif any(e.get('response_code_details') == 'via_upstream' for e in observed):
                state = 'VERIFIED_PASS'
        stages.append({'component': name, 'status': state, 'evidence': observed})
    decisions = [e for e in events if e.get('kind') == 'resource_pe_decision']
    pe_status = ('VERIFIED_BLOCK' if any(e.get('decision') == 'DENY' for e in decisions) else
                 'VERIFIED_PASS' if decisions and all(e.get('decision') == 'ALLOW' for e in decisions) else 'NOT_OBSERVED')
    stages.append({'component': 'external_pe', 'status': pe_status, 'evidence': decisions})
    resource_status = 'NOT_OBSERVED'
    if executions:
        resource_status = 'VERIFIED_PASS'
    elif executions == [] and (pe_status == 'VERIFIED_BLOCK' or any(s['status'] == 'VERIFIED_BLOCK' for s in stages)):
        resource_status = 'NOT_REACHED'
    stages.append({'component': 'resource', 'status': resource_status, 'evidence': executions})
    return {'attempt_id': attempt_id, 'stages': stages,
            'execution_query_observed': executions is not None, 'executions': executions,
            'note': 'IDs correlate observations; they are not identity or authorization evidence.'}
