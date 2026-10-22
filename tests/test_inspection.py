def test_missing_logs_remain_unknown_even_when_http_is_denied():
    from app.inspection import inspect_attempt
    result = inspect_attempt('attempt', [], [], None)
    assert all(s['status'] == 'NOT_OBSERVED' for s in result['stages'])


def test_only_matching_producer_evidence_establishes_decisions():
    from app.inspection import inspect_attempt
    result = inspect_attempt('a', [{'attempt_id': 'other', 'decision': 'ALLOW'},
        {'attempt_id': 'a', 'kind': 'resource_pe_decision', 'decision': 'DENY', 'reason': 'ownership'}],
        [{'attempt_id': 'a', 'component': 'salary', 'response_code_details': 'ext_authz_denied', 'response_code': '403'}], [])
    stages = {s['component']: s for s in result['stages']}
    assert stages['external_pe']['status'] == 'VERIFIED_BLOCK'
    assert stages['resource']['status'] == 'NOT_REACHED'
    assert stages['frontend']['status'] == 'NOT_OBSERVED'


def test_resource_execution_is_never_inferred_from_allow_decision():
    from app.inspection import inspect_attempt
    result = inspect_attempt('a', [{'attempt_id': 'a', 'kind': 'resource_pe_decision', 'decision': 'ALLOW'}], [], None)
    assert result['stages'][-1]['status'] == 'NOT_OBSERVED'
