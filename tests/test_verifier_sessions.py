from types import SimpleNamespace
import httpx


def test_verifier_reuses_session_but_mints_each_jwt():
    from scripts.verify_identity import User
    calls = []
    def agent(path, body, token):
        calls.append((path, token))
        return httpx.Response(200, request=httpx.Request('POST', 'https://localhost'+path),
            json={'session_id': 'owned-session'} if path == '/session' else {'access_token': 'jwt'})
    user = User.__new__(User)
    user.sessions, user.human = {}, 'real-human-token'
    user.operator = SimpleNamespace(agent=agent)
    assert user.token() == user.token() == 'jwt'
    assert calls == [('/session', 'real-human-token'), ('/token/exchange', 'owned-session'),
                     ('/token/exchange', 'owned-session')]


def test_verifier_cleanup_only_revokes_its_own_sessions():
    from scripts.verify_identity import User
    calls = []
    user = User.__new__(User)
    user.sessions = {'salary': 'owned-a', 'profile': 'owned-b'}
    user.operator = SimpleNamespace(control=lambda *args: calls.append(args))
    user.close()
    user.close()
    assert calls == [('pa', '/revoke', 'POST', {'session_id': 'owned-a'}),
                     ('pa', '/revoke', 'POST', {'session_id': 'owned-b'})]
    assert user.sessions == {}


def test_failed_cleanup_cannot_leave_previous_passed_report(tmp_path):
    import json
    import pytest
    from scripts.verify_identity import save_evidence
    path = tmp_path / 'evidence.json'
    path.write_text('{"passed":true}')
    attempted = []
    def failed():
        attempted.append('first')
        raise ConnectionError('unavailable')
    users = [SimpleNamespace(subject='alice', close=failed),
             SimpleNamespace(subject='bob', close=lambda: attempted.append('second'))]
    with pytest.raises(RuntimeError, match='Acceptance cleanup failed'):
        save_evidence({'passed': True}, users, path)
    result = json.loads(path.read_text())
    assert attempted == ['first', 'second']
    assert result['passed'] is False and result['finished_at']
    assert result['cleanup_errors'] == [{'subject': 'alice', 'error': 'ConnectionError'}]
    # Preserve a failure already in flight while still replacing stale evidence.
    save_evidence({'passed': False}, users, path, primary_error=True)


def test_user_cleanup_attempts_all_owned_sessions_even_when_one_fails():
    import pytest
    from scripts.verify_identity import User
    attempted = []
    def control(service, path, method, body):
        attempted.append(body['session_id'])
        if body['session_id'] == 'owned-a':
            raise ConnectionError('unavailable')
    user = User.__new__(User)
    user.sessions = {'salary': 'owned-a', 'profile': 'owned-b'}
    user.operator = SimpleNamespace(control=control)
    with pytest.raises(RuntimeError, match='Test Session cleanup failed'):
        user.close()
    assert attempted == ['owned-a', 'owned-b']
    assert user.sessions == {'salary': 'owned-a'}
