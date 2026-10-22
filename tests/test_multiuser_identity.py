from tests.test_identity import identity, enroll
from tests.authenticator import Authenticator


def test_bob_enrollment_requires_server_invitation_and_cannot_take_alice(identity):
    alice = Authenticator()
    assert enroll(identity, alice).status_code == 200
    assert identity.post('/enrollment/invite', json={'subject': 'bob'}).status_code == 403
    invite = identity.post('/enrollment/invite', json={'subject': 'bob'}, headers={'x-service-key': 'test-key'})
    assert invite.status_code == 200
    opts = identity.post('/register/options', json={'invitation': invite.json()['invitation']}).json()
    bob = Authenticator()
    assert identity.post('/register/verify', json={'ceremony': opts['ceremony'], 'credential': bob.register(opts['publicKey'])}).status_code == 200
    opts = identity.post('/login/options', json={'subject': 'bob'}).json()
    token = identity.post('/login/verify', json={'ceremony': opts['ceremony'], 'credential': bob.login(opts['publicKey'])}).json()['token']
    assert identity.post('/introspect', json={'token': token}, headers={'x-service-key': 'test-key'}).json()['subject'] == 'bob'
    # An Alice credential cannot authenticate a Bob ceremony.
    opts = identity.post('/login/options', json={'subject': 'bob'}).json()
    assert identity.post('/login/verify', json={'ceremony': opts['ceremony'], 'credential': alice.login(opts['publicKey'])}).status_code == 400
    assert identity.post('/register/options', json={'invitation': invite.json()['invitation']}).status_code == 403


def test_additional_passkey_requires_new_admin_invitation(identity):
    assert enroll(identity, Authenticator()).status_code == 200
    assert identity.post('/register/options', json={}).status_code == 409
    invite = identity.post('/enrollment/invite', json={'subject': 'alice'}, headers={'x-service-key': 'test-key'}).json()
    auth = Authenticator()
    opts = identity.post('/register/options', json={'invitation': invite['invitation']}).json()
    assert identity.post('/register/verify', json={'ceremony': opts['ceremony'], 'credential': auth.register(opts['publicKey'])}).status_code == 200
