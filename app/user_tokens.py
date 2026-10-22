"""RS256 user credentials. Verifiers need only a configured, local public JWKS.

Key generation is an explicit operator action. No request can create keys or
choose a verification URL. During rotation retain old public keys for the maximum
token lifetime before removing them from the published JWKS.
"""
import hashlib
import json
import os
import re
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = 'https://zta.example/identity'
AUDIENCE = 'zta-hr'
MAX_TTL = 120
REQUIRED = ['iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'scope', 'role',
            'device_id', 'auth_time', 'sid']


def signing_key():
    key = serialization.load_pem_private_key(
        Path(os.environ['USER_SIGNING_KEY_FILE']).read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise ValueError('RSA key of at least 2048 bits required')
    return key


def public_jwks():
    key = signing_key().public_key()
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key))
    jwk.update(kid=hashlib.sha256(der).hexdigest()[:24], alg='RS256', use='sig')
    return {'keys': [jwk]}


def issue(claims):
    return jwt.encode(claims, signing_key(), algorithm='RS256',
                      headers={'kid': public_jwks()['keys'][0]['kid'], 'typ': 'JWT'})


def verify(token):
    try:
        if not isinstance(token, str) or len(token) > 8192:
            raise ValueError('invalid token size')
        header = jwt.get_unverified_header(token)
        if header.get('alg') != 'RS256' or header.get('typ') != 'JWT' or header.get('crit'):
            raise ValueError('unsupported token header')
        jwks = json.loads(Path(os.environ['USER_JWKS_FILE']).read_text(encoding='utf-8'))
        matches = [k for k in jwks['keys'] if k.get('kid') == header.get('kid')
                   and k.get('kty') == 'RSA' and k.get('alg') == 'RS256' and k.get('use') == 'sig']
        if len(matches) != 1 or set(matches[0]) & {'d', 'p', 'q'}:
            raise ValueError('untrusted key')
        key = jwt.PyJWK.from_dict(matches[0], algorithm='RS256').key
        claims = jwt.decode(token, key, algorithms=['RS256'],
            issuer=os.environ.get('USER_TOKEN_ISSUER', ISSUER),
            audience=AUDIENCE, options={'require': REQUIRED, 'strict_aud': True})
        for field in ('iat', 'exp', 'auth_time'):
            if type(claims[field]) is not int:
                raise ValueError('integer timestamp required')
        if not 0 < claims['exp'] - claims['iat'] <= MAX_TTL or claims['auth_time'] > claims['iat']:
            raise ValueError('invalid token lifetime')
        for field in ('sub', 'jti', 'scope', 'role', 'device_id', 'sid'):
            if not isinstance(claims[field], str) or not claims[field] or len(claims[field]) > 512:
                raise ValueError('invalid claim type')
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', claims['sub']):
            raise ValueError('invalid subject')
        return claims
    except (jwt.PyJWTError, OSError, KeyError, TypeError, ValueError) as exc:
        raise ValueError('invalid_user_token') from exc


def bearer(request):
    values = request.headers.getlist('authorization')
    if len(values) != 1 or not values[0].startswith('Bearer '):
        raise ValueError('user_bearer_required')
    return values[0][7:]
