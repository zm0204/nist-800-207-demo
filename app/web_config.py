"""Explicit WebAuthn origin; never derive identity settings from request headers."""
import os
import re
from urllib.parse import urlsplit

def web_config():
    origin=os.environ.get('WEBAUTHN_ORIGIN','http://localhost:8080')
    rp=os.environ.get('RP_ID','localhost')
    parsed=urlsplit(origin)
    if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise ValueError('WEBAUTHN_ORIGIN must be an origin without credentials or path')
    if not parsed.hostname or parsed.hostname!=rp or not re.fullmatch(r'[a-z0-9.-]+',rp):
        raise ValueError('RP_ID must exactly match the configured origin hostname')
    if parsed.scheme!='https' and not (rp=='localhost' and parsed.scheme=='http'):
        raise ValueError('Remote WebAuthn requires HTTPS')
    return {'origin':origin,'rp':rp,'host':parsed.hostname,
            'stream_enabled':os.environ.get('STREAM_ENABLED','true').lower()=='true'}
