"""Passwordless WebAuthn RP with a single, pre-provisioned demo subject."""
import hashlib
import json
import os
import secrets
import time
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from webauthn import (generate_registration_options, generate_authentication_options,
                      verify_registration_response, verify_authentication_response)
from webauthn.helpers import options_to_json
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, UserVerificationRequirement,
                                     PublicKeyCredentialDescriptor)
from app.common import db, protected

app=FastAPI(title='Passwordless Identity / WebAuthn')
RP=os.environ.get('RP_ID','localhost')
ORIGIN=os.environ.get('WEBAUTHN_ORIGIN','http://localhost:8080')
TOKEN_TTL=int(os.environ.get('TOKEN_TTL','900'))

def initialize():
    with db('identity') as c:
        c.execute('CREATE TABLE IF NOT EXISTS credential (id TEXT PRIMARY KEY, public_key BLOB, counter INTEGER)')
        c.execute('CREATE TABLE IF NOT EXISTS challenge (id TEXT PRIMARY KEY, kind TEXT, challenge BLOB, expires REAL)')
        c.execute('CREATE TABLE IF NOT EXISTS token (hash TEXT PRIMARY KEY, expires REAL)')
initialize()

def save_challenge(kind,options):
    ceremony=secrets.token_urlsafe(32)
    with db('identity') as c:
        c.execute('DELETE FROM challenge WHERE expires<?',(time.time(),))
        c.execute('INSERT INTO challenge VALUES (?,?,?,?)',(ceremony,kind,options.challenge,time.time()+120))
    return {'ceremony':ceremony,'publicKey':json.loads(options_to_json(options))}

def consume(ceremony,kind):
    with db('identity') as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT * FROM challenge WHERE id=?',(ceremony,)).fetchone()
        c.execute('DELETE FROM challenge WHERE id=?',(ceremony,))
    if not row or row['kind']!=kind or row['expires']<time.time():
        raise HTTPException(400,'invalid_expired_or_replayed_challenge')
    return row['challenge']

class Verification(BaseModel):
    ceremony:str
    credential:dict

@app.get('/health')
def health(): return {'ok':True}

@app.post('/register/options')
def register_options():
    with db('identity') as c:
        if c.execute('SELECT COUNT(*) FROM credential').fetchone()[0]:
            raise HTTPException(409,'alice already enrolled; use login or explicitly reset demo storage')
    return save_challenge('register',generate_registration_options(
        rp_id=RP,rp_name='800-207 Demo',user_id=b'alice',user_name='alice',
        authenticator_selection=AuthenticatorSelectionCriteria(user_verification=UserVerificationRequirement.REQUIRED)))

@app.post('/register/verify')
def register_verify(body:Verification):
    challenge=consume(body.ceremony,'register')
    try:
        v=verify_registration_response(credential=body.credential,expected_challenge=challenge,
            expected_rp_id=RP,expected_origin=ORIGIN,require_user_verification=True)
    except Exception:
        raise HTTPException(400,'registration_verification_failed')
    with db('identity') as c:
        c.execute('BEGIN IMMEDIATE')
        if c.execute('SELECT COUNT(*) FROM credential').fetchone()[0]:
            raise HTTPException(409,'subject already enrolled')
        c.execute('INSERT INTO credential VALUES (?,?,?)',(body.credential['id'],v.credential_public_key,v.sign_count))
    return {'subject':'alice','registered':True}

@app.post('/login/options')
def login_options():
    from webauthn import base64url_to_bytes
    with db('identity') as c: rows=c.execute('SELECT id FROM credential').fetchall()
    if not rows: raise HTTPException(409,'register a passkey first')
    return save_challenge('login',generate_authentication_options(rp_id=RP,
        user_verification=UserVerificationRequirement.REQUIRED,
        allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(r['id'])) for r in rows]))

@app.post('/login/verify')
def login_verify(body:Verification):
    challenge=consume(body.ceremony,'login')
    with db('identity') as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT * FROM credential WHERE id=?',(body.credential.get('id',''),)).fetchone()
        if not row: raise HTTPException(400,'unknown_credential')
        try:
            v=verify_authentication_response(credential=body.credential,expected_challenge=challenge,
                expected_rp_id=RP,expected_origin=ORIGIN,credential_public_key=row['public_key'],
                credential_current_sign_count=row['counter'],require_user_verification=True)
        except Exception:
            raise HTTPException(400,'authentication_verification_failed')
        c.execute('UPDATE credential SET counter=? WHERE id=?',(v.new_sign_count,row['id']))
        token=secrets.token_urlsafe(48); expires=time.time()+TOKEN_TTL
        c.execute('INSERT INTO token VALUES (?,?)',(hashlib.sha256(token.encode()).hexdigest(),expires))
        c.execute('DELETE FROM token WHERE expires<?',(time.time(),))
    return {'subject':'alice','token':token,'expires':expires}

class Token(BaseModel): token:str

@app.post('/introspect',dependencies=[Depends(protected)])
def introspect(body:Token):
    with db('identity') as c:
        row=c.execute('SELECT expires FROM token WHERE hash=?',(hashlib.sha256(body.token.encode()).hexdigest(),)).fetchone()
    valid=bool(row and row['expires']>time.time())
    return {'valid':valid,'subject':'alice' if valid else None,'expires':row['expires'] if row else 0}
