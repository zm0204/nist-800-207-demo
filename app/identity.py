"""Passwordless WebAuthn RP with a single, pre-provisioned demo subject."""
import hashlib
import json
import os
import secrets
import time
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from webauthn import (generate_registration_options, generate_authentication_options,
                      verify_registration_response, verify_authentication_response)
from webauthn.helpers import options_to_json
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, UserVerificationRequirement,
                                     PublicKeyCredentialDescriptor, ResidentKeyRequirement,
                                     AuthenticatorTransport, PublicKeyCredentialHint)
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
        if 'auth_time' not in {r['name'] for r in c.execute('PRAGMA table_info(token)')}:
            c.execute('ALTER TABLE token ADD COLUMN auth_time INTEGER NOT NULL DEFAULT 0')
        for table in ('credential', 'challenge', 'token'):
            if 'subject' not in {r['name'] for r in c.execute('PRAGMA table_info('+table+')')}:
                c.execute('ALTER TABLE '+table+" ADD COLUMN subject TEXT NOT NULL DEFAULT 'alice'")
        c.execute('CREATE TABLE IF NOT EXISTS invitation (hash TEXT PRIMARY KEY, subject TEXT, expires REAL)')
        if 'allow_add' not in {r['name'] for r in c.execute('PRAGMA table_info(challenge)')}:
            c.execute('ALTER TABLE challenge ADD COLUMN allow_add INTEGER NOT NULL DEFAULT 0')
        if 'transports' not in {r['name'] for r in c.execute('PRAGMA table_info(credential)')}:
            c.execute("ALTER TABLE credential ADD COLUMN transports TEXT NOT NULL DEFAULT '[]'")
initialize()


def descriptor(row):
    from webauthn import base64url_to_bytes
    # Browser routing metadata only; never identity/authorization evidence.
    transports = [AuthenticatorTransport(t) for t in json.loads(row['transports'])
                  if t in {v.value for v in AuthenticatorTransport}]
    return PublicKeyCredentialDescriptor(id=base64url_to_bytes(row['id']), transports=transports or None)

def save_challenge(kind,options,subject='alice',allow_add=False):
    ceremony=secrets.token_urlsafe(32)
    with db('identity') as c:
        c.execute('DELETE FROM challenge WHERE expires<?',(time.time(),))
        c.execute('INSERT INTO challenge(id,kind,challenge,expires,subject,allow_add) VALUES (?,?,?,?,?,?)',
                  (ceremony,kind,options.challenge,time.time()+120,subject,int(allow_add)))
    return {'ceremony':ceremony,'publicKey':json.loads(options_to_json(options))}

def consume(ceremony,kind,with_subject=False):
    with db('identity') as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT * FROM challenge WHERE id=?',(ceremony,)).fetchone()
        c.execute('DELETE FROM challenge WHERE id=?',(ceremony,))
    if not row or row['kind']!=kind or row['expires']<time.time():
        raise HTTPException(400,'invalid_expired_or_replayed_challenge')
    return (row['challenge'], row['subject'], bool(row['allow_add'])) if with_subject else row['challenge']

class Verification(BaseModel):
    ceremony:str
    credential:dict

class Enrollment(BaseModel):
    model_config = ConfigDict(extra='forbid')
    invitation: str | None = None

class Subject(BaseModel):
    model_config = ConfigDict(extra='forbid')
    subject: str = 'alice'

@app.post('/enrollment/invite', dependencies=[Depends(protected)])
def invite(body: Subject):
    from app.hr_policy import DIRECTORY
    if body.subject not in DIRECTORY:
        raise HTTPException(400, 'unknown_directory_subject')
    value = secrets.token_urlsafe(32)
    with db('identity') as c:
        c.execute('INSERT INTO invitation VALUES (?,?,?)',
                  (hashlib.sha256(value.encode()).hexdigest(), body.subject, time.time()+300))
    return {'invitation': value, 'subject': body.subject}

@app.get('/health')
def health(): return {'ok':True}

@app.post('/register/options')
def register_options(body: Enrollment = Enrollment()):
    subject = 'alice'
    with db('identity') as c:
        c.execute('BEGIN IMMEDIATE')
        if body.invitation:
            hashed = hashlib.sha256(body.invitation.encode()).hexdigest()
            row = c.execute('SELECT * FROM invitation WHERE hash=?', (hashed,)).fetchone()
            if not row or row['expires'] <= time.time():
                raise HTTPException(403, 'valid_enrollment_invitation_required')
            subject = row['subject']
            c.execute('DELETE FROM invitation WHERE hash=?', (hashed,))
        if not body.invitation and c.execute('SELECT COUNT(*) FROM credential WHERE subject=?', (subject,)).fetchone()[0]:
            raise HTTPException(409,'alice already enrolled; use an administrator invitation to add a passkey')
        existing = c.execute('SELECT id,transports FROM credential WHERE subject=?', (subject,)).fetchall()
    namespace = os.environ.get('PASSKEY_ACCOUNT_NAMESPACE', '')
    # Separate localhost applications must not replace one another's resident
    # credential in a password manager by reusing the same RP + user handle.
    handle = hashlib.sha256((namespace+'\0'+subject).encode()).digest() if namespace else subject.encode()
    return save_challenge('register',generate_registration_options(
        rp_id=RP,rp_name='員工服務' if namespace else '800-207 Demo',user_id=handle,
        user_name=subject+'@'+namespace if namespace else subject,
        exclude_credentials=[descriptor(row) for row in existing],
        hints=[PublicKeyCredentialHint.CLIENT_DEVICE],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED, require_resident_key=True,
            user_verification=UserVerificationRequirement.REQUIRED)), subject, bool(body.invitation))

@app.post('/register/verify')
def register_verify(body:Verification):
    challenge,subject,allow_add=consume(body.ceremony,'register',True)
    try:
        v=verify_registration_response(credential=body.credential,expected_challenge=challenge,
            expected_rp_id=RP,expected_origin=ORIGIN,require_user_verification=True)
    except Exception:
        raise HTTPException(400,'registration_verification_failed')
    with db('identity') as c:
        c.execute('BEGIN IMMEDIATE')
        if not allow_add and c.execute('SELECT COUNT(*) FROM credential WHERE subject=?',(subject,)).fetchone()[0]:
            raise HTTPException(409,'subject already enrolled')
        transports = body.credential.get('response', {}).get('transports') or []
        c.execute('INSERT INTO credential(id,public_key,counter,subject,transports) VALUES (?,?,?,?,?)',
                  (body.credential['id'],v.credential_public_key,v.sign_count,subject,json.dumps(transports)))
    return {'subject':subject,'registered':True}

@app.post('/login/options')
def login_options(body: Subject = Subject()):
    with db('identity') as c: rows=c.execute('SELECT id,transports FROM credential WHERE subject=?',(body.subject,)).fetchall()
    if not rows: raise HTTPException(409,'register a passkey first')
    return save_challenge('login',generate_authentication_options(rp_id=RP,
        user_verification=UserVerificationRequirement.REQUIRED,
        allow_credentials=[descriptor(row) for row in rows]), body.subject)

@app.post('/login/verify')
def login_verify(body:Verification):
    challenge,subject,_=consume(body.ceremony,'login',True)
    with db('identity') as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT * FROM credential WHERE id=?',(body.credential.get('id',''),)).fetchone()
        if not row or row['subject'] != subject: raise HTTPException(400,'unknown_credential')
        try:
            v=verify_authentication_response(credential=body.credential,expected_challenge=challenge,
                expected_rp_id=RP,expected_origin=ORIGIN,credential_public_key=row['public_key'],
                credential_current_sign_count=row['counter'],require_user_verification=True)
        except Exception:
            raise HTTPException(400,'authentication_verification_failed')
        c.execute('UPDATE credential SET counter=? WHERE id=?',(v.new_sign_count,row['id']))
        token=secrets.token_urlsafe(48); expires=time.time()+TOKEN_TTL
        c.execute('INSERT INTO token(hash,expires,auth_time,subject) VALUES (?,?,?,?)',
                  (hashlib.sha256(token.encode()).hexdigest(),expires,int(time.time()),subject))
        c.execute('DELETE FROM token WHERE expires<?',(time.time(),))
    return {'subject':subject,'token':token,'expires':expires}

class Token(BaseModel): token:str

@app.post('/introspect',dependencies=[Depends(protected)])
def introspect(body:Token):
    with db('identity') as c:
        row=c.execute('SELECT expires,auth_time,subject FROM token WHERE hash=?',(hashlib.sha256(body.token.encode()).hexdigest(),)).fetchone()
    valid=bool(row and row['expires']>time.time())
    return {'valid':valid,'subject':row['subject'] if valid else None,'expires':row['expires'] if row else 0,
            'auth_time':row['auth_time'] if row else 0}
