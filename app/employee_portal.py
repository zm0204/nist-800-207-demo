"""Employee-only BFF and cache-only, secret-free request observer."""
from datetime import datetime, timezone
import re
import secrets
import threading
import time
from typing import Literal
from uuid import uuid4

import httpx
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field


class Access(BaseModel):
    model_config = ConfigDict(extra='forbid')
    resource: Literal['salary', 'profile']
    owner: Literal['alice', 'bob', 'carol']


class Subject(BaseModel):
    model_config = ConfigDict(extra='forbid')
    subject: Literal['alice', 'bob']


class Verification(BaseModel):
    model_config = ConfigDict(extra='forbid')
    ceremony: str
    credential: dict


class Empty(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Adjustment(BaseModel):
    model_config = ConfigDict(extra='forbid')
    owner: Literal['alice', 'bob', 'carol']
    amount: int = Field(strict=True, ge=0, le=10000000)


def public_attempt(result, subject):
    """Allowlist producer evidence; never serialize tokens, sessions or raw claims."""
    stages = []
    for stage in result.get('stages', []):
        safe = []
        for item in stage.get('evidence') or []:
            safe.append({key: item[key] for key in (
                'component', 'attempt_id', 'request_id', 'decision', 'reason',
                'path', 'method', 'response_code', 'response_code_details',
                'downstream_peer', 'upstream_peer', 'downstream_tls', 'upstream_tls',
                'status', 'source', 'resource', 'owner', 'subject',
                'destination', 'principal',
            ) if key in item})
        stages.append({'component': stage['component'], 'status': stage['status'], 'evidence': safe})
    # Native policies run after CUSTOM. Never turn a PE denial into native success.
    receiver = next((s for s in stages if s['component'] == result['request']['resource']), {})
    logs = receiver.get('evidence', [])
    native = 'NOT_OBSERVED'
    if any('rbac_access_denied' in e.get('response_code_details', '') for e in logs):
        native = 'VERIFIED_BLOCK'
    elif any(e.get('response_code_details') == 'via_upstream' for e in logs):
        native = 'VERIFIED_PASS'
    stages += [
        {'component': 'native_deny', 'status': 'VERIFIED_PASS' if native == 'VERIFIED_PASS' else 'NOT_OBSERVED', 'evidence': logs if native == 'VERIFIED_PASS' else []},
        {'component': 'native_allow', 'status': native, 'evidence': logs if native != 'NOT_OBSERVED' else []},
    ]
    # Envoy's rbac_access_denied cannot identify DENY-match vs no-ALLOW-match.
    if native == 'VERIFIED_BLOCK':
        stages[-1]['component'] = 'native_policy'
    blocked = next((s for s in stages if s['status'] == 'VERIFIED_BLOCK' and s['component'] in
                    ('identity', 'pa_session', 'token_exchange', 'external_pe', 'native_policy')), None)
    if not blocked:
        blocked = next((s for s in stages if s['status'] == 'VERIFIED_BLOCK'), None)
    reason = result.get('reason')
    if not reason and blocked:
        reason = next((e.get('reason') or e.get('response_code_details') for e in blocked['evidence']
                       if e.get('reason') or e.get('response_code_details')), None)
    value = {'attempt_id': result['attempt_id'], 'request_id': result.get('request_id'),
        'subject': subject, 'request': {key: result['request'][key] for key in ('resource', 'owner', 'method', 'attack') if key in result['request']}, 'stages': stages,
        'responses': result.get('responses', []), 'observed_at': result.get('observed_at'),
        'execution_query_observed': result.get('execution_query_observed', False),
        'execution_count': len(result['executions']) if result.get('executions') is not None else None,
        'denial_point': result.get('denial_point') or (blocked['component'] if blocked else None),
        'reason': reason}
    if result.get('origin') == 'inspector' and result.get('caller'):
        value.update(origin='inspector', caller={key: result['caller'][key]
                     for key in ('name', 'service_account', 'principal')})
    return value


def inspector_identity(result):
    """Only PE's signature-verified claims and transport principal classify an attack.

    This consumes server-collected evidence, never request body claims or decoded JWTs.
    Correlation IDs alone do not establish a subject or workload identity.
    """
    request = result.get('request', {})
    if request.get('attack') != 'intruder' or request.get('resource') not in ('salary', 'profile'):
        return None
    path = '/api/'+request['resource']+'/'+request.get('owner', '')
    if request.get('method') == 'POST':
        path += '/adjust'
    audits = [e for s in result.get('stages', []) if s['component'] == 'external_pe'
              for e in s.get('evidence') or []
              if e.get('kind') == 'resource_pe_decision' and e.get('attempt_id') == result.get('attempt_id')
              and e.get('path') == path and e.get('method') == request.get('method')
              and e.get('decision') in ('ALLOW', 'DENY')]
    if not audits:
        return None
    subjects = {e.get('claims', {}).get('sub') for e in audits}
    sources = {e.get('source') for e in audits}
    if len(subjects) != 1 or not subjects <= {'alice', 'bob'} or len(sources) != 1:
        return None
    principal = next(iter(sources))
    if not isinstance(principal, str) or not re.fullmatch(r'spiffe://cluster\.local/ns/[a-z0-9-]+/sa/intruder', principal):
        return None
    destination = principal.rsplit('/', 1)[0]+'/'+request['resource']
    if any(e.get('destination') != destination for e in audits):
        return None
    return next(iter(subjects)), {'name': 'intruder', 'service_account': 'intruder', 'principal': principal}


def attach_portal(app, operator, submit, get_job):
    sessions, pending, attempts = {}, {}, {}
    latest = {'alice': None, 'bob': None}
    lock = threading.RLock()
    public_csrf = secrets.token_urlsafe(32)  # CSRF only, grants no employee/admin identity.

    def cache(safe):
        with lock:
            attempts[safe['attempt_id']] = safe
            latest[safe['subject']] = safe
            while len(attempts) > 90:
                oldest = next(iter(attempts))
                if any(v and v['attempt_id'] == oldest for v in latest.values()):
                    attempts[oldest] = attempts.pop(oldest)
                else:
                    attempts.pop(oldest)
        return safe

    def publish_inspector(result):
        identity = inspector_identity(result)
        if identity is None:
            return
        subject, caller = identity
        enriched = {**result, 'origin': 'inspector', 'caller': caller,
            'stages': [*result['stages'],
                {'component': 'jwt_identity', 'status': 'VERIFIED_PASS', 'evidence': [
                    {'source': 'PE verified JWT claims', 'subject': subject}]},
                {'component': 'caller_workload', 'status': 'VERIFIED_PASS', 'evidence': [
                    {'source': 'PE audit / Envoy authenticated source principal', 'principal': caller['principal']}]}]}
        safe = public_attempt(enriched, subject)
        safe['responses'] = [{key: r[key] for key in ('status', 'error') if key in r} for r in safe['responses']]
        cache(safe)

    def current(request, required=True):
        sid = request.cookies.get('employee_session', '')
        with lock:
            session = sessions.get(sid)
            if session and session['expires'] <= time.time():
                sessions.pop(sid, None)
                session = None
        if required and not session:
            raise HTTPException(401, 'passkey_login_required')
        return sid, session

    def csrf(request, session=None):
        expected = session['csrf'] if session else public_csrf
        if not secrets.compare_digest(request.headers.get('x-portal-csrf', ''), expected):
            raise HTTPException(403, 'portal_csrf_required')

    def identity(operation, body):
        try:
            return operator.identity(operation, body)
        except httpx.HTTPError:
            raise HTTPException(503, 'identity_connection_failed')

    @app.get('/api/portal/session')
    def session(request: Request):
        _, value = current(request, False)
        return {'subject': value['subject'] if value else None, 'csrf': value['csrf'] if value else public_csrf}

    @app.post('/api/portal/login/options')
    def options(body: Subject, request: Request):
        _, old = current(request, False)
        csrf(request, old)
        r = identity('login/options', body.model_dump())
        data = r.json()
        response = JSONResponse(data, r.status_code)
        if r.status_code == 200:
            nonce = secrets.token_urlsafe(32)
            with lock:
                for key in list(pending):
                    if pending[key]['expires'] < time.time():
                        pending.pop(key)
                if len(pending) >= 100:
                    raise HTTPException(429, 'too_many_login_attempts')
                pending[nonce] = {'ceremony': data['ceremony'], 'subject': body.subject, 'expires': time.time()+120}
            response.set_cookie('employee_login', nonce, httponly=True, samesite='strict', max_age=120)
        return response

    @app.post('/api/portal/login/verify')
    def verify(body: Verification, request: Request):
        old_sid, old = current(request, False)
        csrf(request, old)
        with lock:
            expected = pending.pop(request.cookies.get('employee_login', ''), None)
        if not expected or expected['expires'] < time.time() or expected['ceremony'] != body.ceremony:
            raise HTTPException(400, 'login_ceremony_required')
        r = identity('login/verify', body.model_dump())
        if r.status_code != 200:
            return JSONResponse(r.json(), r.status_code)
        data = r.json()
        proof = operator.control('identity', '/introspect', 'POST', {'token': data['token']})
        if not proof.get('valid') or proof.get('subject') != expected['subject']:
            raise HTTPException(401, 'verified_subject_required')
        sid, token = secrets.token_urlsafe(40), secrets.token_urlsafe(32)
        with lock:
            for key in list(sessions):
                if sessions[key]['expires'] <= time.time():
                    sessions.pop(key)
            if len(sessions) >= 100:
                raise HTTPException(429, 'too_many_sessions')
            sessions.pop(old_sid, None)
            sessions[sid] = {'subject': proof['subject'], 'human': data['token'],
                'expires': proof['expires'], 'csrf': token, 'pa': {}}
        response = JSONResponse({'subject': proof['subject'], 'csrf': token})
        response.set_cookie('employee_session', sid, httponly=True, samesite='strict', max_age=max(1, int(proof['expires']-time.time())))
        response.delete_cookie('employee_login')
        return response

    @app.post('/api/portal/logout')
    def logout(request: Request):
        sid, value = current(request, False)
        if value:
            csrf(request, value)
        with lock:
            sessions.pop(sid, None)
        response = JSONResponse({'ok': True})
        response.delete_cookie('employee_session')
        return response

    @app.post('/api/portal/step-up/options')
    def step_up_options(body: Empty, request: Request):
        sid, value = current(request)
        csrf(request, value)
        r = identity('login/options', {'subject': value['subject']})
        response = JSONResponse(r.json(), r.status_code)
        if r.status_code == 200:
            nonce = secrets.token_urlsafe(32)
            with lock:
                for key in list(pending):
                    if pending[key]['expires'] < time.time():
                        pending.pop(key)
                if len(pending) >= 100:
                    raise HTTPException(429, 'too_many_login_attempts')
                pending[nonce] = {'ceremony': r.json()['ceremony'], 'sid': sid,
                                  'expires': time.time()+120, 'purpose': 'step-up'}
            response.set_cookie('employee_step_up', nonce, httponly=True, samesite='strict', max_age=120)
        return response

    @app.post('/api/portal/step-up/verify')
    def step_up_verify(body: Verification, request: Request):
        sid, value = current(request)
        csrf(request, value)
        with lock:
            expected = pending.pop(request.cookies.get('employee_step_up', ''), None)
        if not expected or expected.get('sid') != sid or expected.get('purpose') != 'step-up' or expected['expires'] < time.time() or expected['ceremony'] != body.ceremony:
            raise HTTPException(400, 'step_up_ceremony_required')
        r = identity('login/verify', body.model_dump())
        if r.status_code != 200:
            return JSONResponse(r.json(), r.status_code)
        proof = operator.control('identity', '/introspect', 'POST', {'token': r.json()['token']})
        if not proof.get('valid') or proof.get('subject') != value['subject']:
            raise HTTPException(401, 'verified_subject_required')
        with lock:
            value['step_up'] = r.json()['token']
        response = JSONResponse({'verified': True})
        response.delete_cookie('employee_step_up')
        return response

    def execute(value, body, attempt, request_id, *, operation='read', amount=0):
        from app.inspection import inspect_attempt
        from scripts.security_inspector import Experiment
        phase = 'identity'
        preliminary = []
        result = None
        try:
            proof = operator.control('identity', '/introspect', 'POST', {'token': value['human']})
            if not proof.get('valid') or proof.get('subject') != value['subject']:
                raise HTTPException(401, 'identity_expired')
            preliminary.append({'component': 'identity', 'status': 'VERIFIED_PASS', 'evidence': [{'source': 'Identity introspection after verified WebAuthn', 'subject': proof['subject']}]})
            phase = 'pa_session'
            cached = body.resource in value['pa']
            if body.resource not in value['pa']:
                r = operator.agent('/session', {'path': '/api/'+body.resource, 'method': 'GET'}, value['human'])
                if r.status_code != 200:
                    raise HTTPException(r.status_code, r.json().get('detail', 'pa_session_rejected'))
                value['pa'][body.resource] = r.json()['session_id']
            session_stage = {'component': phase, 'status': 'NOT_OBSERVED' if cached else 'VERIFIED_PASS',
                'evidence': [] if cached else [{'source': 'Device mTLS gateway / PA session response', 'status': 200}]}
            preliminary.append(session_stage)
            if operation == 'adjust':
                phase = 'step_up'
                with lock:
                    step_up = value.pop('step_up', None)
                if not step_up:
                    raise HTTPException(401, 'step_up_required')
                preliminary.append({'component': phase, 'status': 'VERIFIED_PASS', 'evidence': [{'source': 'Identity verified an additional same-subject WebAuthn ceremony'}]})
            phase = 'token_exchange'
            exchange_body = {'scope': 'salary:write', 'step_up_token': step_up} if operation == 'adjust' else {'scope': None}
            r = operator.agent('/token/exchange', exchange_body, value['pa'][body.resource])
            if r.status_code != 200:
                value['pa'].pop(body.resource, None)
                raise HTTPException(r.status_code, r.json().get('detail', 'token_exchange_rejected'))
            if cached:
                session_stage.update(status='VERIFIED_PASS', evidence=[{'source': 'PA exchange revalidated the cached device-bound Session', 'status': 200}])
            preliminary.append({'component': phase, 'status': 'VERIFIED_PASS', 'evidence': [{'source': 'Device mTLS gateway / PA exchange response', 'status': 200}]})
            phase = 'access'
            result = operator.perform(Experiment(token=r.json()['access_token'], resource=body.resource, owner=body.owner,
                                                  operation=operation, amount=amount),
                                      attempt_id=attempt, request_id=request_id)
        except Exception as error:
            try:
                result = operator.evidence(attempt)
            except Exception:
                result = inspect_attempt(attempt, [], [], None)
            http_error = isinstance(error, HTTPException)
            code = error.status_code if http_error else 0
            reason = error.detail if http_error else type(error).__name__
            denied = code in (401, 403)
            preliminary.append({'component': phase, 'status': 'VERIFIED_BLOCK' if denied else 'UNKNOWN',
                'evidence': [{'source': phase+' response' if http_error else 'local transport', 'status': code, 'reason': reason}]})
            if denied and result.get('execution_query_observed') and result.get('executions') == []:
                for stage in result['stages']:
                    if stage['component'] == 'resource':
                        stage['status'] = 'NOT_REACHED'
            result.update(responses=[{'status': code, 'error': reason}], reason=reason,
                          denial_point=phase if denied else None)
        result.update(request={'resource': body.resource, 'owner': body.owner, 'method': 'POST' if operation == 'adjust' else 'GET'},
                      request_id=request_id, observed_at=datetime.now(timezone.utc).isoformat())
        result['stages'] = preliminary+result.get('stages', [])
        return cache(public_attempt(result, value['subject']))

    @app.post('/api/portal/access', status_code=202)
    def access(body: Access, request: Request):
        sid, value = current(request)
        csrf(request, value)
        attempt, request_id = str(uuid4()), str(uuid4())
        return submit(lambda: execute(value, body, attempt, request_id), owner=sid, attempt_id=attempt)

    @app.post('/api/portal/salary/adjust', status_code=202)
    def adjust(body: Adjustment, request: Request):
        sid, value = current(request)
        csrf(request, value)
        attempt, request_id = str(uuid4()), str(uuid4())
        access = Access(resource='salary', owner=body.owner)
        return submit(lambda: execute(value, access, attempt, request_id, operation='adjust', amount=body.amount),
                      owner=sid, attempt_id=attempt)

    @app.get('/api/portal/jobs/{job_id}')
    def job(job_id: str, request: Request):
        sid, _ = current(request)
        return get_job(job_id, sid)

    @app.get('/api/observer/attempts')
    def summaries():
        with lock:
            return {subject: ({key: value[key] for key in ('attempt_id', 'request_id', 'subject', 'request', 'observed_at', 'denial_point', 'reason', 'origin', 'caller') if key in value}
                              if value else None) for subject, value in latest.items()}

    @app.get('/api/observer/attempts/{attempt_id}')
    def detail(attempt_id: str):
        with lock:
            if attempt_id not in attempts:
                raise HTTPException(404, 'attempt_not_cached')
            # Synthetic resource contents belong in the employee page, not public monitoring.
            return {**attempts[attempt_id], 'responses': [{key: r[key] for key in ('status', 'error') if key in r}
                                                       for r in attempts[attempt_id]['responses']]}

    # Server-private hook; no HTTP mutation route exposes it to employees or Observer.
    return publish_inspector
