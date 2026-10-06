"""Demo CDM, threat intelligence, policy database and activity log endpoints."""
import json
import hashlib
import time
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, Field
from app.common import db, protected

app = FastAPI(title='CDM / Threat Intelligence / Policy DB / Telemetry', dependencies=[Depends(protected)])
DEFAULT = {'device':{'id':'device-a','managed':True,'compromised':False,'os_current':True},
           'context':{'source_ip':'192.0.2.10','high_risk_ip':False,'abnormal':False},
           'policy':{'version':1,'threshold':60,'grants':{'alice':['GET /api/salary','GET /api/profile','GET /api/stream']}}}

def initialize():
    with db('context') as c:
        c.execute('CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, value TEXT)')
        c.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ts REAL, value TEXT)')
        c.execute('INSERT OR IGNORE INTO settings VALUES (1,?)',(json.dumps(DEFAULT),))
initialize()

@app.get('/health')
def health(): return {'ok':True}

@app.get('/snapshot')
def snapshot():
    with db('context') as c:
        state = json.loads(c.execute('SELECT value FROM settings WHERE id=1').fetchone()[0])
        recent = c.execute('SELECT COUNT(*) FROM events WHERE ts>? AND json_extract(value,\'$.kind\')=\'request\'', (time.time()-10,)).fetchone()[0]
    state['context']['request_count_10s'] = recent
    state['context']['abnormal'] |= recent >= 12
    return state

@app.post('/event')
def event(value:dict):
    # Auth/session tokens never enter activity logs.
    def sanitized(item):
        if isinstance(item,list): return [sanitized(v) for v in item]
        if not isinstance(item,dict): return item
        result={}
        for key,val in item.items():
            if key in ('token','authorization','human_token'): continue
            if key=='session_id': result['session_ref']=hashlib.sha256(str(val).encode()).hexdigest()[:16]
            else: result[key]=sanitized(val)
        return result
    value=sanitized(value)
    with db('context') as c:
        c.execute('INSERT INTO events(ts,value) VALUES (?,?)',(time.time(),json.dumps(value)))
    return {'ok':True}

@app.get('/events')
def events():
    with db('context') as c:
        return [dict(json.loads(r['value']), event_id=r['id'],timestamp=r['ts']) for r in c.execute('SELECT * FROM events ORDER BY id DESC LIMIT 100')]

class Simulation(BaseModel):
    action: str

@app.post('/simulate')
def simulate(body:Simulation):
    actions={'compromise':('device','compromised',True),'outdated':('device','os_current',False),
             'high-risk-ip':('context','high_risk_ip',True),'abnormal':('context','abnormal',True)}
    with db('context') as c:
        state=json.loads(c.execute('SELECT value FROM settings WHERE id=1').fetchone()[0])
        if body.action == 'reset':
            state=json.loads(json.dumps(DEFAULT)); c.execute('DELETE FROM events')
        elif body.action in actions:
            area,key,val=actions[body.action]; state[area][key]=val
            if body.action=='high-risk-ip': state['context']['source_ip']='198.51.100.66'
        else: raise HTTPException(400,'unknown simulation')
        c.execute('UPDATE settings SET value=? WHERE id=1',(json.dumps(state),))
    event({'kind':'signal','action':body.action})
    return state

class Policy(BaseModel):
    threshold:int=Field(ge=0,le=100)
    grants:dict[str,list[str]]

@app.put('/policy')
def update_policy(body:Policy):
    with db('context') as c:
        state=json.loads(c.execute('SELECT value FROM settings WHERE id=1').fetchone()[0])
        state['policy']={**body.model_dump(),'version':state['policy']['version']+1}
        c.execute('UPDATE settings SET value=? WHERE id=1',(json.dumps(state),))
    event({'kind':'policy_update','policy':state['policy']})
    return state['policy']
