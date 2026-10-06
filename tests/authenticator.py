"""Test-only software authenticator. Real signatures; not a server auth bypass."""
import base64
import hashlib
import json
import os
import struct
import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

def b64(value): return base64.urlsafe_b64encode(value).rstrip(b'=').decode()

class Authenticator:
    def __init__(self):
        self.key=ec.generate_private_key(ec.SECP256R1()); self.id=os.urandom(32); self.counter=0

    def client(self,options,typ,origin):
        return json.dumps({'type':typ,'challenge':options['challenge'],'origin':origin,'crossOrigin':False},separators=(',',':')).encode()

    def register(self,options,origin='http://localhost:8080',uv=True):
        pub=self.key.public_key().public_numbers()
        cose=cbor2.dumps({1:2,3:-7,-1:1,-2:pub.x.to_bytes(32,'big'),-3:pub.y.to_bytes(32,'big')})
        auth=hashlib.sha256(options['rp']['id'].encode()).digest()+bytes([0x45 if uv else 0x41])+struct.pack('>I',0)
        auth+=bytes(16)+struct.pack('>H',len(self.id))+self.id+cose
        return {'id':b64(self.id),'rawId':b64(self.id),'type':'public-key','response':{
            'clientDataJSON':b64(self.client(options,'webauthn.create',origin)),
            'attestationObject':b64(cbor2.dumps({'fmt':'none','attStmt':{},'authData':auth})), 'transports':['internal']}}

    def login(self,options,origin='http://localhost:8080',uv=True):
        self.counter+=1
        client=self.client(options,'webauthn.get',origin)
        auth=hashlib.sha256(options['rpId'].encode()).digest()+bytes([5 if uv else 1])+struct.pack('>I',self.counter)
        signature=self.key.sign(auth+hashlib.sha256(client).digest(),ec.ECDSA(hashes.SHA256()))
        return {'id':b64(self.id),'rawId':b64(self.id),'type':'public-key','response':{
            'clientDataJSON':b64(client),'authenticatorData':b64(auth),'signature':b64(signature),'userHandle':b64(b'alice')}}
