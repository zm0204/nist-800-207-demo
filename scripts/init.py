"""Generate disposable demo PKI and a random control-plane key; idempotent."""
import argparse
import ipaddress
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

def key(): return rsa.generate_private_key(public_exponent=65537,key_size=2048)

def write_key(path,k):
    path.write_bytes(k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    if os.name!='nt': path.chmod(0o600)

def create_ca(root,name):
    k=key(); subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
    now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(k.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
          .not_valid_after(now+timedelta(days=365)).add_extension(x509.BasicConstraints(ca=True,path_length=0),True)
          .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),True).sign(k,hashes.SHA256()))
    write_key(root/(name+'.key'),k); (root/(name+'.crt')).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return k,cert

def leaf(root,name,ca,client=False,dns=(),uri=None):
    k=key(); now=datetime.now(timezone.utc); cak,cac=ca
    sans=[x509.DNSName(d) for d in dns]
    if 'localhost' in dns: sans.append(x509.IPAddress(ipaddress.ip_address('127.0.0.1')))
    if uri: sans.append(x509.UniformResourceIdentifier(uri))
    cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)]))
          .issuer_name(cac.subject).public_key(k.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=90))
          .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
          .add_extension(x509.SubjectAlternativeName(sans),False)
          .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]),False)
          .sign(cak,hashes.SHA256()))
    write_key(root/(name+'.key'),k); (root/(name+'.crt')).write_bytes(cert.public_bytes(serialization.Encoding.PEM))

def initialize(output):
    if os.name!='nt' and os.getuid()==0:
        raise SystemExit('Run PKI initialization as your normal user, not root; Envoy reads keys as that UID.')
    output.mkdir(parents=True,exist_ok=True); root=output/'certs'; root.mkdir(exist_ok=True)
    required=['device-ca','service-ca','upstream-client-ca','pep','device-a','device-b','pep-upstream','resource','resource-client']
    expected=[root/(n+ext) for n in required for ext in ('.crt','.key')]
    present=[p.exists() for p in expected]
    if any(present) and not all(present):
        raise SystemExit('Incomplete PKI: restore files or explicitly remove certs after stopping demo. Refusing partial rotation.')
    if not all(present):
        device=create_ca(root,'device-ca'); service=create_ca(root,'service-ca'); upstream=create_ca(root,'upstream-client-ca')
        leaf(root,'pep',service,dns=['pep','localhost'])
        for name in ['device-a','device-b']:
            leaf(root,name,device,client=True,uri='urn:zta:device:'+name)
        leaf(root,'pep-upstream',upstream,client=True,uri='urn:zta:service:pep')
        leaf(root,'resource',service,dns=['resource','localhost'])
        leaf(root,'resource-client',service,client=True,uri='urn:zta:service:resource')
    if not (output/'.env').exists():
        uid=os.getuid() if os.name!='nt' else 101
        (output/'.env').write_text('SERVICE_KEY='+secrets.token_hex(32)+'\nENVOY_UID='+str(uid)+'\n',encoding='utf-8')
        if os.name!='nt': (output/'.env').chmod(0o600)
    print('Demo PKI ready. Private keys and .env must never be committed.')

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--output',type=Path,default=Path(__file__).resolve().parents[1])
    initialize(parser.parse_args().output)
