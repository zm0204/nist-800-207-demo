from pathlib import Path
import subprocess
import sys
import yaml
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

ROOT=Path(__file__).resolve().parents[1]

def test_networks_and_host_exposure():
    c=yaml.safe_load((ROOT/'compose.yaml').read_text())
    assert c['networks']['control']['internal'] is True
    assert c['networks']['data']['internal'] is True
    assert c['services']['resource']['networks']==['data']
    assert 'ports' not in c['services']['resource']
    assert set(c['services']['pe']['networks'])=={'control'}
    assert set(c['services']['pa']['networks'])=={'control'}
    assert set(c['services']['pep']['networks'])=={'edge','control','data'}
    for svc in c['services'].values():
        for port in svc.get('ports',[]): assert port.startswith('127.0.0.1:')

def test_certificate_generation(tmp_path):
    subprocess.run([sys.executable,str(ROOT/'scripts/init.py'),'--output',str(tmp_path)],check=True)
    cert=x509.load_pem_x509_certificate((tmp_path/'certs/device-a.crt').read_bytes())
    assert cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)==['urn:zta:device:device-a']
    assert ExtendedKeyUsageOID.CLIENT_AUTH in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    server=x509.load_pem_x509_certificate((tmp_path/'certs/pep.crt').read_bytes())
    assert 'localhost' in server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    assert server.issuer != cert.issuer
    assert 'SERVICE_KEY=' in (tmp_path/'.env').read_text()
    # Initializer must not silently rotate existing keys or invalidate sessions.
    before=(tmp_path/'certs/device-a.key').read_bytes()
    subprocess.run([sys.executable,str(ROOT/'scripts/init.py'),'--output',str(tmp_path)],check=True)
    assert before==(tmp_path/'certs/device-a.key').read_bytes()

def test_envoy_fail_closed_and_certificate_sanitization():
    e=yaml.safe_load((ROOT/'envoy/envoy.yaml').read_text())
    hcm=e['static_resources']['listeners'][0]['filter_chains'][0]['filters'][0]['typed_config']
    assert hcm['forward_client_cert_details']=='SANITIZE_SET'
    auth=next(f['typed_config'] for f in hcm['http_filters'] if f['name']=='envoy.filters.http.ext_authz')
    assert auth['failure_mode_allow'] is False
    assert auth['http_service']['path_prefix']=='/check'

def test_sanitize_before_authz_preserves_authorized_headers():
    e=yaml.safe_load((ROOT/'envoy/envoy.yaml').read_text())
    h=e['static_resources']['listeners'][0]['filter_chains'][0]['filters'][0]['typed_config']
    assert h['http_filters'][0]['name']=='envoy.filters.http.lua'
    assert 'x-zta-subject' in h['http_filters'][0]['typed_config']['inline_code']
    for vhost in h['route_config']['virtual_hosts']:
        assert 'request_headers_to_remove' not in vhost
