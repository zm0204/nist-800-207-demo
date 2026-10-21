from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest

URI = 'spiffe://cluster.local/ns/zta-207a/sa/salary'


def certificate(hours=1, uri=URI, offset=0):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc) + timedelta(hours=offset)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test workload')])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - timedelta(minutes=2))
            .not_valid_after(now + timedelta(hours=hours))
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), critical=False)
            .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))


def test_evidence_accepts_one_hour_certificate_with_issuer_backdating():
    from scripts.mesh_demo import certificate_evidence
    result = certificate_evidence(certificate(), URI)
    assert result['uri'] == URI
    assert 3700 <= result['lifetime_seconds'] <= 3730


@pytest.mark.parametrize('kwargs', [{'hours': 24}, {'uri': URI + '-forged'}, {'offset': -2}, {'offset': 2}])
def test_evidence_rejects_wrong_lifetime_identity_or_validity(kwargs):
    from scripts.mesh_demo import certificate_evidence
    with pytest.raises(AssertionError):
        certificate_evidence(certificate(**kwargs), URI)


@pytest.mark.parametrize('spec', [
    {'containers': [{'name': 'app'}, {'name': 'istio-proxy'}]},
    {'containers': [{'name': 'app'}], 'initContainers': [{'name': 'istio-proxy', 'restartPolicy': 'Always'}]},
])
def test_sidecar_evidence_supports_classic_and_kubernetes_native_sidecars(spec):
    from scripts.mesh_demo import has_sidecar
    assert has_sidecar({'spec': spec})


def test_one_shot_init_container_is_not_a_running_sidecar():
    from scripts.mesh_demo import has_sidecar
    assert not has_sidecar({'spec': {'containers': [{'name': 'app'}], 'initContainers': [{'name': 'istio-proxy'}]}})
