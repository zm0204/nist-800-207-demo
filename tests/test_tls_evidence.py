import ssl
import httpx
import pytest


@pytest.mark.parametrize('error', [httpx.ReadTimeout('late'), httpx.WriteTimeout('late'),
    httpx.RemoteProtocolError('reset'), httpx.ConnectError('refused'), ssl.SSLError(1, 'unrelated')])
def test_transport_errors_do_not_prove_client_certificate_rejection(error):
    from scripts.verify_identity import certificate_required
    assert certificate_required(error) is False


def test_specific_tls_certificate_required_alert_is_proof():
    from scripts.verify_identity import certificate_required
    error = ssl.SSLError(1, 'client certificate required')
    error.reason = 'TLSV13_ALERT_CERTIFICATE_REQUIRED'
    assert certificate_required(error) is True
