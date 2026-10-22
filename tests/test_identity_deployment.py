import json
from pathlib import Path


def test_renderer_covers_all_hops_and_custom_cannot_be_bypassed():
    from scripts.identity_deploy import render
    docs = render({'keys': [{'kid': 'public-only'}]})
    policies = [d for d in docs if d['kind'] == 'AuthorizationPolicy']
    authn = next(d for d in docs if d['kind'] == 'RequestAuthentication')
    assert authn['spec']['jwtRules'][0]['audiences'] == ['zta-hr']
    assert authn['spec']['jwtRules'][0]['forwardOriginalToken'] is True
    custom = next(p for p in policies if p['metadata']['name'] == 'backend-external-decision')
    assert custom['spec']['rules'] == [{'to': [{'operation': {'ports': ['8000']}}]}]
    for app in ('frontend', 'salary', 'profile'):
        workload = next(d for d in docs if d['kind'] == 'Deployment' and d['metadata']['name'] == app)
        assert workload['spec']['template']['metadata']['labels']['identity-protected'] == 'true'
        native = next(p for p in policies if p['spec'].get('selector', {}).get('matchLabels', {}).get('app') == app)
        assert all(r['from'][0]['source']['requestPrincipals'] == ['*'] for r in native['spec']['rules'])
    for d in docs:
        assert d['metadata'].get('namespace', 'zta-identity') == 'zta-identity'
        assert 'PRIVATE KEY' not in json.dumps(d)
    for d in docs:
        if d['kind'] == 'Deployment' and d['metadata']['name'] != 'pa':
            assert 'user-signing' not in json.dumps(d)
    import yaml
    gateway = next(d for d in docs if d['kind'] == 'ConfigMap' and d['metadata']['name'] == 'device-gateway')
    envoy = yaml.safe_load(gateway['data']['envoy.yaml'])
    hcm = envoy['static_resources']['listeners'][0]['filter_chains'][0]['filters'][0]['typed_config']
    for route in hcm['route_config']['virtual_hosts'][0]['routes']:
        assert route['route']['host_rewrite_literal'] == route['route']['cluster']+':8000'
    jwt_filter = next(f for f in hcm['http_filters'] if f['name'] == 'envoy.filters.http.jwt_authn')
    assert jwt_filter['typed_config']['rules'] == [{'match': {'prefix': '/api/'}, 'requires': {'provider_name': 'user'}}]
