"""Focused coverage for parser dispatch and importer documentation."""
import importlib
import base64
import json
from pathlib import Path

import pytest

from workspace.parsers import FORMATS, TRACKS, parse


ROOT = Path(__file__).parents[1]
INPUTS = {
    'nmap_xml': b'<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>',
    'nmap_text': b'Nmap scan report for 192.0.2.10\n443/tcp open https\n',
    'nmap_gnmap': b'Host: 192.0.2.10 () Ports: 443/open/tcp//https///\n',
    'har': json.dumps({'log': {'entries': [{'request': {'url': 'https://example.test/app'}, 'response': {'status': 200}}]}}).encode(),
    'zap_json': json.dumps({'site': [{'@name': 'https://example.test', 'alerts': []}]}).encode(),
    'burp_xml': b'<items><item><url>https://example.test/app</url></item></items>',
    'linpeas_text': b'linPEAS synthetic\n[+] Operating system\n',
    'winpeas_text': b'winPEAS synthetic\n[+] Operating system\n',
    'bloodhound': json.dumps({'meta': {'version': 5, 'type': 'groups', 'count': 1}, 'data': [{'ObjectIdentifier': 'S-1-5-21-1', 'Properties': {'name': 'GROUP'}}]}).encode(),
    'manual_json': json.dumps({'schema_version': 1, 'assets': [{'id': 'host', 'label': 'Host', 'track': 'linux'}], 'observations': [], 'relationships': []}).encode(),
    'harness_observation_v1': json.dumps({
        'schema_version': 1, 'kind': 'harness_observation_v1',
        'envelope_id': '00000000-0000-4000-8000-000000000010',
        'engagement_id': '00000000-0000-4000-8000-000000000001',
        'producer': {'source_id': '00000000-0000-4000-8000-000000000011', 'role': 'reviewed_broker', 'key_id': 'synthetic-key'},
        'issued_at': '2026-09-09T12:00:00.000000Z',
        'review': {'status': 'reviewed', 'review_id': '00000000-0000-4000-8000-000000000012', 'reviewed_at': '2026-09-09T11:59:00.000000Z'},
        'profile': {'name': 'cptc11_smb2_security_mode_v1', 'version': 1},
        'execution': {
            'policy': {'id': 'cptc11.readonly', 'version': 3, 'sha256': '1' * 64},
            'release': {'id': 'cptc-harness', 'version': 7, 'sha256': '2' * 64},
            'frozen_plan': {'id': '00000000-0000-4000-8000-000000000014', 'sha256': '3' * 64},
            'target_profile': {'id': 'cptc11_smb2_security_mode_v1', 'version': 1, 'sha256': '4' * 64},
            'action_id': '00000000-0000-4000-8000-000000000015',
            'module': {'id': 'network.nse_smb2_security_mode', 'version': 1, 'sha256': '5' * 64},
            'collector': {'id': 'connected-relay', 'version': 2, 'sha256': '6' * 64},
            'reservation': {
                'id': '00000000-0000-4000-8000-000000000016',
                'reserved': {'tcp_connect_attempts': 2, 'udp_datagrams': 1, 'protocol_requests': 2, 'transmitted_bytes': 4096, 'received_bytes': 16384, 'wall_time_ms': 15000, 'cpu_time_ms': 10000, 'processes': 1, 'output_bytes': 16384, 'authentication_attempts': 0},
                'consumed': {'tcp_connect_attempts': 2, 'udp_datagrams': 1, 'protocol_requests': 1, 'transmitted_bytes': 768, 'received_bytes': 2048, 'wall_time_ms': 480, 'cpu_time_ms': 200, 'processes': 1, 'output_bytes': 512, 'authentication_attempts': 0},
            },
        },
        'observation': {
            'observation_id': '00000000-0000-4000-8000-000000000013', 'observed_at': '2026-09-09T11:58:00.000000Z', 'outcome': 'observed',
            'asset': {'asset_key': 'synthetic-host', 'label': 'Synthetic host', 'kind': 'host', 'track': 'windows_ad', 'identifiers': [], 'context': {'domain': '', 'role': '', 'segment': '', 'source_locator': ''}},
            'detector': {'name': 'smb2_security_mode', 'version': 1, 'deterministic': True},
            'result': {'protocol': 'smb2', 'port': 445, 'security_mode': 'unknown', 'dialect': 'unknown'}, 'evidence_refs': [],
        },
        'signature': {'algorithm': 'Ed25519', 'encoding': 'base64', 'key_id': 'synthetic-key', 'value': base64.b64encode(b'\0' * 64).decode()},
    }).encode(),
}


def test_public_dispatch_contract_and_all_dedicated_importers():
    assert set(INPUTS) == set(FORMATS)
    assert TRACKS == ('network', 'web', 'linux', 'windows_ad', 'database_service')
    for format, raw in INPUTS.items():
        result = parse(raw, format)
        assert result == parse(raw, format)
        assert result['assets']


@pytest.mark.parametrize('module', ('common', 'nmap_importer', 'web_importer', 'peas_importer', 'bloodhound_importer', 'manual_importer'))
def test_each_parser_module_has_documentation(module):
    package = ROOT / 'workspace' / 'parsers' / module
    assert (package / '__init__.py').is_file()
    readme = (package / 'README.md').read_text()
    assert len(readme) >= 120
    assert any(word in readme.lower() for word in ('support', 'limit', 'offline', 'partial'))
    assert importlib.import_module(f'workspace.parsers.{module}')


def test_dispatcher_does_not_expose_collection_execution():
    source = (ROOT / 'workspace' / 'parsers' / '__init__.py').read_text()
    assert 'subprocess' not in source and 'socket' not in source


@pytest.mark.parametrize(
    ('script_xml', 'expected_location'),
    (
        ('<hostscript><script id="synthetic-host" output="discard me"/></hostscript>', 'host[0]/hostscript/script[0]'),
        ('<ports><port protocol="tcp" portid="445"><state state="open"/><script id="synthetic-port" output="discard me"/></port></ports>', 'host[0]/ports/port[0]/script[0]'),
    ),
)
def test_nmap_xml_marks_host_and_port_nse_scripts_unsupported(script_xml, expected_location):
    raw = (
        '<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/>'
        f'{script_xml}</host><runstats><finished exit="success"/></runstats></nmaprun>'
    ).encode()

    result = parse(raw, 'nmap_xml')

    assert result['complete'] is False
    assert any('unsupported Nmap NSE' in limitation for limitation in result['limitations'])
    metadata = next(observation for observation in result['observations'] if observation['summary'] == 'Unsupported Nmap NSE script evidence was detected')
    assert metadata['facts'] == {
        'script_count': 1,
        'source_locations': [expected_location],
        'source_locations_truncated': False,
    }
    assert 'discard me' not in json.dumps(result)
    assert 'synthetic-host' not in json.dumps(result)
    assert 'synthetic-port' not in json.dumps(result)


def test_nmap_xml_detects_malformed_nse_script_without_parsing_its_body():
    raw = b'''<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/>
        <hostscript><script><table key="synthetic"><elem>unstructured body</elem></table></script></hostscript>
        </host><runstats><finished exit="success"/></runstats></nmaprun>'''

    result = parse(raw, 'nmap_xml')

    assert result['complete'] is False
    assert result['observations'][-1]['facts']['script_count'] == 1
    assert 'unstructured body' not in json.dumps(result)


def test_nmap_xml_without_nse_scripts_remains_complete():
    result = parse(INPUTS['nmap_xml'], 'nmap_xml')

    assert result['complete'] is True
    assert not result['limitations']
    assert all('Nmap NSE' not in observation['summary'] for observation in result['observations'])


def test_nmap_xml_bounds_nse_source_location_metadata():
    scripts = ''.join('<script/>' for _ in range(65))
    raw = (
        '<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/>'
        f'<hostscript>{scripts}</hostscript></host>'
        '<runstats><finished exit="success"/></runstats></nmaprun>'
    ).encode()

    result = parse(raw, 'nmap_xml')

    metadata = result['observations'][-1]['facts']
    assert metadata['script_count'] == 65
    assert len(metadata['source_locations']) == 64
    assert metadata['source_locations_truncated'] is True
    assert any('1 additional location(s)' in limitation for limitation in result['limitations'])
