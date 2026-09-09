"""Focused coverage for parser dispatch and importer documentation."""
import importlib
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
