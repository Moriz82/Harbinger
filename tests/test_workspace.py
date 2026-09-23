import io
import json
import os
import sqlite3
import threading
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import stat
import uuid
import zipfile
from xml.etree.ElementTree import ParseError
import pytest
from fastapi.testclient import TestClient
from workspace import APP_NAME
from workspace.cli import initialize, backup, restore
from workspace.auth import add_user
from workspace.store import Store, Conflict, canonical, digest
from workspace.server import create_app
from workspace.parsers import parse, archive
from workspace.transfer import enroll, peer_http_headers, provision_keys, public_card

NMAP = b'''<?xml version="1.0"?><nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port><port protocol="tcp" portid="5432"><state state="open"/><service name="postgresql" version="16.1"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'''
MANUAL = {'schema_version': 1, 'assets': [{'id': 'host-one', 'label': 'Training host', 'kind': 'host', 'track': 'linux'}], 'observations': [{'subject': 'host-one', 'summary': 'Operator-reviewed metadata', 'facts': {'synthetic': True}}], 'relationships': []}


@pytest.fixture
def store(tmp_path):
    return initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic practice', engagement_id='00000000-0000-4000-8000-000000000001')


@pytest.fixture
def client(store):
    role = 'captain' if APP_NAME == 'Harbinger' else 'lead_scribe'
    add_user(store, 'host', role, 'synthetic-test-password', APP_NAME)
    client = TestClient(create_app(store.root), base_url='http://127.0.0.1:8710', headers={'Origin': 'http://127.0.0.1:8710'})
    response = client.post('/api/login', json={'name': 'host', 'password': 'synthetic-test-password'})
    assert response.status_code == 200
    client.headers['X-CSRF-Token'] = response.json()['csrf']
    with client:
        yield client


def test_revision_conflict_preserves_history(store):
    with store.tx() as c:
        first = store.put(c, 'draft', {'title': 'First'}, 'a')
        store.event(c, 'a', 'created', [first['id']])
    with store.tx() as c:
        second = store.put(c, 'draft', {'title': 'Second'}, 'b', first['id'], first['revision_id'])
        store.event(c, 'b', 'updated', [first['id']])
    with pytest.raises(Conflict):
        with store.tx() as c:
            store.put(c, 'draft', {'title': 'Lost edit'}, 'c', first['id'], first['revision_id'])
    assert store.get(first['id'])['data']['title'] == 'Second'
    with store.connect() as c:
        assert c.execute('SELECT COUNT(*) FROM revisions').fetchone()[0] == 2
    assert store.verify()['events'] == 3


def test_audit_utc_and_injection(store):
    with store.tx() as c:
        store.event(c, 'operator\n\x1b[31m', 'record.updated', ['synthetic'])
    lines = (store.root / 'audit.jsonl').read_text().splitlines()
    assert len(lines) == 2
    event = json.loads(lines[-1])['body']
    import re
    assert re.fullmatch(r'.*T\d{2}:\d{2}:\d{2}\.\d{6}Z', event['utc'])
    assert '\x1b' not in (store.root / 'transcript.log').read_text()


def test_tampered_audit_blocks_restart(store):
    p = store.root / 'audit.jsonl'
    p.write_text(p.read_text().replace('configuration.changed', 'configuration.altered'))
    restarted = Store(store.root)
    assert restarted.blocked
    with pytest.raises(RuntimeError):
        restarted.configure('x', 'y')


def test_healthcheck_reports_write_readiness_after_audit_tamper(store):
    base = 'http://127.0.0.1:8710'
    with TestClient(create_app(store.root), base_url=base) as healthy:
        assert healthy.get('/healthz').status_code == 200
    audit = store.root / 'audit.jsonl'
    audit.write_text(audit.read_text().replace('configuration.changed', 'configuration.altered'))
    with TestClient(create_app(store.root), base_url=base) as degraded:
        assert degraded.get('/api/session').status_code == 200
        response = degraded.get('/healthz')
        assert response.status_code == 503
        assert response.json() == {'status': 'degraded'}


def test_healthcheck_reports_permission_drift_during_service(client, store):
    assert client.get('/healthz').status_code == 200
    audit = store.root / 'audit.jsonl'
    audit.chmod(0o644)
    try:
        assert client.get('/healthz').status_code == 503
        assert client.get('/api/readiness').status_code == 503
        assert client.post('/api/logout').status_code == 503
    finally:
        audit.chmod(0o600)


@pytest.mark.parametrize('name,mode', [
    ('workspace.db', 0o400),
    ('audit.jsonl', 0o400),
    ('transcript.log', 0o400),
    ('artifacts', 0o500),
    ('artifacts', 0o600),
    ('artifacts', 0o200),
    ('keys', 0o500),
    ('staging', 0o500),
    ('conflicts', 0o500),
    ('exports', 0o500),
])
def test_healthcheck_rejects_owner_read_only_storage(client, store, name, mode):
    path = store.root / name
    original = path.stat().st_mode & 0o777
    path.chmod(mode)
    try:
        assert client.get('/healthz').status_code == 503
        assert client.get('/api/readiness').status_code == 503
        with pytest.raises(RuntimeError, match='not writable'):
            store.require_write_ready()
    finally:
        path.chmod(original)


@pytest.mark.parametrize('name', ['artifacts', 'keys', 'staging', 'conflicts', 'exports'])
def test_healthcheck_rejects_directory_replaced_by_file(client, store, name):
    path = store.root / name
    assert not any(path.iterdir())
    path.rmdir()
    path.write_text('synthetic wrong type')
    path.chmod(0o600)
    try:
        assert client.get('/healthz').status_code == 503
        assert client.get('/api/readiness').status_code == 503
        with pytest.raises(RuntimeError, match='wrong type'):
            store.require_write_ready()
    finally:
        path.unlink()
        path.mkdir(mode=0o700)


def test_event_stream_session_checks_do_not_extend_idle_authentication(store, monkeypatch):
    from workspace import auth
    add_user(store, 'stream-user', 'tester', 'synthetic-stream-password', APP_NAME)
    token, _ = auth.login(store, 'stream-user', 'synthetic-stream-password', '127.0.0.1')
    with store.connect() as connection:
        before = connection.execute('SELECT touched FROM sessions').fetchone()[0]
    assert auth.session(store, token, touch=False)
    with store.connect() as connection:
        assert connection.execute('SELECT touched FROM sessions').fetchone()[0] == before
    monkeypatch.setattr(auth, 'time', SimpleNamespace(time=lambda: before + 1801))
    assert auth.session(store, token, touch=False) is None


def test_passive_session_endpoints_do_not_refresh_idle_time(client, store, monkeypatch):
    from workspace import auth
    with store.connect() as connection:
        before = connection.execute('SELECT touched FROM sessions').fetchone()[0]
    for _ in range(3):
        assert client.get('/api/session-status').json() == {'active': True}
    original = auth.session
    calls = []
    def finite_stream(current_store, token, *, touch=True):
        calls.append(touch)
        return original(current_store, token, touch=touch) if len(calls) % 2 else None
    monkeypatch.setattr(auth, 'session', finite_stream)
    for _ in range(2):
        assert client.get('/api/events').status_code == 200
    assert calls == [False] * 4
    monkeypatch.setattr(auth, 'session', original)
    with store.connect() as connection:
        assert connection.execute('SELECT touched FROM sessions').fetchone()[0] == before
    monkeypatch.setattr(auth, 'time', SimpleNamespace(time=lambda: before + 1801))
    assert client.get('/api/session-status').json() == {'active': False}


def test_permission_drift_blocks_changes(store):
    (store.root / 'audit.jsonl').chmod(0o644)
    with pytest.raises(RuntimeError):
        store.configure('x', 'y')


def test_short_audit_writes(store, monkeypatch):
    original = os.write
    monkeypatch.setattr(os, 'write', lambda fd, data: original(fd, data[:7]))
    store.configure('short-writes', True)
    assert store.verify()['events'] == 2


def test_audit_failure_rolls_back(store, monkeypatch):
    def fail(*args):
        raise OSError('synthetic full disk')
    monkeypatch.setattr(os, 'write', fail)
    with pytest.raises(OSError):
        store.configure('uncommitted', True)
    assert store.setting('uncommitted') is None
    assert store.blocked


def test_backup_consistent_and_sources_unchanged(store, tmp_path):
    before = (store.root / 'audit.jsonl').read_bytes()
    result = backup(store, tmp_path / 'backup')
    assert result['files'] >= 3
    assert not (tmp_path / 'backup' / 'workspace.db-wal').exists()
    assert not (tmp_path / 'backup' / 'workspace.db-shm').exists()
    manifest = json.loads((tmp_path / 'backup' / 'backup-manifest.json').read_text())
    actual = {str(path.relative_to(tmp_path / 'backup')) for path in (tmp_path / 'backup').rglob('*') if path.is_file() and path.name != 'backup-manifest.json'}
    assert set(manifest['files']) == actual
    copy = Store(tmp_path / 'backup')
    assert copy.setting('config') == store.setting('config')
    assert copy.verify() == store.verify()
    assert (store.root / 'audit.jsonl').read_bytes() == before


def test_readonly_store_backup_preserves_every_source_file(store, tmp_path):
    before = {
        str(path.relative_to(store.root)): path.read_bytes()
        for path in store.root.rglob('*') if path.is_file()
    }
    readonly = Store(store.root, readonly=True)
    backup(readonly, tmp_path / 'readonly-backup')
    after = {
        str(path.relative_to(store.root)): path.read_bytes()
        for path in store.root.rglob('*') if path.is_file()
    }
    assert after == before
    with pytest.raises(RuntimeError, match='read-only'):
        readonly.configure('blocked', True)


def test_wal_aware_readonly_backup_preserves_live_sidecars_and_committed_data(store, tmp_path):
    reader = sqlite3.connect(store.path)
    try:
        reader.execute('BEGIN')
        reader.execute('SELECT COUNT(*) FROM settings').fetchone()
        with sqlite3.connect(store.path) as writer:
            writer.execute('PRAGMA wal_autocheckpoint=0')
            writer.execute('INSERT INTO settings(key,value) VALUES(?,?)', ('wal-fixture', canonical({'present': True})))
        assert (store.root / 'workspace.db-wal').stat().st_size > 0
        before = {
            str(path.relative_to(store.root)): path.read_bytes()
            for path in store.root.rglob('*') if path.is_file() and path.name != 'workspace.db-shm'
        }
        readonly = Store(store.root, readonly=True, wal_aware_readonly=True)
        backup(readonly, tmp_path / 'wal-backup')
        after = {
            str(path.relative_to(store.root)): path.read_bytes()
            for path in store.root.rglob('*') if path.is_file() and path.name != 'workspace.db-shm'
        }
        assert after == before
        copied = Store(tmp_path / 'wal-backup', readonly=True)
        assert copied.setting('wal-fixture') == {'present': True}
    finally:
        reader.close()


def test_wal_aware_readonly_backup_without_sidecars_uses_immutable_database(store, tmp_path, monkeypatch):
    assert not (store.root / 'workspace.db-wal').exists()
    assert not (store.root / 'workspace.db-shm').exists()
    real_connect = sqlite3.connect
    source_uris = []

    def track_connect(database, *args, **kwargs):
        if str(database).startswith(f'file:{store.path}?'):
            source_uris.append(str(database))
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, 'connect', track_connect)
    store.root.chmod(0o500)
    try:
        readonly = Store(store.root, readonly=True, wal_aware_readonly=True)
        backup(readonly, tmp_path / 'no-sidecar-backup')
    finally:
        store.root.chmod(0o700)
    assert source_uris and all('mode=ro&immutable=1' in uri for uri in source_uris)
    assert not (store.root / 'workspace.db-wal').exists()
    assert not (store.root / 'workspace.db-shm').exists()


def test_restore_verifies_manifest_and_preserves_history(store, tmp_path):
    with store.tx() as connection:
        item = store.put(connection, 'finding', {'title': 'Restore fixture', 'observation': 'Synthetic history'}, 'fixture')
        store.event(connection, 'fixture', 'finding.fixture_created', [item['id']])
    backup_path = tmp_path / 'backup'
    backup(store, backup_path)
    restored_path = tmp_path / 'restored'
    result = restore(backup_path, restored_path)
    restored = Store(restored_path)
    assert result['files'] > 0
    assert (restored.root / 'parser-queue').is_dir()
    assert restored.get(item['id'])['revision_id'] == item['revision_id']
    assert restored.setting('config') == store.setting('config')
    assert restored.verify() == store.verify()


def test_restore_rejects_tampered_backup_without_creating_destination(store, tmp_path):
    backup_path = tmp_path / 'backup'
    backup(store, backup_path)
    with (backup_path / 'audit.jsonl').open('ab') as target:
        target.write(b'changed\n')
    destination = tmp_path / 'restored'
    with pytest.raises(ValueError, match='integrity'):
        restore(backup_path, destination)
    assert not destination.exists()


INPUTS = {
    'nmap_xml': NMAP,
    'nmap_text': b'Nmap scan report for 192.0.2.10\n443/tcp open https\n',
    'nmap_gnmap': b'Host: 192.0.2.10 () Ports: 443/open/tcp//https///\n',
    'har': json.dumps({'log': {'entries': [{'request': {'url': 'https://example.test/app', 'method': 'GET'}, 'response': {'status': 200}}]}}).encode(),
    'zap_json': json.dumps({'site': [{'@name': 'https://example.test', 'alerts': [{'name': 'Synthetic candidate', 'cweid': '693', 'instances': [{'uri': 'https://example.test/app'}]}]}]}).encode(),
    'burp_xml': b'<items><item><url>https://example.test/app</url></item></items>',
    'linpeas_text': b'linPEAS synthetic\n[+] Operating system\n',
    'winpeas_text': b'winPEAS synthetic\n[+] Operating system\n',
    'bloodhound': json.dumps({'meta': {'version': 5, 'type': 'groups', 'count': 1, 'methods': 1}, 'data': [{'ObjectIdentifier': 'S-1-5-21-1', 'Properties': {'name': 'TRAINING GROUP'}, 'Members': [{'ObjectIdentifier': 'S-1-5-21-2', 'ObjectType': 'User'}]}]}).encode(),
    'manual_json': json.dumps(MANUAL).encode(),
}


@pytest.mark.parametrize('format', INPUTS)
def test_admitted_formats_deterministic(format):
    a = parse(INPUTS[format], format)
    assert a == parse(INPUTS[format], format)
    assert a['assets'] and not a['quarantined']
    assert all(x['source'] in {y['id'] for y in a['assets']} for x in a['relationships'])


@pytest.mark.parametrize('format', INPUTS)
def test_malformed_never_clean(format):
    try:
        result = parse(b'not a supported file', format)
    except (ValueError, KeyError, ParseError):
        return
    assert not result['complete'] and result['limitations']


def test_all_tracks_have_visible_records():
    tracks = {a['track'] for format, raw in INPUTS.items() for a in parse(raw, format)['assets']}
    assert tracks == {'network', 'web', 'linux', 'windows_ad', 'database_service'}


def test_nmap_does_not_infer_host_connectivity():
    p = parse(NMAP, 'nmap_xml')
    assert all(e['label'] == 'Observed service' for e in p['relationships'])


def test_missing_completion_is_partial():
    p = parse(NMAP.replace(b'<runstats><finished exit="success"/></runstats>', b''), 'nmap_xml')
    assert not p['complete']


def test_xml_external_entities_rejected():
    with pytest.raises(Exception):
        parse(b'<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun>&x;</nmaprun>', 'nmap_xml')


@pytest.mark.parametrize('name', ['../file.json', '/file.json', 'a\\file.json', 'nested.zip', 'database.db'])
def test_unsafe_archive_rejected(name):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as z:
        z.writestr(name, '{}')
    with pytest.raises(ValueError):
        list(archive(stream.getvalue()))


def test_zip_symlink_rejected():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as z:
        info = zipfile.ZipInfo('link.json'); info.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(info, 'anything')
    with pytest.raises(ValueError):
        list(archive(stream.getvalue()))


def test_secret_quarantine():
    raw = INPUTS['har'].replace(b'"method": "GET"', b'"method": "GET", "headers": [{"name":"Authorization","value":"Bearer synthetic-secret"}]')
    # Header name/value representations must be recognized, not only key=value text.
    result = parse(raw, 'har')
    assert result['quarantined'] and result['assets'] == []


def test_query_values_omitted():
    raw = INPUTS['har'].replace(b'/app"', b'/app?record=synthetic-private-value"')
    result = parse(raw, 'har')
    assert 'synthetic-private-value' not in json.dumps(result)
    assert result['limitations']


def test_unknown_bloodhound_format_rejected():
    with pytest.raises(ValueError):
        parse(INPUTS['bloodhound'].replace(b'"version": 5', b'"version": 6'), 'bloodhound')


def test_auth_and_csrf(client):
    assert client.get('/api/session').json()['user']['name'] == 'host'
    assert client.post('/api/logout', headers={'X-CSRF-Token': 'wrong'}).status_code == 403
    assert client.post('/api/logout', headers={'Origin': 'https://outside.invalid'}).status_code == 403
    assert client.get('/api/assets', headers={'Host': 'outside.invalid'}).status_code == 400
    assert client.post('/api/logout').status_code == 200
    assert client.get('/api/assets').status_code == 401


def test_connection_status_describes_configuration_not_reachability(client, store):
    store = client.app.state.store
    empty = client.get('/api/connections').json()
    if APP_NAME == 'Harbinger':
        assert empty['ghostwriter'] == {'status': 'unavailable', 'origin': '', 'report_id': ''} and empty['peers'] == []
        store.configure('ghostwriter', {'origin': 'https://ghostwriter.example.test', 'report_id': '7', 'schema_hash': 'fixture'})
        assert client.get('/api/connections').json()['ghostwriter']['status'] == 'unavailable'
        assert client.get('/api/deliveries').status_code == 404
        return
    assert empty['ghostwriter']['status'] == 'not_configured' and empty['peers'] == []
    store.configure('ghostwriter', {'origin': 'https://ghostwriter.example.test', 'report_id': '7'})
    assert client.get('/api/connections').json()['ghostwriter']['status'] == 'configured_unverified'
    store.configure('ghostwriter', {'origin': 'https://ghostwriter.example.test', 'report_id': '7', 'schema_hash': 'fixture'})
    peer = {'id': str(uuid.uuid4()), 'name': 'Merlin', 'origin': 'https://merlin.example.test', 'recipient': 'age1fixture'}
    store.configure('peers', [peer])
    state = client.get('/api/connections').json()
    assert state['ghostwriter']['status'] == 'verified'
    assert state['peers'][0]['status'] == 'enrolled'


def test_upload_listing_routes_accept_the_authenticated_request(client):
    assert client.get('/api/uploads').status_code == 200
    assert client.get('/api/evidence').status_code == 200
    if APP_NAME == 'Merlin':
        assert client.get('/api/deliveries').status_code == 200


def test_tester_cannot_use_host_transfer_operations(client, store):
    store = client.app.state.store
    add_user(store, 'limited-user', 'tester', 'synthetic-limited-password', APP_NAME)
    limited = TestClient(client.app, base_url='http://127.0.0.1:8710', headers={'Origin': 'http://127.0.0.1:8710'})
    login = limited.post('/api/login', json={'name': 'limited-user', 'password': 'synthetic-limited-password'})
    limited.headers['X-CSRF-Token'] = login.json()['csrf']
    record_id, recipient_id = str(uuid.uuid4()), str(uuid.uuid4())
    body = {'record_ids': [record_id], 'recipient_id': recipient_id, 'review_hash': 'a' * 64}
    assert limited.post('/api/transfers/preview', json={
        'record_ids': [record_id], 'recipient_id': recipient_id,
    }).status_code == 403
    assert limited.post('/api/transfers/export', json=body).status_code == 403
    assert limited.post('/api/transfers/send', json=body).status_code == 403
    assert limited.post('/api/transfers/import', files={'file': ('fixture.age', b'fixture', 'application/octet-stream')}).status_code == 403
    assert limited.get('/api/transfers/conflicts').status_code == 403
    assert limited.post(f'/api/transfers/conflicts/{record_id}/resolve', json={
        'decision': 'keep_local', 'conflict_revision_id': str(uuid.uuid4()),
        'manifest_hash': 'a' * 64, 'local_revisions': {},
    }).status_code == 403
    with store.tx() as connection:
        conflict = store.put(connection, 'transfer_conflict', {
            'state': 'needs_review', 'incoming': [{'data': {'restricted': True}}],
            'local_at_conflict': [], 'encrypted_bundle': 'restricted.age',
        }, 'fixture')
        store.event(connection, 'fixture', 'transfer.conflict_fixture', [conflict['id']])
    assert limited.get('/api/records?kind=transfer_conflict').status_code == 403
    assert limited.get('/api/records/' + conflict['id']).status_code == 403
    assert limited.get('/api/records/' + conflict['id'] + '/revisions').status_code == 403
    visible = limited.get('/api/records').json()
    assert conflict['id'] not in {item['id'] for item in visible['items']}
    assert visible['total'] == len(visible['items'])


def test_peer_origin_is_accepted_only_for_the_encrypted_inbox(tmp_path):
    engagement = str(uuid.uuid4())
    peer_store = initialize(
        tmp_path / 'peer-state', 'http://127.0.0.1:8710', 'Synthetic',
        engagement_id=engagement, peer_origin='http://harbinger:8710',
    )
    sender = initialize(tmp_path / 'sender-state', 'http://127.0.0.1:8711', 'Synthetic', engagement_id=engagement)
    sender.configure('config', {**sender.setting('config'), 'app': 'Merlin'})
    for value in (peer_store, sender):
        provision_keys(value)
    for receiver, source in ((peer_store, sender), (sender, peer_store)):
        card = public_card(source)
        enroll(receiver, card, digest(card))
    app = create_app(peer_store.root)
    peer = TestClient(app, base_url='http://harbinger:8710')
    assert peer.post('/peer/inbox', content=b'invalid synthetic bundle').status_code == 401
    headers = peer_http_headers(sender, sender.setting('peers')[0], b'invalid synthetic bundle')
    assert peer.post('/peer/inbox', content=b'invalid synthetic bundle', headers=headers).status_code == 422
    body = b'synthetic request digest A'
    mismatch_headers = peer_http_headers(sender, sender.setting('peers')[0], body)
    mismatch = peer.post('/peer/inbox', content=b'synthetic request digest B', headers=mismatch_headers)
    assert mismatch.status_code == 422
    assert mismatch.json()['detail'] == 'The peer request body did not match its signed headers.'
    assert peer.get('/api/session').status_code == 400


def test_login_throttle(client):
    for _ in range(5):
        assert client.post('/api/login', json={'name': 'host', 'password': 'incorrect'}).status_code == 401
    assert client.post('/api/login', json={'name': 'host', 'password': 'incorrect'}).status_code == 429


def test_no_arbitrary_execution_routes(client):
    for path in ('/api/exec', '/api/shell', '/api/scan', '/api/ai', '/api/tools/register'):
        assert client.post(path, json={'command': 'untrusted target instruction'}).status_code == 404


def test_api_revision_conflict(client):
    kind = 'finding' if APP_NAME == 'Harbinger' else 'draft'
    data = {'title': 'Synthetic finding'}
    if kind == 'finding':
        data['observation'] = 'A tester note'
    first = client.post('/api/records', json={'kind': kind, 'data': data}).json()
    updated = {**first['data'], 'title': 'Changed title'}
    assert client.put('/api/records/' + first['id'], json={'base_revision_id': first['revision_id'], 'data': updated}).status_code == 200
    stale = client.put('/api/records/' + first['id'], json={'base_revision_id': first['revision_id'], 'data': data})
    assert stale.status_code == 409
    assert stale.json()['detail']['current']['data']['title'] == 'Changed title'
    assert len(client.get('/api/records/' + first['id'] + '/revisions').json()['items']) == 2


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns upload parsing')
def test_upload_contained_merge_flow(client, store):
    response = client.post('/api/uploads', data={'format': 'nmap_xml'}, files={'file': ('synthetic.xml', NMAP, 'application/xml')})
    assert response.status_code == 200
    id = response.json()['id']
    assert client.get('/api/assets').json()['total'] == 0
    assert client.post(f'/api/uploads/{id}/merge').status_code == 422
    parsed = client.post(f'/api/uploads/{id}/parse')
    assert parsed.status_code == 200, parsed.text
    preview = client.get(f'/api/uploads/{id}/preview').json()
    assert preview['complete']
    assert set(preview['_review']) == {'upload_revision_id', 'preview_revision_id', 'preview_hash'}
    assert client.get('/api/assets').json()['total'] == 0
    assert client.post(f'/api/uploads/{id}/merge', json=preview['_review']).status_code == 200
    assert client.get('/api/assets').json()['total'] == 3
    assert client.post(f'/api/uploads/{id}/merge', json=preview['_review']).status_code == 200
    duplicate = client.post('/api/uploads', data={'format': 'nmap_xml'}, files={'file': ('copy.xml', NMAP, 'application/xml')})
    assert duplicate.json()['id'] == id
    assert store.verify()['events'] > 4


def test_merge_rejects_artifact_changed_after_parse(client):
    store = client.app.state.store
    response = client.post('/api/uploads', data={'format': 'nmap_xml'}, files={'file': ('synthetic.xml', NMAP, 'application/xml')})
    upload_id = response.json()['id']
    assert client.post(f'/api/uploads/{upload_id}/parse').status_code == 200
    preview = client.get(f'/api/uploads/{upload_id}/preview').json()
    upload = store.get(upload_id)
    artifact = store.root / 'artifacts' / upload['data']['artifact_id']
    artifact.write_bytes(b'X' * len(NMAP))
    merged = client.post(f'/api/uploads/{upload_id}/merge', json=preview['_review'])
    assert merged.status_code == 503
    assert 'Evidence integrity failed' in merged.json()['detail']
    assert store.get(upload_id)['data']['status'] == 'preview'
    assert client.get('/api/assets').status_code == 200
    assert client.get('/api/assets').json()['total'] == 0


@pytest.mark.parametrize('view', ['preview', 'download'])
def test_evidence_views_fail_closed_after_artifact_tampering(client, view):
    store = client.app.state.store
    evidence_id = str(uuid.uuid4())
    original = b'synthetic evidence text\n'
    artifact = store.root / 'artifacts' / evidence_id
    artifact.write_bytes(original)
    artifact.chmod(0o600)
    import hashlib
    with store.tx() as connection:
        store.put(connection, 'upload', {
            'filename': 'evidence.txt', 'format': 'manual_json', 'status': 'merged',
            'sha256': hashlib.sha256(original).hexdigest(), 'size': len(original),
            'artifact_id': evidence_id, 'quarantined': False, 'limitations': [],
            'reviewed_for_export': True,
        }, 'fixture', evidence_id)
        store.event(connection, 'fixture', 'evidence.fixture_created', [evidence_id])

    first = client.get(f'/api/evidence/{evidence_id}/{view}')
    assert first.status_code == 200
    if view == 'download':
        assert first.content == original
    artifact.write_bytes(b'changed after it was recorded\n')
    event_count = store.verify()['events']
    response = client.get(f'/api/evidence/{evidence_id}/{view}')
    assert response.status_code == 503
    assert 'Evidence integrity failed' in response.json()['detail']
    assert store.blocked and store.verify()['events'] == event_count


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns parser dispatch')
def test_stale_parser_completion_cannot_replace_newer_state(client, store, monkeypatch):
    store = client.app.state.store
    response = client.post('/api/uploads', data={'format': 'nmap_xml'}, files={'file': ('synthetic.xml', NMAP, 'application/xml')})
    upload_id = response.json()['id']
    started = threading.Event()
    release = threading.Event()

    def delayed_parser(path, format):
        started.set()
        assert release.wait(5)
        return parse(path.read_bytes(), format)

    monkeypatch.setattr('workspace.server.run_parser', delayed_parser)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(client.post, f'/api/uploads/{upload_id}/parse')
        assert started.wait(5)
        with store.tx() as connection:
            current = store.get(upload_id, connection)
            store.put(connection, 'upload', {**current['data'], 'status': 'needs_review'}, 'recovery', upload_id, current['revision_id'])
            store.event(connection, 'recovery', 'parser.state_reviewed', [upload_id])
        release.set()
        assert future.result().status_code == 409
    assert store.get(upload_id)['data']['status'] == 'needs_review'


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns finding evidence state')
def test_tester_cannot_create_confirmed_finding(client, store):
    store = client.app.state.store
    add_user(store, 'tester', 'tester', 'synthetic-tester-password', APP_NAME)
    tester = TestClient(client.app, base_url='http://127.0.0.1:8710', headers={'Origin': 'http://127.0.0.1:8710'})
    login = tester.post('/api/login', json={'name': 'tester', 'password': 'synthetic-tester-password'})
    tester.headers['X-CSRF-Token'] = login.json()['csrf']
    result = tester.post('/api/records', json={'kind': 'finding', 'data': {
        'title': 'Synthetic candidate',
        'observation': 'A fixture produced this observation.',
        'evidence_state': 'confirmed',
    }})
    assert result.status_code == 403


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns captain evidence confirmation')
def test_tester_cannot_edit_or_downgrade_a_confirmed_finding(client, store):
    store = client.app.state.store
    tester_id = add_user(store, 'tester', 'tester', 'synthetic-tester-password', APP_NAME)
    confirmed = client.post('/api/records', json={'kind': 'finding', 'data': {
        'title': 'Captain confirmed', 'observation': 'Fixture evidence was reviewed.',
        'evidence_state': 'confirmed', 'owner_id': tester_id,
    }}).json()
    tester = TestClient(client.app, base_url='http://127.0.0.1:8710', headers={'Origin': 'http://127.0.0.1:8710'})
    login = tester.post('/api/login', json={'name': 'tester', 'password': 'synthetic-tester-password'})
    tester.headers['X-CSRF-Token'] = login.json()['csrf']
    for evidence_state in ('confirmed', 'observed'):
        edited = tester.put('/api/records/' + confirmed['id'], json={
            'base_revision_id': confirmed['revision_id'],
            'data': {**confirmed['data'], 'observation': 'Unreviewed replacement', 'evidence_state': evidence_state},
        })
        assert edited.status_code == 403
    assert store.get(confirmed['id'])['revision_id'] == confirmed['revision_id']


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns lead submission')
def test_submitted_state_requires_submission_and_edits_reopen_for_review(client, store):
    store = client.app.state.store
    forged = client.post('/api/records', json={'kind': 'finding', 'data': {
        'title': 'Forged submission', 'observation': 'Fixture', 'writing_state': 'submitted',
    }})
    assert forged.status_code == 403
    created = client.post('/api/records', json={'kind': 'finding', 'data': {
        'title': 'Normal draft', 'observation': 'Fixture', 'writing_state': 'draft',
    }}).json()
    forged_edit = client.put('/api/records/' + created['id'], json={
        'base_revision_id': created['revision_id'], 'data': {**created['data'], 'writing_state': 'submitted'},
    })
    assert forged_edit.status_code == 403
    with store.tx() as connection:
        submitted = store.put(connection, 'finding', {**created['data'], 'writing_state': 'submitted'}, 'fixture', created['id'], created['revision_id'])
        store.event(connection, 'fixture', 'finding.fixture_submitted', [created['id']])
    reopened = client.put('/api/records/' + created['id'], json={
        'base_revision_id': submitted['revision_id'],
        'data': {**submitted['data'], 'observation': 'New evidence was added.'},
    })
    assert reopened.status_code == 200
    assert reopened.json()['data']['writing_state'] == 'ready'


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns lead submission')
def test_lead_submission_persists_state_and_is_idempotent(client, store):
    store = client.app.state.store
    with store.tx() as connection:
        asset = store.put(connection, 'asset', {'label': 'Fixture host', 'kind': 'host', 'track': 'network'}, 'fixture')
        store.event(connection, 'fixture', 'asset.fixture_created', [asset['id']])
    finding = client.post('/api/records', json={'kind': 'finding', 'data': {
        'title': 'Synthetic lead',
        'observation': 'A controlled fixture exposed this condition.',
        'asset_ids': [asset['id']],
        'evidence_needed': 'A screenshot is pending.',
        'writing_state': 'ready',
    }}).json()
    first = client.post('/api/findings/' + finding['id'] + '/submit', json={'base_revision_id': finding['revision_id']})
    assert first.status_code == 200
    current = client.get('/api/records/' + finding['id']).json()
    assert current['data']['writing_state'] == 'submitted'
    assert first.json()['data']['finding_revision_id'] == current['revision_id']
    second = client.post('/api/findings/' + finding['id'] + '/submit', json={'base_revision_id': finding['revision_id']})
    assert second.status_code == 200
    assert second.json()['id'] == first.json()['id']


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns review bindings')
def test_review_bindings_reject_stale_clients_and_keep_exact_retries_idempotent(client, store):
    second = TestClient(client.app, base_url='http://127.0.0.1:8710', headers={'Origin': 'http://127.0.0.1:8710'})
    login = second.post('/api/login', json={'name': 'host', 'password': 'synthetic-test-password'})
    second.headers['X-CSRF-Token'] = login.json()['csrf']
    uploaded = client.post('/api/uploads', data={'format': 'nmap_xml'}, files={'file': ('synthetic.xml', NMAP, 'application/xml')}).json()
    assert client.post(f"/api/uploads/{uploaded['id']}/parse").status_code == 200
    stale_preview = client.get(f"/api/uploads/{uploaded['id']}/preview").json()
    assert second.post(f"/api/uploads/{uploaded['id']}/parse").status_code == 200
    assert client.post(f"/api/uploads/{uploaded['id']}/merge", json=stale_preview['_review']).status_code == 409
    assert client.get('/api/assets').json()['total'] == 0
    preview = client.get(f"/api/uploads/{uploaded['id']}/preview").json()
    merged = client.post(f"/api/uploads/{uploaded['id']}/merge", json=preview['_review'])
    assert merged.status_code == 200
    retried = client.post(f"/api/uploads/{uploaded['id']}/merge", json=preview['_review'])
    assert retried.status_code == 200 and retried.json()['revision_id'] == merged.json()['revision_id']

    asset_id = client.get('/api/assets').json()['items'][0]['id']
    finding = client.post('/api/records', json={'kind': 'finding', 'data': {
        'title': 'Bound finding', 'observation': 'Synthetic reviewed observation.', 'asset_ids': [asset_id],
        'evidence_needed': 'Synthetic screenshot pending.', 'writing_state': 'ready',
    }}).json()
    changed = second.put('/api/records/' + finding['id'], json={
        'base_revision_id': finding['revision_id'], 'data': {**finding['data'], 'observation': 'A second client changed this saved finding.'},
    })
    assert changed.status_code == 200
    assert client.post('/api/findings/' + finding['id'] + '/submit', json={'base_revision_id': finding['revision_id']}).status_code == 409
    first_lead = client.post('/api/findings/' + finding['id'] + '/submit', json={'base_revision_id': changed.json()['revision_id']})
    assert first_lead.status_code == 200
    exact_lead_retry = client.post('/api/findings/' + finding['id'] + '/submit', json={'base_revision_id': changed.json()['revision_id']})
    assert exact_lead_retry.status_code == 200 and exact_lead_retry.json()['id'] == first_lead.json()['id']

    evidence_preview = client.get(f"/api/evidence/{uploaded['id']}/preview").json()
    assert set(evidence_preview) >= {'base_revision_id', 'artifact_sha256'}
    approved = second.post(f"/api/evidence/{uploaded['id']}/approve-export", json={
        'base_revision_id': evidence_preview['base_revision_id'], 'artifact_sha256': evidence_preview['artifact_sha256'],
    })
    assert approved.status_code == 200
    assert client.post(f"/api/evidence/{uploaded['id']}/approve-export", json={
        'base_revision_id': evidence_preview['base_revision_id'], 'artifact_sha256': evidence_preview['artifact_sha256'],
    }).status_code == 409
    second.close()


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns upload artifact lifecycle')
def test_upload_limit_cleans_partial_artifact(client, store, monkeypatch):
    import workspace.server as server
    real_usage = server.shutil.disk_usage
    calls = 0

    def shrinking_space(path):
        nonlocal calls
        calls += 1
        usage = real_usage(path)
        return usage if calls == 1 else usage._replace(free=0)

    monkeypatch.setattr(server.shutil, 'disk_usage', shrinking_space)
    response = client.post('/api/uploads', data={'format': 'manual_json'}, files={'file': ('synthetic.json', b'x' * (1024 * 1024 + 1), 'application/json')})
    assert response.status_code == 413 and calls >= 2
    assert not store.records('upload') and not list((store.root / 'artifacts').iterdir())


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns upload artifact lifecycle')
def test_upload_commit_failure_cleans_written_artifact(client, store, monkeypatch):
    app_store = client.app.state.store
    original_put = app_store.put

    def fail_upload(*args, **kwargs):
        if args[1] == 'upload':
            raise OSError('synthetic post-write failure')
        return original_put(*args, **kwargs)

    monkeypatch.setattr(app_store, 'put', fail_upload)
    with pytest.raises(OSError, match='synthetic post-write failure'):
        client.post('/api/uploads', data={'format': 'manual_json'}, files={'file': ('synthetic.json', b'{}', 'application/json')})
    assert not store.records('upload') and not list((store.root / 'artifacts').iterdir())


def test_evidence_question_creation_matches_application_ownership(client, store):
    store = client.app.state.store
    with store.tx() as connection:
        finding = store.put(connection, 'finding', {'title': 'Synthetic transferred finding'}, 'fixture')
        store.event(connection, 'fixture', 'finding.fixture_created', [finding['id']])
    response = client.post('/api/questions', json={
        'finding_id': finding['id'],
        'text': 'Please confirm the synthetic evidence source.',
    })
    if APP_NAME == 'Merlin':
        assert response.status_code == 200
        assert response.json()['kind'] == 'question'
    else:
        assert response.status_code == 403
        assert not store.records('question')


def test_markdown_blocks_html_and_images():
    from workspace.ghostwriter import html
    output = html('<script>alert(1)</script>\n\n![outside](https://outside.invalid/image)')
    assert '<script>' not in output and '<img' not in output


def test_clock_jump_does_not_reorder_sequences(store, monkeypatch):
    import workspace.store as module
    monkeypatch.setattr(module, 'utc', lambda: '2000-01-01T00:00:00.000000Z')
    store.configure('clock-jump', True)
    assert store.verify()['events'] == 2
