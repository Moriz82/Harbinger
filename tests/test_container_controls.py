import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from workspace import APP_NAME
from workspace.auth import add_user
from workspace.cli import backup, encrypted_storage, initialize, restore
from workspace.isolation import queue_parser
from workspace.parser_service import atomic_file, file_sha256, inspect_queue, serve
from workspace.server import create_app
from workspace.store import Store
from workspace.transfer import enroll, peer_http_headers, provision_keys, public_card


NMAP = b'<nmaprun><host><address addr="192.0.2.44" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'


def test_parser_result_is_published_only_after_complete_short_writes(tmp_path, monkeypatch):
    target = tmp_path / 'job.response'
    payload = b'{"complete":true,"records":[' + b'"fixture",' * 4096 + b'"done"]}'
    real_write = os.write
    real_replace = os.replace
    replace_seen = []

    def short_write(fd, value):
        return real_write(fd, bytes(value[:max(1, len(value) // 3)]))

    def checked_replace(source, destination):
        assert not target.exists()
        assert Path(source).read_bytes() == payload
        replace_seen.append(True)
        return real_replace(source, destination)

    monkeypatch.setattr(os, 'write', short_write)
    monkeypatch.setattr(os, 'replace', checked_replace)
    atomic_file(target, payload)
    assert replace_seen == [True]
    assert target.read_bytes() == payload


def test_failed_parser_publication_leaves_no_final_or_temporary_file(tmp_path, monkeypatch):
    target = tmp_path / 'job.response'
    monkeypatch.setattr(os, 'fsync', lambda _fd: (_ for _ in ()).throw(OSError('fixture fsync failure')))
    with pytest.raises(OSError):
        atomic_file(target, b'partial fixture')
    assert not target.exists()
    assert not list(tmp_path.iterdir())


def test_parser_healthcheck_requires_the_live_parser_and_rejects_unsafe_queue_entries(tmp_path, monkeypatch):
    import workspace.parser_service as service
    queue = tmp_path / 'queue'; queue.mkdir(mode=0o700)
    pid_file = tmp_path / 'parser.pid'
    monkeypatch.setattr(service, 'HEALTH_PID_FILE', pid_file)
    assert service.healthy(queue) is False
    pid_file.write_text('1234')
    monkeypatch.setattr(service, '_parser_process_alive', lambda pid: pid == 1234)
    assert service.healthy(queue) is True
    (queue / 'unexpected').write_text('synthetic fixture')
    assert service.healthy(queue) is False


def test_parser_healthcheck_accepts_active_queue_files_for_a_live_parser(tmp_path, monkeypatch):
    import workspace.parser_service as service
    queue = tmp_path / 'queue'; queue.mkdir(mode=0o700)
    job = str(uuid.uuid4())
    (queue / f'{job}.input').write_bytes(b'synthetic active input')
    (queue / f'{job}.request').write_text('{"synthetic":"active"}')
    pid_file = tmp_path / 'parser.pid'
    pid_file.write_text('1234')
    monkeypatch.setattr(service, 'HEALTH_PID_FILE', pid_file)
    monkeypatch.setattr(service, '_parser_process_alive', lambda pid: pid == 1234)
    assert inspect_queue(queue)['recovery_required'] is True
    assert service.healthy(queue) is True


def test_parser_healthcheck_rejects_recovery_required_entry_beyond_metadata_cap(tmp_path, monkeypatch):
    import workspace.parser_service as service
    queue = tmp_path / 'queue'; queue.mkdir(mode=0o700)
    for value in range(1, 65):
        (queue / f'{uuid.UUID(int=value)}.error').write_text('closed synthetic receipt\n')
    (queue / 'zz-unsafe').write_text('synthetic fixture')
    state = inspect_queue(queue)
    assert state['truncated'] is True
    assert state['recovery_required'] is True
    assert all(entry['kind'] == 'error' for entry in state['entries'])
    pid_file = tmp_path / 'parser.pid'
    pid_file.write_text('1234')
    monkeypatch.setattr(service, 'HEALTH_PID_FILE', pid_file)
    monkeypatch.setattr(service, '_parser_process_alive', lambda pid: pid == 1234)
    assert service.healthy(queue) is False


def test_parser_healthcheck_command_requires_a_live_service(tmp_path):
    queue = tmp_path / 'queue'; queue.mkdir(mode=0o700)
    project = Path(__file__).resolve().parents[1]
    process = subprocess.Popen(
        [sys.executable, '-B', '-m', 'workspace.parser_service', str(queue)],
        cwd=project,
        env={**os.environ, 'PYTHONPATH': str(project)},
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and process.poll() is None:
            health = subprocess.run(
                [sys.executable, '-B', '-m', 'workspace.parser_service', '--healthcheck', str(queue)],
                cwd=project, env={**os.environ, 'PYTHONPATH': str(project)},
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if health.returncode == 0:
                break
            time.sleep(0.05)
        assert process.poll() is None and health.returncode == 0
    finally:
        process.terminate()
        process.wait(timeout=5)
    assert subprocess.run(
        [sys.executable, '-B', '-m', 'workspace.parser_service', '--healthcheck', str(queue)],
        cwd=project, env={**os.environ, 'PYTHONPATH': str(project)},
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 1


def test_app_health_endpoint_is_available_without_a_session(store):
    app = create_app(store.root)
    response = TestClient(app, base_url='http://127.0.0.1:8710').get('/healthz')
    assert response.status_code == 200
    assert response.json() == {'status': 'ok'}


@pytest.fixture
def store(tmp_path):
    return initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic practice', engagement_id='00000000-0000-4000-8000-000000000001')


@pytest.fixture
def client(store):
    role = 'captain' if APP_NAME == 'Harbinger' else 'lead_scribe'
    add_user(store, 'host', role, 'synthetic-test-password', APP_NAME)
    value = TestClient(create_app(store.root), base_url='http://127.0.0.1:8710', headers={'Origin': 'http://127.0.0.1:8710'})
    response = value.post('/api/login', json={'name': 'host', 'password': 'synthetic-test-password'})
    assert response.status_code == 200
    value.headers['X-CSRF-Token'] = response.json()['csrf']
    with value:
        yield value


def audit_operations(store):
    return [json.loads(line)['body']['operation'] for line in (store.root / 'audit.jsonl').read_text().splitlines()]


def install_evidence(store, body, filename, *, reviewed=True, quarantined=False):
    evidence_id = str(uuid.uuid4())
    artifact = store.root / 'artifacts' / evidence_id
    artifact.write_bytes(body)
    artifact.chmod(0o600)
    with store.tx() as connection:
        item = store.put(connection, 'upload', {
            'filename': filename, 'format': 'manual_json', 'status': 'merged',
            'sha256': hashlib.sha256(body).hexdigest(), 'size': len(body),
            'artifact_id': evidence_id, 'quarantined': quarantined, 'limitations': [],
            'reviewed_for_export': reviewed,
        }, 'fixture', evidence_id)
        store.event(connection, 'fixture', 'evidence.fixture_created', [evidence_id])
    return item


def test_inline_evidence_images_require_review_and_safe_local_bytes(client, store):
    store = client.app.state.store
    png = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Zl1sAAAAASUVORK5CYII=')
    approved = install_evidence(store, png, 'fixture.png')
    rendered = client.get(f"/api/evidence/{approved['id']}/render")
    assert rendered.status_code == 200
    assert rendered.content == png
    assert rendered.headers['content-type'] == 'image/png'
    assert rendered.headers['content-disposition'].startswith('inline;')
    assert rendered.headers['x-content-type-options'] == 'nosniff'
    assert audit_operations(store)[-1] == 'evidence.rendered'

    pending = install_evidence(store, png, 'pending.png', reviewed=False)
    assert client.get(f"/api/evidence/{pending['id']}/render").status_code == 409
    svg = install_evidence(store, b'<svg xmlns="http://www.w3.org/2000/svg"><script>fixture</script></svg>', 'blocked.svg')
    assert client.get(f"/api/evidence/{svg['id']}/render").status_code == 415

    anonymous = TestClient(client.app, base_url='http://127.0.0.1:8710', headers={'Origin': 'http://127.0.0.1:8710'})
    assert anonymous.get(f"/api/evidence/{approved['id']}/render").status_code == 401


def test_evidence_preview_reports_byte_identified_inline_image_eligibility(client, store):
    store = client.app.state.store
    png = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Zl1sAAAAASUVORK5CYII=')
    before = audit_operations(store).count('evidence.rendered')

    approved_png = install_evidence(store, png, 'misleading.txt')
    preview = client.get(f"/api/evidence/{approved_png['id']}/preview")
    assert preview.status_code == 200
    assert preview.json()['inline_image_media_type'] == 'image/png'

    mislabeled_text = install_evidence(store, b'synthetic text only', 'misleading.png')
    assert client.get(f"/api/evidence/{mislabeled_text['id']}/preview").json()['inline_image_media_type'] is None

    unsupported_webp = install_evidence(store, b'RIFF\x10\x00\x00\x00WEBPVP8 synthetic', 'fixture.webp')
    assert client.get(f"/api/evidence/{unsupported_webp['id']}/preview").json()['inline_image_media_type'] is None

    pending_png = install_evidence(store, png, 'pending.png', reviewed=False)
    assert client.get(f"/api/evidence/{pending_png['id']}/preview").json()['inline_image_media_type'] is None

    quarantined_png = install_evidence(store, png, 'quarantined.png', quarantined=True)
    assert client.get(f"/api/evidence/{quarantined_png['id']}/preview").json()['inline_image_media_type'] is None
    assert audit_operations(store).count('evidence.rendered') == before


def test_container_storage_marker_is_private_and_typed(tmp_path, monkeypatch):
    monkeypatch.setenv('CONTAINERIZED', '1')
    marker = tmp_path / '.storage-verified.json'
    marker.write_text(json.dumps({'encrypted': True, 'schema_version': 1, 'verified_at': '2026-09-08T00:00:00.000000Z'}))
    marker.chmod(0o600)
    assert encrypted_storage(tmp_path)
    marker.chmod(0o644)
    assert not encrypted_storage(tmp_path)


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Only Harbinger runs an import parser')
def test_parser_queue_roundtrip_and_cleanup(tmp_path):
    queue = tmp_path / 'queue'
    queue.mkdir(mode=0o700)
    source = tmp_path / 'input.xml'
    source.write_bytes(NMAP)
    project = Path(__file__).resolve().parents[1]
    process = subprocess.Popen(
        [sys.executable, '-B', '-m', 'workspace.parser_service', str(queue)],
        cwd=project,
        env={'PATH': os.environ.get('PATH', '/usr/bin'), 'PYTHONPATH': str(project)},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        time.sleep(0.2)
        assert process.poll() is None
        result = queue_parser(source, 'nmap_xml', queue)
        assert result['complete'] is True
        assert any(item['label'] == '192.0.2.44' for item in result['assets'])
        time.sleep(.2)
        assert not list(queue.iterdir())
    finally:
        process.terminate()
        process.wait(timeout=5)


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Only Harbinger runs an import parser')
def test_parser_client_waits_for_service_to_retire_successful_job(tmp_path):
    queue = tmp_path / 'queue'; queue.mkdir(mode=0o700)
    source = tmp_path / 'input.xml'; source.write_bytes(NMAP)
    failures = []

    def parser_service_stub():
        try:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                pending = list(queue.glob('*.request'))
                if pending:
                    break
                time.sleep(.005)
            else:
                raise AssertionError('No parser request arrived')
            running = pending[0].with_suffix('.running')
            pending[0].rename(running)
            atomic_file(running.with_suffix('.response'), json.dumps({
                'assets': [], 'relationships': [], 'observations': [],
                'limitations': [], 'complete': True, 'quarantined': [],
            }).encode())
            time.sleep(.2)
            assert running.exists(), 'Client removed an active parser job'
            running.unlink()
        except Exception as error:
            failures.append(error)

    worker = threading.Thread(target=parser_service_stub, daemon=True)
    worker.start()
    started = time.monotonic()
    result = queue_parser(source, 'nmap_xml', queue)
    elapsed = time.monotonic() - started
    worker.join(timeout=3)
    assert not worker.is_alive() and not failures
    assert result['complete'] is True
    assert elapsed >= .19
    assert not list(queue.iterdir())


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Only Harbinger runs an import parser')
def test_parser_timeout_preserves_request_and_cancel_for_recovery(tmp_path, monkeypatch):
    import workspace.isolation as isolation
    queue = tmp_path / 'queue'; queue.mkdir(mode=0o700)
    source = tmp_path / 'input.xml'; source.write_bytes(NMAP)
    monkeypatch.setattr(isolation, 'PARSER_WAIT_SECONDS', .1)
    with pytest.raises(RuntimeError, match='deadline'):
        queue_parser(source, 'nmap_xml', queue)
    state = inspect_queue(queue)
    assert state['recovery_required']
    assert {entry['kind'] for entry in state['entries']} == {'input', 'request', 'cancel'}


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Only Harbinger runs an import parser')
def test_parser_publish_failure_preserves_uncertain_queue_files(tmp_path, monkeypatch):
    queue = tmp_path / 'queue'; queue.mkdir(mode=0o700)
    source = tmp_path / 'input.xml'; source.write_bytes(NMAP)

    def fail_publish(*_):
        raise OSError('synthetic rename failure')

    monkeypatch.setattr(os, 'replace', fail_publish)
    with pytest.raises(OSError, match='synthetic rename failure'):
        queue_parser(source, 'nmap_xml', queue)
    assert len(list(queue.glob('*.input'))) == 1
    assert len(list(queue.glob('.*.request.tmp'))) == 1
    assert inspect_queue(queue)['recovery_required']


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Only Harbinger runs an import parser')
def test_parser_failure_keeps_terminal_error_receipt(tmp_path):
    queue = tmp_path / 'queue'; queue.mkdir(mode=0o700)
    source = tmp_path / 'input.xml'; source.write_bytes(NMAP)
    failures = []

    def parser_service_stub():
        try:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                pending = list(queue.glob('*.request'))
                if pending:
                    break
                time.sleep(.005)
            else:
                raise AssertionError('No parser request arrived')
            running = pending[0].with_suffix('.running')
            pending[0].rename(running)
            atomic_file(running.with_suffix('.error'), b'The parser did not accept this file. No records were merged.\n')
            running.unlink()
        except Exception as error:
            failures.append(error)

    worker = threading.Thread(target=parser_service_stub, daemon=True)
    worker.start()
    with pytest.raises(RuntimeError, match='did not accept'):
        queue_parser(source, 'nmap_xml', queue)
    worker.join(timeout=3)
    assert not worker.is_alive() and not failures
    state = inspect_queue(queue)
    assert not state['recovery_required']
    assert [entry['kind'] for entry in state['entries']] == ['error']


@pytest.mark.parametrize('subtree,kind', [
    ('artifacts', 'root'), ('conflicts', 'root'), ('exports', 'root'), ('keys', 'root'),
    ('artifacts', 'nested'), ('conflicts', 'nested'), ('exports', 'nested'), ('keys', 'nested'),
])
def test_backup_rejects_symlinks_without_copying_external_fixture_bytes(tmp_path, subtree, kind):
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    external = tmp_path / 'external-secret'; external.write_bytes(b'external synthetic secret')
    target = store.root / subtree
    if kind == 'root':
        target.rmdir(); target.symlink_to(external)
    else:
        (target / 'nested').symlink_to(external)
    destination = tmp_path / 'backup'
    with pytest.raises(ValueError, match='symlink'):
        backup(store, destination)
    assert not destination.exists() and external.read_bytes() == b'external synthetic secret'


@pytest.mark.parametrize('subtree,kind', [
    ('artifacts', 'root'), ('conflicts', 'root'), ('exports', 'root'), ('keys', 'root'),
    ('artifacts', 'nested'), ('conflicts', 'nested'), ('exports', 'nested'), ('keys', 'nested'),
])
def test_restore_rejects_source_symlinks_before_creating_destination(tmp_path, subtree, kind):
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    source = tmp_path / 'backup'; backup(store, source)
    external = tmp_path / 'external-secret'; external.write_bytes(b'external synthetic secret')
    target = source / subtree
    if kind == 'root':
        target.rmdir(); target.symlink_to(external)
    else:
        (target / 'nested').symlink_to(external)
    destination = tmp_path / 'restored'
    with pytest.raises(ValueError, match='symlink'):
        restore(source, destination)
    assert not destination.exists()


def test_restore_rejects_unexpected_empty_backup_directory(tmp_path):
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    source = tmp_path / 'backup'; backup(store, source)
    (source / 'unexpected').mkdir(mode=0o700)
    destination = tmp_path / 'restored'
    with pytest.raises(ValueError, match='file list'):
        restore(source, destination)
    assert not destination.exists()


def test_backup_copy_retries_interrupted_and_short_writes(tmp_path, monkeypatch):
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    real_write = os.write
    calls = 0

    def interrupted_then_short(fd, data):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise InterruptedError
        return real_write(fd, data[:max(1, len(data) // 3)])

    monkeypatch.setattr(os, 'write', interrupted_then_short)
    result = backup(store, tmp_path / 'backup')
    assert result['files'] >= 3 and calls > 3
    assert restore(tmp_path / 'backup', tmp_path / 'restored')['files'] == result['files']


def test_backup_copy_failure_never_publishes_partial_destination(tmp_path, monkeypatch):
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    destination = tmp_path / 'backup'
    monkeypatch.setattr(os, 'write', lambda *_: (_ for _ in ()).throw(OSError('synthetic disk failure')))
    with pytest.raises(OSError, match='synthetic disk failure'):
        backup(store, destination)
    assert not destination.exists()


def test_backup_seals_database_without_sqlite_sidecars(tmp_path):
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    destination = tmp_path / 'backup'
    backup(store, destination)
    assert not (destination / 'workspace.db-wal').exists()
    assert not (destination / 'workspace.db-shm').exists()
    with sqlite3.connect(f'file:{destination / "workspace.db"}?mode=ro&immutable=1', uri=True) as copied:
        assert copied.execute('PRAGMA journal_mode').fetchone()[0].lower() == 'delete'
    assert not (destination / 'workspace.db-wal').exists()
    assert not (destination / 'workspace.db-shm').exists()


def test_default_readonly_store_still_rejects_sqlite_sidecars(tmp_path):
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    (store.root / 'workspace.db-wal').touch(mode=0o600)
    with pytest.raises(RuntimeError, match='sidecar'):
        Store(store.root, readonly=True)


def test_wal_aware_readonly_store_rejects_unsafe_sidecars(tmp_path):
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    external = tmp_path / 'external'; external.write_bytes(b'synthetic')
    (store.root / 'workspace.db-wal').symlink_to(external)
    with pytest.raises(RuntimeError, match='permissions'):
        Store(store.root, readonly=True, wal_aware_readonly=True)


def test_restore_reads_backup_identity_with_immutable_sqlite_uri(tmp_path, monkeypatch):
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    source = tmp_path / 'backup'
    backup(store, source)
    import workspace.cli as cli
    real_connect = cli.sqlite3.connect
    observed = []

    def track_connect(database, *args, **kwargs):
        observed.append((database, kwargs.copy()))
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(cli.sqlite3, 'connect', track_connect)
    restore(source, tmp_path / 'restored')
    assert observed[0] == (f'file:{source.absolute() / "workspace.db"}?mode=ro&immutable=1', {'uri': True})


@pytest.mark.parametrize(('mutation', 'extra_byte'), [('source', b''), ('staged', b'X')])
def test_restore_rejects_changed_bytes_before_publishing(tmp_path, monkeypatch, mutation, extra_byte):
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    source = tmp_path / 'backup'; backup(store, source)
    original = (source / 'audit.jsonl').read_bytes()
    changed = b'X' * len(original) + extra_byte
    import workspace.cli as cli
    copy_regular = cli._copy_regular

    def mutate_copy(source_path, target):
        source_path, target = Path(source_path), Path(target)
        if source_path == source / 'audit.jsonl' and mutation == 'source':
            source_path.write_bytes(changed)
        copy_regular(source_path, target)
        if source_path == source / 'audit.jsonl' and mutation == 'staged':
            target.write_bytes(changed)

    monkeypatch.setattr(cli, '_copy_regular', mutate_copy)
    destination = tmp_path / 'restored'
    with pytest.raises(ValueError, match='restored file failed'):
        restore(source, destination)
    assert not destination.exists()


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Only Harbinger owns the parser queue')
def test_parser_service_refuses_stale_running_job_and_preserves_every_fixture_byte(tmp_path):
    queue = tmp_path / 'queue'; queue.mkdir(mode=0o700)
    job = str(uuid.uuid4()); raw = b'raw synthetic parser input that must remain private'
    source = queue / f'{job}.input'; source.write_bytes(raw)
    request = {'schema_version': 1, 'job_id': job, 'format': 'nmap_xml', 'sha256': file_sha256(source), 'size': len(raw)}
    running = queue / f'{job}.running'; running.write_text(json.dumps(request)); running.chmod(0o600)
    import workspace.parser_service as service
    service.STOP = True
    try:
        with pytest.raises(RuntimeError, match='recovery'):
            serve(queue)
    finally:
        service.STOP = False
    assert source.read_bytes() == raw and running.read_text() == json.dumps(request)
    assert not (queue / f'{job}.error').exists()


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Only Harbinger owns the parser queue')
def test_parser_service_refuses_pending_request_after_restart_without_dispatch(tmp_path, monkeypatch):
    queue = tmp_path / 'queue'; queue.mkdir(mode=0o700)
    job = str(uuid.uuid4()); raw = b'synthetic pending request bytes'
    source = queue / f'{job}.input'; source.write_bytes(raw); source.chmod(0o600)
    request = {'schema_version': 1, 'job_id': job, 'format': 'nmap_xml', 'sha256': file_sha256(source), 'size': len(raw)}
    request_path = queue / f'{job}.request'; request_path.write_text(json.dumps(request)); request_path.chmod(0o600)
    monkeypatch.setattr(subprocess, 'Popen', lambda *_args, **_kwargs: pytest.fail('stale work must not dispatch'))
    with pytest.raises(RuntimeError, match='recovery'):
        serve(queue)
    assert source.read_bytes() == raw and request_path.read_text() == json.dumps(request)


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Only Harbinger owns the parser queue')
def test_parser_queue_inspection_streams_checksums_and_bounds_metadata(tmp_path, monkeypatch):
    queue = tmp_path / 'queue'; queue.mkdir(mode=0o700)
    first = '00000000-0000-4000-8000-000000000001'
    payload = queue / f'{first}.input'; payload.write_bytes(b'synthetic queue bytes'); payload.chmod(0o600)
    for index in range(10):
        path = queue / f'ffffffff-ffff-4fff-8fff-{index:012d}.cancel'; path.write_bytes(b''); path.chmod(0o600)
    monkeypatch.setattr(Path, 'read_bytes', lambda *_: pytest.fail('queue inspection must stream through no-follow descriptors'))
    state = inspect_queue(queue, max_entries=4)
    assert state['total_entries'] == 11 and state['reported_entries'] == 4 and state['truncated'] is True
    assert all(set(item) <= {'job_id', 'name', 'kind', 'size', 'sha256'} for item in state['entries'])
    input_metadata = next(item for item in state['entries'] if item['name'] == f'{first}.input')
    assert input_metadata['sha256'] == hashlib.sha256(b'synthetic queue bytes').hexdigest()


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Only Harbinger owns the parser queue')
def test_parser_queue_recovery_audits_metadata_blocks_mutations_and_refuses_backup(tmp_path):
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    add_user(store, 'host', 'captain', 'synthetic-test-password', APP_NAME)
    queue = store.root / 'parser-queue'; queue.mkdir(mode=0o700)
    job = str(uuid.uuid4()); raw = b'raw synthetic parser input must never be logged'
    source = queue / f'{job}.input'; source.write_bytes(raw)
    request = {'schema_version': 1, 'job_id': job, 'format': 'nmap_xml', 'sha256': file_sha256(source), 'size': len(raw)}
    (queue / f'{job}.running').write_text(json.dumps(request))
    app = create_app(store.root)
    assert app.state.store.blocked == 'Parser recovery is required. Preserve the queue and inspect the listed jobs.'
    audit = (store.root / 'audit.jsonl').read_text()
    assert 'parser.recovery_required' in audit and job in audit and request['sha256'] in audit and raw.decode() not in audit
    client = TestClient(app, base_url='http://127.0.0.1:8710', headers={'Origin': 'http://127.0.0.1:8710'})
    assert client.post('/api/login', json={'name': 'host', 'password': 'synthetic-test-password'}).status_code == 503
    with pytest.raises(RuntimeError, match='parser queue'):
        backup(store, tmp_path / 'backup')
    assert source.read_bytes() == raw and (queue / f'{job}.running').exists()


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns parser recovery')
def test_closed_parser_receipts_remain_visible_without_blocking_restart(tmp_path):
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    queue = store.root / 'parser-queue'; queue.mkdir(mode=0o700)
    response_job = str(uuid.uuid4())
    error_job = str(uuid.uuid4())
    response = {'assets': [], 'relationships': [], 'observations': [], 'limitations': [], 'complete': True, 'quarantined': []}
    (queue / f'{response_job}.response').write_text(json.dumps(response))
    (queue / f'{error_job}.error').write_text('synthetic closed receipt\n')
    state = inspect_queue(queue)
    assert state['total_entries'] == 2 and state['recovery_required'] is False
    app = create_app(store.root)
    assert app.state.store.blocked is None
    assert 'parser.recovery_required' not in (store.root / 'audit.jsonl').read_text()
    import workspace.parser_service as service
    service.STOP = True
    try:
        serve(queue)
    finally:
        service.STOP = False
    assert (queue / f'{response_job}.response').exists() and (queue / f'{error_job}.error').exists()


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns parser recovery')
def test_reviewed_closed_parser_receipt_can_be_acknowledged_before_backup(tmp_path, monkeypatch):
    from workspace.parser_service import acknowledge_receipt
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    queue = store.root / 'parser-queue'; queue.mkdir(mode=0o700)
    job = str(uuid.uuid4())
    body = b'synthetic reviewed closed receipt\n'
    path = queue / f'{job}.error'; path.write_bytes(body); path.chmod(0o600)
    checksum = hashlib.sha256(body).hexdigest()
    archive = store.root / 'artifacts' / 'parser-receipts'
    fsynced_directories = []
    original_fsync = os.fsync

    def record_fsync(fd):
        target = Path(os.readlink(f'/proc/self/fd/{fd}'))
        if target.is_dir():
            fsynced_directories.append(target)
        return original_fsync(fd)

    monkeypatch.setattr(os, 'fsync', record_fsync)

    with pytest.raises(ValueError, match='Only closed'):
        acknowledge_receipt(queue, archive, job, 'input', checksum)
    with pytest.raises(ValueError, match='checksum changed'):
        acknowledge_receipt(queue, archive, job, 'error', '0' * 64)
    assert path.read_bytes() == body

    receipt = acknowledge_receipt(queue, archive, job, 'error', checksum)
    assert receipt == {'job_id': job, 'kind': 'error', 'size': len(body), 'sha256': checksum, 'already_archived': False}
    assert not path.exists()
    assert (archive / path.name).read_bytes() == body
    assert store.root / 'artifacts' in fsynced_directories
    assert queue in fsynced_directories and archive in fsynced_directories
    assert acknowledge_receipt(queue, archive, job, 'error', checksum)['already_archived'] is True
    assert backup(store, tmp_path / 'backup')['files'] >= 3


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns parser recovery')
def test_parser_ack_cli_audits_intent_before_removing_reviewed_receipt(tmp_path):
    import sys
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    queue = store.root / 'parser-queue'; queue.mkdir(mode=0o700)
    job = str(uuid.uuid4())
    body = b'synthetic reviewed response receipt\n'
    path = queue / f'{job}.response'; path.write_bytes(body); path.chmod(0o600)
    checksum = hashlib.sha256(body).hexdigest()

    result = subprocess.run([
        sys.executable, '-m', 'workspace.cli', '--workspace', str(store.root),
        'parser-ack', job, '--kind', 'response', '--sha256', checksum,
    ], text=True, capture_output=True)

    assert result.returncode == 0 and not path.exists()
    assert (store.root / 'artifacts' / 'parser-receipts' / path.name).read_bytes() == body
    audit = (store.root / 'audit.jsonl').read_text()
    assert audit.index('parser.receipt_acknowledgement_requested') < audit.index('parser.receipt_acknowledged')
    assert job in audit and checksum in audit and body.decode().strip() not in audit


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns parser recovery')
def test_parser_ack_completion_failure_preserves_and_reconciles_archived_receipt(tmp_path, monkeypatch):
    from workspace.cli import acknowledge_parser_receipt
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    queue = store.root / 'parser-queue'; queue.mkdir(mode=0o700)
    job = str(uuid.uuid4())
    body = b'synthetic crash-safe response receipt\n'
    path = queue / f'{job}.response'; path.write_bytes(body); path.chmod(0o600)
    checksum = hashlib.sha256(body).hexdigest()
    original_event = store.event

    def fail_completion(connection, actor, operation, ids, **details):
        if operation == 'parser.receipt_acknowledged':
            raise OSError('synthetic completion audit failure')
        return original_event(connection, actor, operation, ids, **details)

    monkeypatch.setattr(store, 'event', fail_completion)
    with pytest.raises(RuntimeError, match='completion event failed'):
        acknowledge_parser_receipt(store, job, 'response', checksum)

    archived = store.root / 'artifacts' / 'parser-receipts' / path.name
    assert not path.exists() and archived.read_bytes() == body
    audit = (store.root / 'audit.jsonl').read_text()
    assert 'parser.receipt_acknowledgement_requested' in audit
    assert 'parser.receipt_acknowledged' not in audit

    recovered = Store(store.root)
    receipt = acknowledge_parser_receipt(recovered, job, 'response', checksum)
    assert receipt['already_archived'] is True and archived.read_bytes() == body
    audit = (store.root / 'audit.jsonl').read_text()
    assert 'parser.receipt_acknowledged' in audit
    assert backup(recovered, tmp_path / 'recovered-backup')['files'] >= 4


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns parser recovery')
def test_parser_ack_reconciles_completion_appended_before_database_commit_failure(tmp_path, monkeypatch):
    from workspace.cli import acknowledge_parser_receipt
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    queue = store.root / 'parser-queue'; queue.mkdir(mode=0o700)
    job = str(uuid.uuid4())
    body = b'synthetic post-append interruption receipt\n'
    path = queue / f'{job}.response'; path.write_bytes(body); path.chmod(0o600)
    checksum = hashlib.sha256(body).hexdigest()
    original_event = store.event

    def fail_after_completion_append(connection, actor, operation, ids, **details):
        result = original_event(connection, actor, operation, ids, **details)
        if operation == 'parser.receipt_acknowledged':
            raise OSError('synthetic interruption after completion audit append')
        return result

    monkeypatch.setattr(store, 'event', fail_after_completion_append)
    with pytest.raises(RuntimeError, match='completion event failed'):
        acknowledge_parser_receipt(store, job, 'response', checksum)

    archived = store.root / 'artifacts' / 'parser-receipts' / path.name
    assert not path.exists() and archived.read_bytes() == body
    recovered = Store(store.root)
    assert recovered.blocked == 'Audit integrity check failed. Preserve the workspace and inspect it.'

    receipt = acknowledge_parser_receipt(recovered, job, 'response', checksum)
    assert receipt['already_archived'] is True and recovered.blocked is None
    assert archived.read_bytes() == body
    assert recovered.verify()['events'] >= 2
    audit = (store.root / 'audit.jsonl').read_text()
    assert audit.count('parser.receipt_acknowledgement_requested') == 1
    assert audit.count('parser.receipt_acknowledged') == 1
    assert backup(recovered, tmp_path / 'post-append-backup')['files'] >= 4


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns parser recovery')
def test_parser_ack_reconciles_request_appended_before_database_commit_failure(tmp_path, monkeypatch):
    from workspace.cli import acknowledge_parser_receipt
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    queue = store.root / 'parser-queue'; queue.mkdir(mode=0o700)
    job = str(uuid.uuid4())
    body = b'synthetic request interruption receipt\n'
    path = queue / f'{job}.error'; path.write_bytes(body); path.chmod(0o600)
    checksum = hashlib.sha256(body).hexdigest()
    original_event = store.event

    def fail_after_request_append(connection, actor, operation, ids, **details):
        result = original_event(connection, actor, operation, ids, **details)
        if operation == 'parser.receipt_acknowledgement_requested':
            raise OSError('synthetic interruption after request audit append')
        return result

    monkeypatch.setattr(store, 'event', fail_after_request_append)
    with pytest.raises(OSError, match='request audit append'):
        acknowledge_parser_receipt(store, job, 'error', checksum)

    assert path.read_bytes() == body
    recovered = Store(store.root)
    assert recovered.blocked == 'Audit integrity check failed. Preserve the workspace and inspect it.'

    receipt = acknowledge_parser_receipt(recovered, job, 'error', checksum)
    archived = store.root / 'artifacts' / 'parser-receipts' / path.name
    assert receipt['already_archived'] is False and recovered.blocked is None
    assert not path.exists() and archived.read_bytes() == body
    assert recovered.verify()['events'] >= 2
    audit = (store.root / 'audit.jsonl').read_text()
    assert audit.count('parser.receipt_acknowledgement_requested') == 1
    assert audit.count('parser.receipt_acknowledged') == 1


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns parser recovery')
def test_parser_ack_reconciles_repeat_request_tail_for_archived_receipt(tmp_path, monkeypatch):
    from workspace.cli import acknowledge_parser_receipt
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    queue = store.root / 'parser-queue'; queue.mkdir(mode=0o700)
    job = str(uuid.uuid4())
    body = b'synthetic repeated acknowledgement receipt\n'
    path = queue / f'{job}.response'; path.write_bytes(body); path.chmod(0o600)
    checksum = hashlib.sha256(body).hexdigest()
    acknowledge_parser_receipt(store, job, 'response', checksum)
    original_event = store.event

    def fail_repeat_request_after_append(connection, actor, operation, ids, **details):
        result = original_event(connection, actor, operation, ids, **details)
        if operation == 'parser.receipt_acknowledgement_requested':
            raise OSError('synthetic repeat request interruption')
        return result

    monkeypatch.setattr(store, 'event', fail_repeat_request_after_append)
    with pytest.raises(OSError, match='repeat request interruption'):
        acknowledge_parser_receipt(store, job, 'response', checksum)

    recovered = Store(store.root)
    assert recovered.blocked == 'Audit integrity check failed. Preserve the workspace and inspect it.'
    receipt = acknowledge_parser_receipt(recovered, job, 'response', checksum)
    assert receipt['already_archived'] is True and recovered.blocked is None
    assert recovered.verify()['events'] >= 4
    audit = (store.root / 'audit.jsonl').read_text()
    assert audit.count('parser.receipt_acknowledgement_requested') == 2
    assert audit.count('parser.receipt_acknowledged') == 2


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns parser recovery')
def test_parser_receipt_retry_repeats_archive_parent_sync(tmp_path, monkeypatch):
    from workspace.parser_service import acknowledge_receipt
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    queue = store.root / 'parser-queue'; queue.mkdir(mode=0o700)
    job = str(uuid.uuid4())
    body = b'synthetic archive parent sync receipt\n'
    path = queue / f'{job}.error'; path.write_bytes(body); path.chmod(0o600)
    checksum = hashlib.sha256(body).hexdigest()
    archive = store.root / 'artifacts' / 'parser-receipts'
    original_fsync = os.fsync
    parent_failures = 0
    fsynced = []

    def interrupt_first_parent_sync(fd):
        nonlocal parent_failures
        target = Path(os.readlink(f'/proc/self/fd/{fd}'))
        if target.is_dir():
            fsynced.append(target)
        if target == store.root / 'artifacts' and parent_failures == 0:
            parent_failures += 1
            raise OSError('synthetic archive parent sync interruption')
        return original_fsync(fd)

    monkeypatch.setattr(os, 'fsync', interrupt_first_parent_sync)
    with pytest.raises(OSError, match='parent sync interruption'):
        acknowledge_receipt(queue, archive, job, 'error', checksum)
    assert path.read_bytes() == body and archive.is_dir()

    receipt = acknowledge_receipt(queue, archive, job, 'error', checksum)
    assert receipt['already_archived'] is False and not path.exists()
    assert fsynced.count(store.root / 'artifacts') == 2


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns parser recovery')
def test_parser_receipt_retry_syncs_queue_and_existing_archive_after_rename(tmp_path, monkeypatch):
    from workspace.parser_service import acknowledge_receipt
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    queue = store.root / 'parser-queue'; queue.mkdir(mode=0o700)
    job = str(uuid.uuid4())
    body = b'synthetic post-rename sync receipt\n'
    path = queue / f'{job}.response'; path.write_bytes(body); path.chmod(0o600)
    checksum = hashlib.sha256(body).hexdigest()
    archive = store.root / 'artifacts' / 'parser-receipts'
    original_fsync = os.fsync
    queue_failures = 0
    fsynced = []

    def interrupt_first_queue_sync(fd):
        nonlocal queue_failures
        target = Path(os.readlink(f'/proc/self/fd/{fd}'))
        if target.is_dir():
            fsynced.append(target)
        if target == queue and queue_failures == 0:
            queue_failures += 1
            raise OSError('synthetic queue sync interruption')
        return original_fsync(fd)

    monkeypatch.setattr(os, 'fsync', interrupt_first_queue_sync)
    with pytest.raises(OSError, match='queue sync interruption'):
        acknowledge_receipt(queue, archive, job, 'response', checksum)
    archived = archive / path.name
    assert not path.exists() and archived.read_bytes() == body

    fsynced.clear()
    receipt = acknowledge_receipt(queue, archive, job, 'response', checksum)
    assert receipt['already_archived'] is True
    assert queue in fsynced and archive in fsynced


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns parser recovery')
def test_parser_ack_refuses_to_reconcile_an_unrelated_audit_tail(tmp_path):
    from workspace.cli import acknowledge_parser_receipt
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    queue = store.root / 'parser-queue'; queue.mkdir(mode=0o700)
    job = str(uuid.uuid4())
    body = b'synthetic unrelated-tail receipt\n'
    path = queue / f'{job}.error'; path.write_bytes(body); path.chmod(0o600)
    checksum = hashlib.sha256(body).hexdigest()

    with pytest.raises(OSError, match='synthetic unrelated interruption'):
        with store.tx() as connection:
            store.event(connection, 'fixture', 'fixture.unrelated_event', [], note='synthetic')
            raise OSError('synthetic unrelated interruption')

    recovered = Store(store.root)
    assert recovered.blocked == 'Audit integrity check failed. Preserve the workspace and inspect it.'
    with pytest.raises(RuntimeError, match='Audit tail recovery failed'):
        acknowledge_parser_receipt(recovered, job, 'error', checksum)
    assert path.read_bytes() == body
    assert not (store.root / 'artifacts' / 'parser-receipts' / path.name).exists()


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns parser recovery')
def test_hidden_pending_request_beyond_metadata_limit_blocks_restart(tmp_path):
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    queue = store.root / 'parser-queue'; queue.mkdir(mode=0o700)
    for index in range(64):
        job = f'00000000-0000-4000-8000-{index:012d}'
        (queue / f'{job}.error').write_text('closed synthetic receipt\n')
    pending = 'ffffffff-ffff-4fff-8fff-ffffffffffff'
    (queue / f'{pending}.request').write_text('{}')
    state = inspect_queue(queue)
    assert state['truncated'] is True
    assert all(entry['kind'] == 'error' for entry in state['entries'])
    assert state['recovery_required'] is True
    app = create_app(store.root)
    assert app.state.store.blocked == 'Parser recovery is required. Preserve the queue and inspect the listed jobs.'
    with pytest.raises(RuntimeError, match='recovery'):
        serve(queue)


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns parser recovery')
def test_closed_receipts_beyond_metadata_limit_do_not_block_restart(tmp_path):
    store = initialize(tmp_path / 'state', 'http://127.0.0.1:8710', 'Synthetic')
    queue = store.root / 'parser-queue'; queue.mkdir(mode=0o700)
    for index in range(65):
        job = f'00000000-0000-4000-8000-{index:012d}'
        (queue / f'{job}.error').write_text('closed synthetic receipt\n')
    state = inspect_queue(queue)
    assert state['truncated'] is True and state['recovery_required'] is False
    assert create_app(store.root).state.store.blocked is None


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns parser recovery')
def test_parser_queue_inspection_does_not_leak_directory_descriptors(tmp_path):
    queue = tmp_path / 'queue'; queue.mkdir(mode=0o700)
    before = len(list(Path('/proc/self/fd').iterdir()))
    for _ in range(100):
        assert inspect_queue(queue)['recovery_required'] is False
    after = len(list(Path('/proc/self/fd').iterdir()))
    assert after == before


def _guard_external_reads(monkeypatch, external):
    real_read = os.read
    external_stat = external.stat()

    def guarded_read(fd, size):
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) == (external_stat.st_dev, external_stat.st_ino):
            pytest.fail('outside fixture bytes were read')
        return real_read(fd, size)

    monkeypatch.setattr(os, 'read', guarded_read)


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns parser queue reads')
def test_parser_queue_request_read_refuses_symlink_swapped_at_descriptor_open(tmp_path, monkeypatch):
    queue = tmp_path / 'queue'; queue.mkdir(mode=0o700)
    job = str(uuid.uuid4())
    request = queue / f'{job}.request'; request.write_text('{}')
    outside = tmp_path / 'outside'; outside.write_bytes(b'outside synthetic request bytes')
    _guard_external_reads(monkeypatch, outside)
    real_open = os.open

    def swap_request(name, flags, *args, **kwargs):
        if name == request.name and kwargs.get('dir_fd') is not None and request.exists():
            request.unlink(); request.symlink_to(outside)
        return real_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(os, 'open', swap_request)
    state = inspect_queue(queue)
    assert state['entries'][0]['kind'] == 'unsafe' and state['recovery_required'] is True


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns parser queue reads')
@pytest.mark.parametrize('swapped_kind', ['running', 'input'])
def test_parser_service_never_reads_symlink_swapped_running_or_input(tmp_path, monkeypatch, swapped_kind):
    queue = tmp_path / 'queue'; queue.mkdir(mode=0o700)
    job = str(uuid.uuid4())
    input_path = queue / f'{job}.input'; input_path.write_bytes(b'synthetic input')
    request = {'schema_version': 1, 'job_id': job, 'format': 'nmap_xml', 'sha256': file_sha256(input_path), 'size': input_path.stat().st_size}
    (queue / f'{job}.request').write_text(json.dumps(request))
    outside = tmp_path / 'outside'; outside.write_bytes(b'outside synthetic running bytes')
    _guard_external_reads(monkeypatch, outside)
    real_open = os.open
    swapped = False

    def swap_queue_entry(name, flags, *args, **kwargs):
        nonlocal swapped
        candidate = queue / f'{job}.{swapped_kind}'
        if not swapped and name == candidate.name and kwargs.get('dir_fd') is not None and candidate.exists():
            swapped = True
            candidate.unlink(); candidate.symlink_to(outside)
        return real_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(os, 'open', swap_queue_entry)
    monkeypatch.setattr(subprocess, 'Popen', lambda *_args, **_kwargs: pytest.fail('unsafe queue data must not dispatch'))
    import workspace.parser_service as service
    monkeypatch.setattr(service, 'inspect_queue', lambda _queue: {'recovery_required': False})
    monkeypatch.setattr(time, 'sleep', lambda _seconds: setattr(service, 'STOP', True))
    try:
        serve(queue)
    finally:
        service.STOP = False
    assert swapped and (queue / f'{job}.error').exists()


@pytest.mark.skipif(APP_NAME != 'Harbinger', reason='Harbinger owns parser queue reads')
def test_parser_client_never_reads_symlink_swapped_response(tmp_path, monkeypatch):
    queue = tmp_path / 'queue'; queue.mkdir(mode=0o700)
    job = uuid.UUID('00000000-0000-4000-8000-000000000111')
    response = queue / f'{job}.response'
    response.write_bytes(b'{"assets":[],"relationships":[],"observations":[],"limitations":[],"complete":true,"quarantined":[]}')
    outside = tmp_path / 'outside'; outside.write_bytes(b'outside synthetic response bytes')
    _guard_external_reads(monkeypatch, outside)
    monkeypatch.setattr(uuid, 'uuid4', lambda: job)
    real_open = os.open
    swapped = False

    def swap_response(name, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped and name == response.name and kwargs.get('dir_fd') is not None and response.exists():
            swapped = True
            response.unlink(); response.symlink_to(outside)
        return real_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(os, 'open', swap_response)
    source = tmp_path / 'input.xml'; source.write_bytes(NMAP)
    with pytest.raises(RuntimeError, match='output is unavailable'):
        queue_parser(source, 'nmap_xml', queue)
    assert swapped


def test_client_http_peer_request_is_rejected_before_nonce_or_audit_write(tmp_path, monkeypatch):
    monkeypatch.setenv('CONTAINERIZED', '1')
    receiver_root = tmp_path / 'receiver'; receiver_root.mkdir(mode=0o700)
    marker = receiver_root / '.storage-verified.json'
    marker.write_text(json.dumps({'schema_version': 1, 'encrypted': True, 'verified_at': '2026-09-09T00:00:00.000000Z'})); marker.chmod(0o600)
    receiver = initialize(receiver_root, 'https://receiver.test', 'Synthetic', mode='client', peer_origin='https://peer.test')
    sender = initialize(tmp_path / 'sender', 'https://sender.test', 'Synthetic', engagement_id=receiver.setting('config')['engagement']['id'])
    sender.configure('config', {**sender.setting('config'), 'app': 'Merlin'})
    provision_keys(receiver); provision_keys(sender)
    enroll(receiver, public_card(sender), __import__('workspace.store', fromlist=['digest']).digest(public_card(sender)))
    enroll(sender, public_card(receiver), __import__('workspace.store', fromlist=['digest']).digest(public_card(receiver)))
    body = b'synthetic signed peer body'; headers = peer_http_headers(sender, sender.setting('peers')[0], body)
    response = TestClient(create_app(receiver.root), base_url='http://peer.test').post('/peer/inbox', content=body, headers=headers)
    assert response.status_code == 403
    with receiver.connect() as connection:
        assert connection.execute('SELECT COUNT(*) FROM peer_http_nonces').fetchone()[0] == 0
    assert 'peer.request_authorized' not in (receiver.root / 'audit.jsonl').read_text()


def test_lead_drafting_boundary(client, store):
    store = client.app.state.store
    with store.tx() as connection:
        lead = store.put(connection, 'lead', {
            'title': 'Synthetic lead',
            'observation': 'A controlled fixture exposed a service.',
            'impact': 'Review is required.',
            'evidence_ids': [],
        }, 'fixture')
        store.event(connection, 'fixture', 'lead.received', [lead['id']])
    response = client.post('/api/leads/' + lead['id'] + '/draft')
    if APP_NAME == 'Harbinger':
        assert response.status_code == 403
        return
    assert response.status_code == 200
    first = response.json()
    assert first['data']['lead_id'] == lead['id']
    assert first['data']['description'] == lead['data']['observation']
    again = client.post('/api/leads/' + lead['id'] + '/draft')
    assert again.status_code == 200 and again.json()['id'] == first['id']


@pytest.mark.skipif(APP_NAME != 'Merlin', reason='Only Merlin delivers reviewed drafts')
def test_delivery_blocks_parallel_and_later_revision(client, store):
    store = client.app.state.store
    store.configure('ghostwriter', {
        'origin': 'http://127.0.0.1:9999',
        'report_id': '7',
        'severity_id': 1,
        'finding_type_id': 1,
        'schema_hash': 'fixture-schema',
    })
    created = client.post('/api/records', json={'kind': 'draft', 'data': {
        'title': 'Synthetic draft', 'description': 'Description', 'impact': 'Impact',
        'remediation': 'Fix', 'references': '', 'evidence_ids': [], 'owner_id': '', 'lead_id': '',
    }}).json()
    first = client.post('/api/deliveries/review', json={'draft_id': created['id'], 'report_id': '7'})
    assert first.status_code == 200
    parallel = client.post('/api/deliveries/review', json={'draft_id': created['id'], 'report_id': '7'})
    assert parallel.status_code == 409
    edited = client.put('/api/records/' + created['id'], json={
        'base_revision_id': created['revision_id'],
        'data': {**created['data'], 'description': 'Later description'},
    })
    assert edited.status_code == 200
    assert store.get(first.json()['id'])['data']['status'] == 'rejected'
    later = client.post('/api/deliveries/review', json={'draft_id': created['id'], 'report_id': '7'})
    assert later.status_code == 200


@pytest.mark.skipif(APP_NAME != 'Merlin', reason='Only Merlin owns draft delivery state')
def test_reviewed_delivery_is_invalidated_by_a_draft_edit(client, store):
    store = client.app.state.store
    with store.tx() as connection:
        draft = store.put(connection, 'draft', {
            'title': 'Synthetic draft', 'description': 'First', 'impact': '', 'remediation': '',
            'references': '', 'evidence_ids': [], 'owner_id': '', 'lead_id': '',
        }, 'fixture')
        delivery = store.put(connection, 'delivery', {
            'status': 'reviewed', 'draft_id': draft['id'], 'revision_id': draft['revision_id'],
            'report_id': '7', 'payload_hash': 'fixture', 'payload': {}, 'config_hash': 'fixture',
            'approved_by': 'fixture',
        }, 'fixture')
        store.event(connection, 'fixture', 'delivery.fixture_created', [draft['id'], delivery['id']])
    edited = client.put('/api/records/' + draft['id'], json={
        'base_revision_id': draft['revision_id'],
        'data': {**draft['data'], 'description': 'Changed'},
    })
    assert edited.status_code == 200
    changed = store.get(delivery['id'])
    assert changed['data']['status'] == 'rejected'
    assert changed['data']['reason'] == 'draft_changed'


@pytest.mark.skipif(APP_NAME != 'Merlin', reason='Only Merlin owns draft delivery state')
@pytest.mark.parametrize('status', ['sending', 'uncertain', 'delivered'])
def test_terminal_or_uncertain_delivery_blocks_draft_edit(client, store, status):
    store = client.app.state.store
    with store.tx() as connection:
        draft = store.put(connection, 'draft', {
            'title': 'Synthetic draft', 'description': 'First', 'impact': '', 'remediation': '',
            'references': '', 'evidence_ids': [], 'owner_id': '', 'lead_id': '',
        }, 'fixture')
        delivery = store.put(connection, 'delivery', {
            'status': status, 'draft_id': draft['id'], 'revision_id': draft['revision_id'],
            'report_id': '7', 'payload_hash': 'fixture', 'payload': {}, 'config_hash': 'fixture',
            'approved_by': 'fixture',
        }, 'fixture')
        store.event(connection, 'fixture', 'delivery.fixture_created', [draft['id'], delivery['id']])
    edited = client.put('/api/records/' + draft['id'], json={
        'base_revision_id': draft['revision_id'],
        'data': {**draft['data'], 'description': 'Changed'},
    })
    assert edited.status_code == 409
    assert store.get(draft['id'])['revision_id'] == draft['revision_id']
