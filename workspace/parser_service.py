"""One-job-at-a-time parser service for a Docker container with no network."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from .parsers import FORMATS, FORMAT_LIMITS

STOP = False
QUEUE_SCAN_LIMIT = 4096
QUEUE_METADATA_LIMIT = 64
QUEUE_FILE_LIMITS = {
    'input': 256 * 1024**2,
    'request': 4096,
    'running': 4096,
    'response': 128 * 1024**2,
    'error': 4096,
    'cancel': 4096,
}
HEALTH_PID_FILE = Path('/tmp/harbinger-parser.pid')


def stopping(*_):
    global STOP
    STOP = True


def limits():
    resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (110, 110))
    resource.setrlimit(resource.RLIMIT_FSIZE, (128 * 1024**2, 128 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))


def atomic_file(path, data):
    """Publish a complete parser result only after its bytes are durable."""
    path = Path(path)
    if path.exists():
        raise FileExistsError(path)
    temporary = path.with_name(f'.{path.name}.{uuid.uuid4()}.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(data)
        while view:
            try:
                written = os.write(fd, view)
            except InterruptedError:
                continue
            if written <= 0:
                raise OSError('Parser result write stopped')
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, path)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)


def fixed_error(path):
    atomic_file(path, b'The parser did not accept this file. No records were merged.\n')


def _same_file(before, after):
    return (before.st_dev, before.st_ino, before.st_size) == (after.st_dev, after.st_ino, after.st_size)


def _open_queue(queue):
    fd = os.open(Path(queue).absolute(), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise ValueError('Parser queue is not a directory')
        return fd
    except Exception:
        os.close(fd)
        raise


@contextmanager
def _scan_queue(queue_fd):
    """Scan through a duplicate without leaking the caller-owned directory fd."""
    scan_fd = os.dup(queue_fd)
    try:
        with os.scandir(scan_fd) as entries:
            yield entries
    finally:
        os.close(scan_fd)


def _open_regular_at(queue_fd, name, limit):
    if not isinstance(name, str) or '/' in name or name in ('', '.', '..'):
        raise ValueError('Queue entry name is invalid')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=queue_fd)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('Queue entry is not a regular file')
        if before.st_size > limit:
            raise ValueError('Queue entry exceeds its limit')
        return fd, before
    except Exception:
        os.close(fd)
        raise


def _read_open_file(fd, before, limit):
    chunks = []
    total = 0
    while total <= limit:
        chunk = os.read(fd, min(1024 * 1024, limit - total + 1))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    after = os.fstat(fd)
    if total > limit or total != before.st_size or not _same_file(before, after):
        raise ValueError('Queue entry changed during inspection')
    return b''.join(chunks)


def _hash_open_file(fd, before, limit):
    value = hashlib.sha256()
    total = 0
    while total <= limit:
        chunk = os.read(fd, min(1024 * 1024, limit - total + 1))
        if not chunk:
            break
        value.update(chunk)
        total += len(chunk)
    after = os.fstat(fd)
    if total > limit or total != before.st_size or not _same_file(before, after):
        raise ValueError('Queue entry changed during inspection')
    return value.hexdigest(), before


def read_queue_file(queue, name, limit):
    """Read one bounded regular queue entry through no-follow descriptors."""
    queue_fd = _open_queue(queue)
    try:
        fd, before = _open_regular_at(queue_fd, name, limit)
        try:
            return _read_open_file(fd, before, limit)
        finally:
            os.close(fd)
    finally:
        os.close(queue_fd)


def _read_queue_file_at(queue_fd, name, limit):
    fd, before = _open_regular_at(queue_fd, name, limit)
    try:
        return _read_open_file(fd, before, limit)
    finally:
        os.close(fd)


def _read_bounded_path(path, limit):
    """Read a known final path through one no-follow descriptor."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError('Queue entry is invalid')
        return _read_open_file(fd, before, limit)
    finally:
        os.close(fd)


def _hash_queue_file_at(queue_fd, name, limit):
    fd, before = _open_regular_at(queue_fd, name, limit)
    try:
        return _hash_open_file(fd, before, limit)
    finally:
        os.close(fd)


def _queue_file_exists_at(queue_fd, name, limit):
    fd, _ = _open_regular_at(queue_fd, name, limit)
    os.close(fd)


def file_sha256(path):
    """Hash one regular queue file without following links."""
    path = Path(path)
    queue_fd = _open_queue(path.parent)
    try:
        return _hash_queue_file_at(queue_fd, path.name, QUEUE_FILE_LIMITS['input'])[0]
    finally:
        os.close(queue_fd)


def _queue_identity(name):
    path = Path(name)
    kind = path.suffix.removeprefix('.')
    if kind not in QUEUE_FILE_LIMITS:
        return None
    try:
        job_id = str(uuid.UUID(path.stem))
    except ValueError:
        return None
    if path.stem != job_id or name != f'{job_id}.{kind}':
        return None
    return job_id, kind


def inspect_queue(queue, max_entries=QUEUE_METADATA_LIMIT):
    """Return bounded metadata for a queue. Never return raw bytes or unsafe names."""
    if type(max_entries) is not int or not 1 <= max_entries <= QUEUE_METADATA_LIMIT:
        raise ValueError('Queue metadata limit is invalid')
    queue_fd = _open_queue(queue)
    candidates = []
    total = 0
    scan_complete = True
    ambiguous_seen = False
    try:
        with _scan_queue(queue_fd) as entries:
            for entry in entries:
                total += 1
                if total > QUEUE_SCAN_LIMIT:
                    scan_complete = False
                    break
                identity = _queue_identity(entry.name)
                if identity is None:
                    ambiguous_seen = True
                else:
                    kind = identity[1]
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except OSError:
                        ambiguous_seen = True
                    else:
                        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > QUEUE_FILE_LIMITS[kind]:
                            ambiguous_seen = True
                    if kind in ('input', 'request', 'running', 'cancel'):
                        ambiguous_seen = True
                candidates.append(entry.name)
                candidates.sort()
                if len(candidates) > max_entries:
                    candidates.pop()
        result = []
        for name in candidates:
            identity = _queue_identity(name)
            if identity is None:
                result.append({'name': 'unsupported-entry', 'kind': 'unsupported', 'size': 0, 'sha256': None})
                continue
            job_id, kind = identity
            try:
                checksum, value = _hash_queue_file_at(queue_fd, name, QUEUE_FILE_LIMITS[kind])
            except (FileNotFoundError, OSError, ValueError):
                result.append({'name': 'changed-entry', 'kind': 'unsafe', 'size': 0, 'sha256': None})
                continue
            result.append({'job_id': job_id, 'name': name, 'kind': kind, 'size': value.st_size, 'sha256': checksum})
        ambiguous = ambiguous_seen or any(entry['kind'] in ('unsafe', 'unsupported') for entry in result)
        return {
            'entries': result,
            'total_entries': total,
            'reported_entries': len(result),
            'truncated': total > len(result) or not scan_complete,
            'scan_complete': scan_complete,
            'recovery_required': ambiguous or not scan_complete,
        }
    finally:
        os.close(queue_fd)


def _parser_process_alive(pid):
    try:
        os.kill(pid, 0)
        return b'workspace.parser_service' in Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
    except (OSError, ValueError):
        return False


def queue_is_safe_for_health(queue):
    """Check every bounded queue entry without treating active jobs as recovery."""
    try:
        queue_fd = _open_queue(queue)
    except (OSError, ValueError):
        return False
    try:
        with _scan_queue(queue_fd) as entries:
            for count, entry in enumerate(entries, start=1):
                if count > QUEUE_SCAN_LIMIT:
                    return False
                identity = _queue_identity(entry.name)
                if identity is None:
                    return False
                try:
                    _queue_file_exists_at(queue_fd, entry.name, QUEUE_FILE_LIMITS[identity[1]])
                except (FileNotFoundError, OSError, ValueError):
                    return False
    finally:
        os.close(queue_fd)
    return True


def healthy(queue):
    """Check that the parser loop is alive and the queue has no unsafe entries."""
    try:
        if not queue_is_safe_for_health(queue):
            return False
        pid = int(HEALTH_PID_FILE.read_text())
    except (OSError, ValueError):
        return False
    return _parser_process_alive(pid)


def _write_health_pid():
    fd = os.open(HEALTH_PID_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, str(os.getpid()).encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def acknowledge_receipt(queue, archive, job_id, kind, expected_sha256):
    """Atomically archive one reviewed receipt while the parser is stopped."""
    job_id = str(uuid.UUID(job_id))
    if kind not in ('response', 'error'):
        raise ValueError('Only closed parser receipts can be acknowledged')
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        raise ValueError('Parser receipt checksum is invalid')
    try:
        bytes.fromhex(expected_sha256)
    except ValueError as error:
        raise ValueError('Parser receipt checksum is invalid') from error
    name = f'{job_id}.{kind}'
    queue_fd = _open_queue(queue)
    archive = Path(archive).absolute()
    archive_parent_fd = _open_queue(archive.parent)
    try:
        try:
            os.mkdir(archive.name, mode=0o700, dir_fd=archive_parent_fd)
        except FileExistsError:
            pass
        os.fsync(archive_parent_fd)
    finally:
        os.close(archive_parent_fd)
    archive_fd = _open_queue(archive)
    try:
        already_archived = False
        try:
            fd, before = _open_regular_at(queue_fd, name, QUEUE_FILE_LIMITS[kind])
        except FileNotFoundError:
            fd, before = _open_regular_at(archive_fd, name, QUEUE_FILE_LIMITS[kind])
            already_archived = True
        try:
            checksum, opened = _hash_open_file(fd, before, QUEUE_FILE_LIMITS[kind])
            current_fd = archive_fd if already_archived else queue_fd
            current = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
            if not _same_file(opened, current):
                raise ValueError('Parser receipt changed during acknowledgement')
            if not hmac.compare_digest(checksum, expected_sha256.lower()):
                raise ValueError('Parser receipt checksum changed')
            if not already_archived:
                try:
                    os.stat(name, dir_fd=archive_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError('Parser receipt archive already exists')
                os.rename(name, name, src_dir_fd=queue_fd, dst_dir_fd=archive_fd)
            os.fsync(queue_fd)
            os.fsync(archive_fd)
            return {
                'job_id': job_id, 'kind': kind, 'size': opened.st_size,
                'sha256': checksum, 'already_archived': already_archived,
            }
        finally:
            os.close(fd)
    finally:
        os.close(archive_fd)
        os.close(queue_fd)


def child(input_path, output_path, format):
    """Run inside a bounded child. Paths are generated UUID names in one queue."""
    limits()
    from .parsers import parse
    input_path = Path(input_path)
    raw = _read_bounded_path(input_path, FORMAT_LIMITS[format])
    result = parse(raw, format)
    encoded = json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
    if len(encoded) > 128 * 1024**2:
        raise ValueError('Parser output exceeds the limit')
    atomic_file(output_path, encoded)


def serve(queue):
    root = Path(queue).absolute()
    state = inspect_queue(root)
    if state['recovery_required']:
        raise RuntimeError('Parser recovery is required for interrupted jobs')
    _write_health_pid()
    signal.signal(signal.SIGTERM, stopping)
    signal.signal(signal.SIGINT, stopping)
    queue_fd = _open_queue(root)
    try:
        while not STOP:
            requests = []
            with _scan_queue(queue_fd) as entries:
                for entry in entries:
                    identity = _queue_identity(entry.name)
                    if identity and identity[1] == 'request':
                        try:
                            requests.append((entry.stat(follow_symlinks=False).st_mtime_ns, entry.name))
                        except FileNotFoundError:
                            pass
            if not requests:
                time.sleep(.1)
                continue
            _, request_name = min(requests)
            job = request_name.removesuffix('.request')
            running_name = f'{job}.running'
            try:
                uuid.UUID(job)
                os.replace(request_name, running_name, src_dir_fd=queue_fd, dst_dir_fd=queue_fd)
                request = json.loads(_read_queue_file_at(queue_fd, running_name, QUEUE_FILE_LIMITS['running']))
                if set(request) != {'schema_version', 'job_id', 'format', 'sha256', 'size'} or request['schema_version'] != 1 or request['job_id'] != job or request['format'] not in FORMATS or type(request['size']) is not int or not 0 <= request['size'] <= FORMAT_LIMITS[request['format']]:
                    raise ValueError('Invalid job request')
                input_name = f'{job}.input'
                digest, source = _hash_queue_file_at(queue_fd, input_name, QUEUE_FILE_LIMITS['input'])
                if source.st_size != request['size'] or digest != request['sha256']:
                    raise ValueError('Input integrity failed')
                output = root / f'{job}.response'
                application_root = Path(__file__).resolve().parent.parent
                # The child resolves its input below this inherited queue descriptor, not by a mutable queue path.
                child_input = f'/proc/self/fd/{queue_fd}/{input_name}'
                process = subprocess.Popen(
                    [sys.executable, '-B', '-m', 'workspace.parser_job', child_input, str(output), request['format']],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    cwd=str(application_root),
                    env={'PATH': '/usr/local/bin:/usr/bin', 'PYTHONPATH': str(application_root)},
                    close_fds=True,
                    pass_fds=(queue_fd,),
                    start_new_session=True,
                )
                deadline = time.monotonic() + 120
                while process.poll() is None and time.monotonic() < deadline and not (root / f'{job}.cancel').exists() and not STOP:
                    time.sleep(.1)
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                code = process.wait(timeout=5)
                if code:
                    raise RuntimeError('Child failed')
                _queue_file_exists_at(queue_fd, f'{job}.response', QUEUE_FILE_LIMITS['response'])
            except Exception:
                try:
                    fixed_error(root / f'{job}.error')
                except FileExistsError:
                    pass
            finally:
                try:
                    os.unlink(running_name, dir_fd=queue_fd)
                except FileNotFoundError:
                    pass
                for temporary in root.glob(f'.{job}.*.tmp'):
                    temporary.unlink(missing_ok=True)
    finally:
        os.close(queue_fd)
        HEALTH_PID_FILE.unlink(missing_ok=True)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--healthcheck':
        return 0 if healthy(sys.argv[2]) else 1
    if len(sys.argv) != 2:
        print('usage: python -m workspace.parser_service QUEUE', file=sys.stderr)
        return 64
    try:
        serve(sys.argv[1])
    except Exception as error:
        print(f'Cannot start parser service: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
