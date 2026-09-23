"""A fixed offline parser launcher. No general command API is exposed."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import sysconfig
import threading
import ctypes
import hashlib
import time
import uuid
from .store import canonical
from .parsers import FORMATS, FORMAT_LIMITS
from .parser_service import QUEUE_FILE_LIMITS, _open_queue, _queue_file_exists_at, _read_queue_file_at

_slot = threading.Lock()
PARSER_WAIT_SECONDS = 125


def memfd():
    # Some standalone CPython 3.11 builds omit os.memfd_create on Linux.
    libc = ctypes.CDLL(None, use_errno=True)
    fn = libc.memfd_create
    fn.argtypes = [ctypes.c_char_p, ctypes.c_uint]
    fn.restype = ctypes.c_int
    fd = fn(b'parser-result', 1)
    if fd < 0:
        raise OSError(ctypes.get_errno(), 'Cannot reserve parser output')
    return fd


def queue_parser(path, format, queue):
    """Pass one sealed-by-hash job to the networkless Docker parser service."""
    root = Path(queue).absolute()
    try:
        queue_fd = _open_queue(root)
    except (OSError, ValueError) as error:
        raise RuntimeError('The parser queue is unavailable.') from error
    job = str(uuid.uuid4())
    input_path = root / f'{job}.input'
    request_path = root / f'{job}.request'
    temp_path = root / f'.{job}.request.tmp'
    response_path = root / f'{job}.response'
    error_path = root / f'{job}.error'
    cancel_path = root / f'{job}.cancel'
    paths = (input_path, request_path, temp_path, response_path, error_path, cancel_path, root / f'{job}.running')
    request_published = False
    terminal = None
    try:
        digest = hashlib.sha256()
        source = Path(path)
        fd = os.open(input_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with source.open('rb') as incoming, os.fdopen(fd, 'wb', closefd=False) as outgoing:
                size = 0
                while chunk := incoming.read(1024 * 1024):
                    size += len(chunk)
                    if size > FORMAT_LIMITS.get(format, 0):
                        raise RuntimeError('Parser input exceeds its limit.')
                    digest.update(chunk)
                    outgoing.write(chunk)
                outgoing.flush()
                os.fsync(outgoing.fileno())
        finally:
            os.close(fd)
        request = canonical({'schema_version': 1, 'job_id': job, 'format': format, 'sha256': digest.hexdigest(), 'size': size})
        fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(request)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, request_path)
        request_published = True
        deadline = time.monotonic() + PARSER_WAIT_SECONDS
        while time.monotonic() < deadline:
            try:
                raw = _read_queue_file_at(queue_fd, response_path.name, QUEUE_FILE_LIMITS['response'])
            except FileNotFoundError:
                raw = None
            except (OSError, ValueError) as error:
                raise RuntimeError('Parser output is unavailable.') from error
            if raw is not None:
                # The child publishes the response before the parser service has
                # checked it and retired the running job. Leave the queue intact
                # until that final check finishes, or cleanup can create a false
                # error receipt for a successful import.
                try:
                    _queue_file_exists_at(queue_fd, f'{job}.running', QUEUE_FILE_LIMITS['running'])
                except FileNotFoundError:
                    pass
                except (OSError, ValueError) as error:
                    raise RuntimeError('Parser completion is unavailable.') from error
                else:
                    time.sleep(.05)
                    continue
                try:
                    _queue_file_exists_at(queue_fd, error_path.name, QUEUE_FILE_LIMITS['error'])
                except FileNotFoundError:
                    pass
                except (OSError, ValueError) as error:
                    raise RuntimeError('Parser error receipt is unavailable.') from error
                else:
                    raise RuntimeError('Conflicting parser completion receipts require review.')
                result = json.loads(raw)
                if set(result) != {'assets', 'relationships', 'observations', 'limitations', 'complete', 'quarantined'}:
                    raise RuntimeError('Invalid parser result.')
                terminal = 'success'
                return result
            try:
                _queue_file_exists_at(queue_fd, error_path.name, QUEUE_FILE_LIMITS['error'])
            except FileNotFoundError:
                pass
            except (OSError, ValueError) as error:
                raise RuntimeError('Parser error receipt is unavailable.') from error
            else:
                try:
                    _queue_file_exists_at(queue_fd, f'{job}.running', QUEUE_FILE_LIMITS['running'])
                except FileNotFoundError:
                    terminal = 'error'
                    raise RuntimeError('The networkless parser did not accept this file.')
                except (OSError, ValueError) as error:
                    raise RuntimeError('Parser completion is unavailable.') from error
                time.sleep(.05)
                continue
            time.sleep(.05)
        cancel_path.touch(mode=0o600, exist_ok=False)
        raise RuntimeError('Parsing stopped at its deadline. No records were merged.')
    finally:
        os.close(queue_fd)
        # A timed out or ambiguous job must remain visible to recovery. Never
        # erase an active request, cancellation marker, or terminal error proof.
        if not request_published or terminal is not None:
            for candidate in paths:
                if terminal == 'error' and candidate == error_path:
                    continue
                try:
                    candidate.unlink()
                except FileNotFoundError:
                    pass
            for temporary in root.glob(f'.{job}.*.tmp'):
                temporary.unlink(missing_ok=True)


def run_parser(path, format):
    if format not in FORMATS:
        raise ValueError('Unsupported parser')
    if not _slot.acquire(blocking=False):
        raise RuntimeError('Another file is being parsed. Wait for it to finish.')
    if os.environ.get('PARSER_QUEUE'):
        try:
            return queue_parser(path, format, os.environ['PARSER_QUEUE'])
        finally:
            _slot.release()
    fd = None
    process = None
    try:
        fd = memfd()
        source = Path(__file__).parent / 'parsers'
        cmd = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp']
        for p in dict.fromkeys(['/usr', '/lib', '/lib64', sys.base_prefix, sys.prefix]):
            if Path(p).exists():
                cmd += ['--ro-bind', p, p]
        purelib = sysconfig.get_paths()['purelib']
        contracts = Path(__file__).resolve().parent.parent / 'contracts'
        cmd += [
            '--ro-bind', str(source), '/code/parsers',
            '--ro-bind', str(contracts), '/code/contracts',
            '--ro-bind', str(Path(path).absolute()), '/input',
            '--chdir', '/code',
            '--setenv', 'PYTHONPATH', '/code',
            '--setenv', 'PARSER_PURELIB', purelib,
            str(Path(sys.executable).resolve()), '-S', '-B',
            '/code/parsers/worker.py', format,
        ]
        process = subprocess.Popen(cmd, stdout=fd, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, env={}, close_fds=True, start_new_session=True)
        try:
            code = process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            raise RuntimeError('Parsing stopped at its deadline. No records were merged.')
        if code:
            raise RuntimeError('The contained parser did not finish. Check the format, limits, and local sandbox support.')
        length = os.fstat(fd).st_size
        if length > 128 * 1024**2:
            raise RuntimeError('Parser output exceeds its limit')
        os.lseek(fd, 0, 0)
        raw = os.read(fd, length + 1)
        result = json.loads(raw)
        if set(result) != {'assets', 'relationships', 'observations', 'limitations', 'complete', 'quarantined'}:
            raise RuntimeError('Invalid parser result')
        if any(not isinstance(result[k], list) for k in ('assets', 'relationships', 'observations', 'limitations')):
            raise RuntimeError('Invalid parser collection')
        return result
    finally:
        if process and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        if fd is not None:
            os.close(fd)
        _slot.release()
