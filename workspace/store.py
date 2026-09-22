"""Private local records, immutable revisions, and a durable audit chain."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time
import uuid
import re
from datetime import datetime, timezone


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def file_digest(path):
    checksum = hashlib.sha256()
    with Path(path).open('rb') as source:
        while chunk := source.read(1024 * 1024):
            checksum.update(chunk)
    return checksum.hexdigest()


def private(path, directory=False):
    path = Path(path)
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise RuntimeError("Private storage permissions changed. Stop and inspect the workspace.")
    if directory and not stat.S_ISDIR(st.st_mode):
        raise RuntimeError("Expected a private directory")


class Conflict(Exception):
    def __init__(self, current):
        self.current = current


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


class Store:
    def __init__(self, root, readonly=False):
        self.root = Path(root).absolute()
        self.readonly = bool(readonly)
        if not self.readonly:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        private(self.root, True)
        self.lock = threading.RLock()
        self.blocked = None
        self.audit_stats = None
        for name in ("artifacts", "staging", "conflicts", "keys", "exports"):
            if not self.readonly:
                (self.root / name).mkdir(mode=0o700, exist_ok=True)
            private(self.root / name, True)
        self.path = self.root / "workspace.db"
        if not self.path.exists() and not self.readonly:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        private(self.path)
        if self.readonly and any(self.path.with_name(self.path.name + suffix).exists() for suffix in ('-wal', '-shm')):
            raise RuntimeError('The workspace still has SQLite sidecar files. Stop the service cleanly before backup.')
        if not self.readonly:
            with self.connect() as c:
                c.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, role TEXT NOT NULL, password TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id), csrf TEXT NOT NULL, expires REAL NOT NULL, touched REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS login_limits(key TEXT PRIMARY KEY, count INTEGER NOT NULL, reset REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY, kind TEXT NOT NULL, revision_id TEXT NOT NULL, data TEXT NOT NULL, updated_at TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS records_kind ON records(kind);
                CREATE TABLE IF NOT EXISTS revisions(id TEXT PRIMARY KEY, record_id TEXT NOT NULL REFERENCES records(id), base_revision_id TEXT, actor TEXT NOT NULL, data TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL, hash TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS imports(key TEXT PRIMARY KEY, record_id TEXT NOT NULL REFERENCES records(id));
                CREATE TABLE IF NOT EXISTS transfers(id TEXT PRIMARY KEY, hash TEXT NOT NULL, receipt TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS peer_http_nonces(source TEXT NOT NULL, nonce TEXT NOT NULL, created INTEGER NOT NULL, PRIMARY KEY(source,nonce));
                CREATE TABLE IF NOT EXISTS harness_sources(source_id TEXT PRIMARY KEY, card TEXT NOT NULL, fingerprint TEXT NOT NULL, status TEXT NOT NULL, enrolled_at TEXT NOT NULL, revoked_at TEXT);
                CREATE TABLE IF NOT EXISTS harness_envelopes(envelope_id TEXT PRIMARY KEY, observation_id TEXT UNIQUE NOT NULL, source_id TEXT NOT NULL, signed_sha256 TEXT NOT NULL, observation_sha256 TEXT NOT NULL, artifact_sha256 TEXT NOT NULL, upload_id TEXT NOT NULL REFERENCES records(id), status TEXT NOT NULL, recorded_at TEXT NOT NULL);
                ''')
        for name in ("audit.jsonl", "transcript.log"):
            p = self.root / name
            if not p.exists() and not self.readonly:
                fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
            private(p)
        try:
            self.verify()
        except Exception:
            self.blocked = "Audit integrity check failed. Preserve the workspace and inspect it."

    def connect(self):
        if self.readonly:
            c = sqlite3.connect(f'file:{self.path}?mode=ro&immutable=1', uri=True, timeout=5, factory=ClosingConnection)
        else:
            c = sqlite3.connect(self.path, timeout=5, factory=ClosingConnection)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        if self.readonly:
            c.execute("PRAGMA query_only=ON")
        else:
            c.execute("PRAGMA synchronous=FULL")
        return c

    @contextlib.contextmanager
    def tx(self):
        with self.lock:
            self._assert_write_ready()
            c = self.connect()
            try:
                c.execute("BEGIN IMMEDIATE")
                yield c
                c.commit()
            except Exception:
                c.rollback()
                # A durable event can precede a failed commit. Never erase it.
                try:
                    self.verify()
                except Exception:
                    self.blocked = "Audit and database diverged. Recovery review is required."
                raise
            finally:
                c.close()

    def _assert_write_ready(self):
        if self.readonly:
            raise RuntimeError('This workspace is open read-only')
        if self.blocked:
            raise RuntimeError(self.blocked)
        for name in ("", "workspace.db", "audit.jsonl", "transcript.log", "artifacts", "keys", "staging", "conflicts", "exports"):
            private(self.root / name)
        if self.audit_stats is not None and self.audit_stats != self._stats():
            self.blocked = 'Audit files changed outside the writer. Inspect integrity before new work.'
            raise RuntimeError(self.blocked)

    def require_write_ready(self):
        """Check the same preconditions as ``tx`` without starting a write."""
        with self.lock:
            self._assert_write_ready()

    def reconcile_tail_event(self, actor=None, operation=None, ids=(), *, allowed_metadata=None, alternatives=None, **metadata):
        """Commit one exact durable audit tail after an interrupted DB commit."""
        if self.readonly:
            raise RuntimeError('This workspace is open read-only')
        base_fields = {
            'sequence', 'event_id', 'utc', 'monotonic_ns', 'instance_id',
            'engagement_id', 'clock_status', 'actor', 'operation', 'ids', 'previous',
        }
        if alternatives is None:
            alternatives = ({
                'actor': actor, 'operation': operation, 'ids': list(ids),
                'metadata': metadata, 'allowed_metadata': allowed_metadata or {},
            },)
        elif actor is not None or operation is not None or metadata or allowed_metadata:
            raise ValueError('Choose one recovery specification form')
        specifications = []
        for candidate in alternatives:
            if set(candidate) != {'actor', 'operation', 'ids', 'metadata', 'allowed_metadata'}:
                raise ValueError('Recovered event specification is invalid')
            exact = candidate['metadata']
            allowed = candidate['allowed_metadata']
            if not isinstance(exact, dict) or not isinstance(allowed, dict) or set(exact) & set(allowed):
                raise ValueError('Recovered metadata fields overlap')
            specifications.append({**candidate, 'ids': list(candidate['ids'])})
        with self.lock:
            c = self.connect()
            try:
                rows = c.execute('SELECT seq,body,hash FROM events ORDER BY seq').fetchall()
                previous = '0' * 64
                with (self.root / 'audit.jsonl').open() as audit, (self.root / 'transcript.log').open() as transcript:
                    for row in rows:
                        item = json.loads(audit.readline())
                        body = json.loads(row['body'])
                        if item != {'body': body, 'hash': row['hash']} or body['previous'] != previous or digest(body) != row['hash']:
                            raise ValueError('Existing audit history is invalid')
                        readable = f'{body["utc"]} #{body["sequence"]} {canonical(body["operation"])} actor={canonical(body["actor"])} ids={canonical(body["ids"])}\n'
                        if transcript.readline() != readable:
                            raise ValueError('Existing transcript history is invalid')
                        previous = row['hash']
                    tail = audit.readline()
                    transcript_tail = transcript.readline()
                    if not tail or audit.read() or not transcript_tail or transcript.read():
                        raise ValueError('Expected exactly one uncommitted audit tail')
                item = json.loads(tail)
                if not isinstance(item, dict) or set(item) != {'body', 'hash'} or not isinstance(item['body'], dict):
                    raise ValueError('Audit tail shape is invalid')
                body = item['body']
                expected_sequence = rows[-1]['seq'] + 1 if rows else 1
                if (body.get('sequence') != expected_sequence or body.get('previous') != previous
                        or item['hash'] != digest(body)):
                    raise ValueError('Audit tail does not match the requested recovery')
                matched = None
                for candidate in specifications:
                    exact = candidate['metadata']
                    allowed = candidate['allowed_metadata']
                    expected_fields = base_fields | set(exact) | set(allowed)
                    if (set(body) == expected_fields
                            and body.get('actor') == candidate['actor']
                            and body.get('operation') == candidate['operation']
                            and body.get('ids') == candidate['ids']
                            and all(body.get(key) == value for key, value in exact.items())
                            and all(body.get(key) in values for key, values in allowed.items())):
                        matched = candidate
                        break
                if matched is None:
                    raise ValueError('Audit tail does not match the requested recovery')
                uuid.UUID(body['event_id'])
                if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z', body.get('utc', '')):
                    raise ValueError('Audit tail time is invalid')
                if type(body.get('monotonic_ns')) is not int or body['monotonic_ns'] < 0:
                    raise ValueError('Audit tail monotonic time is invalid')
                expected_transcript = f'{body["utc"]} #{body["sequence"]} {canonical(matched["operation"])} actor={canonical(matched["actor"])} ids={canonical(matched["ids"])}\n'
                if transcript_tail != expected_transcript:
                    raise ValueError('Audit tail transcript does not match')
                c.execute('BEGIN IMMEDIATE')
                c.execute('INSERT INTO events(seq,body,hash) VALUES(?,?,?)', (body['sequence'], canonical(body), item['hash']))
                c.commit()
                self.blocked = None
                self.verify()
                self.audit_stats = self._stats()
                return body
            except Exception as error:
                c.rollback()
                self.blocked = 'Audit tail recovery failed. Preserve the workspace and inspect it.'
                raise RuntimeError(self.blocked) from error
            finally:
                c.close()

    def event(self, c, actor, operation, ids=(), **metadata):
        previous = c.execute("SELECT seq,hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        seq = previous["seq"] + 1 if previous else 1
        config_row = c.execute("SELECT value FROM settings WHERE key='config'").fetchone()
        config = json.loads(config_row[0]) if config_row else {}
        body = dict(sequence=seq, event_id=str(uuid.uuid4()), utc=utc(), monotonic_ns=time.monotonic_ns(),
                    instance_id=config.get('instance_id', 'setup'), engagement_id=config.get('engagement', {}).get('id', 'setup'),
                    clock_status="local_unverified", actor=actor, operation=operation, ids=list(ids),
                    previous=previous["hash"] if previous else "0" * 64, **metadata)
        line = canonical(dict(body=body, hash=digest(body))) + "\n"
        readable = f'{body["utc"]} #{seq} {canonical(operation)} actor={canonical(actor)} ids={canonical(list(ids))}\n'
        try:
            for name, text in (("audit.jsonl", line), ("transcript.log", readable)):
                fd = os.open(self.root / name, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
                try:
                    view = memoryview(text.encode("ascii", "backslashreplace"))
                    while view:
                        n = os.write(fd, view)
                        if n <= 0:
                            raise OSError("Audit write stopped")
                        view = view[n:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
            c.execute("INSERT INTO events(seq,body,hash) VALUES(?,?,?)", (seq, canonical(body), digest(body)))
            self.audit_stats = self._stats()
        except Exception:
            self.blocked = "Audit write failed. New changes are blocked."
            raise

    def _stats(self):
        return tuple((s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns) for s in ((self.root / n).stat() for n in ('audit.jsonl', 'transcript.log')))

    def verify(self):
        with self.lock, self.connect() as c:
            previous = "0" * 64
            rows = c.execute("SELECT seq,body,hash FROM events ORDER BY seq").fetchall()
            with (self.root / "audit.jsonl").open() as f, (self.root / 'transcript.log').open() as transcript:
                for row in rows:
                    item = json.loads(f.readline())
                    body = json.loads(row["body"])
                    if item != {"body": body, "hash": row["hash"]} or body["previous"] != previous or digest(body) != row["hash"]:
                        raise ValueError("Audit integrity failed")
                    expected = f'{body["utc"]} #{body["sequence"]} {canonical(body["operation"])} actor={canonical(body["actor"])} ids={canonical(body["ids"])}\n'
                    if transcript.readline() != expected:
                        raise ValueError('Transcript integrity failed')
                    previous = row["hash"]
                if f.read() or transcript.read():
                    raise ValueError("Uncommitted audit event")
            for row in c.execute("SELECT data FROM records WHERE kind='transfer_conflict'"):
                data = json.loads(row['data'])
                bundle_id = str(uuid.UUID(data['bundle_id']))
                name = f'transfer-conflict-{bundle_id}.age'
                if data.get('encrypted_bundle') != name:
                    raise ValueError('Conflict bundle locator is invalid')
                path = self.root / 'conflicts' / name
                private(path)
                if not path.is_file() or path.stat().st_size != data.get('ciphertext_size') or file_digest(path) != data.get('ciphertext_sha256'):
                    raise ValueError('Conflict bundle integrity failed')
            tables = {row[0] for row in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if 'harness_sources' in tables:
                for row in c.execute('SELECT * FROM harness_sources'):
                    card = json.loads(row['card'])
                    if (row['status'] not in ('active', 'revoked') or digest(card) != row['fingerprint']
                            or card.get('source_id') != row['source_id'] or (row['status'] == 'active') != (row['revoked_at'] is None)):
                        raise ValueError('Harness source enrollment integrity failed')
            if 'harness_envelopes' in tables:
                for row in c.execute('SELECT * FROM harness_envelopes'):
                    upload = self.get(row['upload_id'], c)
                    hashes = (row['signed_sha256'], row['observation_sha256'], row['artifact_sha256'])
                    trust = upload['data'].get('harness_trust', {}) if upload else {}
                    if (row['status'] not in ('uploaded', 'merged') or not upload or upload['kind'] != 'upload'
                            or upload['data'].get('format') != 'harness_observation_v1'
                            or upload['data'].get('sha256') != row['artifact_sha256']
                            or trust.get('envelope_id') != row['envelope_id'] or trust.get('observation_id') != row['observation_id']
                            or trust.get('source_id') != row['source_id'] or trust.get('signed_sha256') != row['signed_sha256']
                            or trust.get('observation_sha256') != row['observation_sha256']
                            or ('harness_sources' in tables and not c.execute('SELECT 1 FROM harness_sources WHERE source_id=?', (row['source_id'],)).fetchone())
                            or (row['status'] == 'merged') != (upload['data'].get('status') == 'merged')
                            or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z', row['recorded_at'] or '')
                            or any(not re.fullmatch(r'[0-9a-f]{64}', value or '') for value in hashes)):
                        raise ValueError('Harness envelope index integrity failed')
            export_groups = {}
            for path in (self.root / 'exports').iterdir():
                private(path)
                match = re.fullmatch(r'team-transfer-([0-9a-f]{64})\.(age|json)', path.name)
                if not match or not path.is_file():
                    raise ValueError('Outgoing transfer cache contains an unsupported entry')
                export_groups.setdefault(match.group(1), {})[match.group(2)] = path
            for review_hash, paths in export_groups.items():
                if set(paths) != {'age', 'json'}:
                    raise ValueError('Outgoing transfer cache is incomplete')
                metadata = json.loads(paths['json'].read_text())
                required = {'bundle_id', 'manifest_hash', 'record_ids', 'recipient_id', 'review_hash', 'sha256', 'bytes'}
                if (
                    set(metadata) != required
                    or metadata.get('review_hash') != review_hash
                    or metadata.get('bytes') != paths['age'].stat().st_size
                    or metadata.get('sha256') != file_digest(paths['age'])
                ):
                    raise ValueError('Outgoing transfer cache integrity failed')
            self.audit_stats = self._stats()
            return {"events": len(rows), "head": previous}

    @staticmethod
    def decode(row):
        if row is None:
            return None
        out = dict(row)
        out["data"] = json.loads(out["data"])
        return out

    def get(self, id, c=None):
        if c is not None:
            return self.decode(c.execute("SELECT * FROM records WHERE id=?", (id,)).fetchone())
        with self.connect() as con:
            return self.get(id, con)

    def records(self, kind=None):
        with self.connect() as c:
            rows = c.execute("SELECT * FROM records WHERE (? IS NULL OR kind=?) ORDER BY updated_at DESC,id", (kind, kind))
            return [self.decode(r) for r in rows]

    def put(self, c, kind, data, actor, id=None, base=None):
        id = id or str(uuid.uuid4())
        current = self.get(id, c)
        if current and (current["revision_id"] != base or current["kind"] != kind):
            raise Conflict(current)
        revision, now = str(uuid.uuid4()), utc()
        encoded = canonical(data)
        c.execute("INSERT INTO records VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET revision_id=excluded.revision_id,data=excluded.data,updated_at=excluded.updated_at", (id, kind, revision, encoded, now))
        c.execute("INSERT INTO revisions VALUES(?,?,?,?,?,?)", (revision, id, base, actor, encoded, now))
        return self.get(id, c)

    def setting(self, key, default=None):
        with self.connect() as c:
            row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return json.loads(row[0]) if row else default

    def configure(self, key, value, actor="operator"):
        with self.tx() as c:
            c.execute("INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, canonical(value)))
            self.event(c, actor, "configuration.changed", [key])
