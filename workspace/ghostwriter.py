"""Reviewed report-specific Ghostwriter proposals with uncertain-send handling."""
import json
from urllib.parse import urlsplit
import httpx
from fastapi import HTTPException, Request
from markdown_it import MarkdownIt
from . import APP_NAME
from .models import Review
from .store import digest, private

ADAPTER = 'ghostwriter-reportedFinding-v7.2.6-1'
FIELDS = {'title', 'description', 'impact', 'mitigation', 'references', 'reportId', 'severityId', 'findingTypeId', 'position', 'extra_fields', 'complete', 'added_as_blank'}
PROBE = '''query MerlinSchema { __type(name:"reportedFinding_insert_input") { inputFields { name } } __schema { mutationType { fields { name } } } }'''
CREATE = '''mutation MerlinCreate($object: reportedFinding_insert_input!) { insert_reportedFinding_one(object:$object) { id reportId title extra_fields } }'''
LOOKUP = '''query MerlinReceipt($id:bigint!) { reportedFinding_by_pk(id:$id) { id reportId title extra_fields } }'''


def html(text):
    md = MarkdownIt('commonmark', {'html': False, 'linkify': False}).enable('table')
    md.add_render_rule('image', lambda renderer, tokens, idx, options, env: '[Attach reviewed evidence in Ghostwriter]')
    return md.render(text)


def request_graphql(store, query, variables, operation):
    config = store.setting('ghostwriter', {})
    if not config:
        raise RuntimeError('Configure an approved Ghostwriter test report first.')
    origin = config['origin']
    u = urlsplit(origin)
    synthetic_loopback = store.setting('config', {}).get('mode') == 'synthetic' and u.scheme == 'http' and u.hostname in ('127.0.0.1', 'localhost')
    if u.scheme != 'https' and not synthetic_loopback or u.username or u.password or u.query or u.fragment or u.path not in ('', '/'):
        raise RuntimeError('Ghostwriter requires an exact HTTPS origin.')
    token_path = store.root / 'keys' / 'ghostwriter.token'
    private(token_path)
    token = token_path.read_text().strip()
    with httpx.Client(trust_env=False, follow_redirects=False, timeout=30) as client:
        with client.stream('POST', origin.rstrip('/') + '/v1/graphql', json={'operationName': operation, 'query': query, 'variables': variables}, headers={'Authorization': 'Bearer ' + token}) as response:
            raw = bytearray()
            for chunk in response.iter_bytes():
                raw.extend(chunk)
                if len(raw) > 1024 * 1024:
                    raise ValueError('Ghostwriter response exceeded its limit')
            if response.status_code != 200:
                raise ValueError('Ghostwriter rejected the request')
    data = json.loads(raw)
    if data.get('errors') or not isinstance(data.get('data'), dict):
        raise ValueError('Ghostwriter did not confirm the operation')
    return data['data']


def verify_adapter(store):
    result = request_graphql(store, PROBE, {}, 'MerlinSchema')
    fields = {f['name'] for f in (result.get('__type') or {}).get('inputFields', [])}
    mutations = {f['name'] for f in result.get('__schema', {}).get('mutationType', {}).get('fields', [])}
    if not FIELDS <= fields or 'insert_reportedFinding_one' not in mutations:
        raise RuntimeError('This Ghostwriter schema is not supported by the installed adapter.')
    return digest({'adapter': ADAPTER, 'fields': sorted(fields), 'mutation': 'insert_reportedFinding_one'})


def payload(store, draft, proposal_id):
    c = store.setting('ghostwriter', {})
    if not c or not c.get('schema_hash'):
        raise RuntimeError('Verify the Ghostwriter adapter before review.')
    d = draft['data']
    if d.get('evidence_ids'):
        raise RuntimeError('This adapter has not passed file-attachment acceptance. Use the encrypted evidence bundle and attach files in Ghostwriter. No finding was sent.')
    return dict(title=d['title'], description=html(d['description']), impact=html(d['impact']), mitigation=html(d['remediation']), references=html(d['references']), reportId=int(c['report_id']), severityId=int(c['severity_id']), findingTypeId=int(c['finding_type_id']), position=0, complete=False, added_as_blank=True, extra_fields={'merlin_proposal_id': proposal_id, 'merlin_revision_id': draft['revision_id']})


def routes(app, store, actor, admin, record):
    def merlin(request):
        if APP_NAME != 'Merlin':
            raise HTTPException(403, 'Ghostwriter delivery belongs to Merlin.')
        admin(request)

    @app.get('/api/deliveries')
    def deliveries():
        values = store.records('delivery')
        # Do not send stored outgoing payloads to status-only clients.
        return {'items': [{**r, 'data': {k: v for k, v in r['data'].items() if k != 'payload'}} for r in values], 'total': len(values)}

    @app.get('/api/deliveries/{id}')
    def delivery(id: str):
        r = record(id, 'delivery')
        return {**r, 'data': {k: v for k, v in r['data'].items() if k != 'payload'}}

    @app.post('/api/deliveries/review')
    def review(body: Review, request: Request):
        merlin(request)
        draft = record(body.draft_id, 'draft')
        config = store.setting('ghostwriter', {})
        if str(config.get('report_id')) != body.report_id:
            raise HTTPException(422, 'Select the report approved on this host.')
        import uuid
        id = str(uuid.uuid4())
        outgoing = payload(store, draft, id)
        with store.tx() as c:
            for prior in c.execute("SELECT data FROM records WHERE kind='delivery'"):
                d = json.loads(prior[0])
                if d.get('draft_id') != draft['id']:
                    continue
                if d.get('status') in ('reviewed', 'sending', 'uncertain'):
                    raise HTTPException(409, 'This draft has an active or uncertain delivery. Resolve it before another review.')
                if d.get('status') == 'delivered':
                    raise HTTPException(409, 'This draft was delivered. Make later wording changes in Ghostwriter or create a separately reviewed finding.')
            r = store.put(c, 'delivery', dict(status='reviewed', draft_id=draft['id'], revision_id=draft['revision_id'], report_id=body.report_id, payload_hash=digest(outgoing), payload=outgoing, config_hash=digest(config), approved_by=actor(request)), actor(request), id)
            store.event(c, actor(request), 'delivery.reviewed', [id, draft['id']], payload_hash=digest(outgoing), report_id=body.report_id)
        return delivery(id)

    @app.post('/api/deliveries/{id}/send')
    def send(id: str, request: Request):
        merlin(request)
        with store.tx() as c:
            r = store.get(id, c)
            if not r or r['kind'] != 'delivery' or r['data']['status'] != 'reviewed':
                raise HTTPException(409, 'Only a reviewed, unsent proposal can be sent.')
            d = r['data']
            current = store.get(d['draft_id'], c)
            if current['revision_id'] != d['revision_id'] or d['config_hash'] != digest(store.setting('ghostwriter', {})) or digest(d['payload']) != d['payload_hash']:
                raise HTTPException(409, 'The draft or connection changed. Review a new proposal.')
            r = store.put(c, 'delivery', {**d, 'status': 'sending'}, actor(request), id, r['revision_id'])
            store.event(c, actor(request), 'delivery.dispatch', [id], payload_hash=d['payload_hash'])
        state, remote_id = 'uncertain', None
        try:
            result = request_graphql(store, CREATE, {'object': d['payload']}, 'MerlinCreate').get('insert_reportedFinding_one')
            if result and str(result.get('reportId')) == d['report_id'] and result.get('extra_fields', {}).get('merlin_proposal_id') == id:
                remote_id, state = result['id'], 'delivered'
        except Exception:
            # An error after dispatch does not prove the server performed no mutation.
            state = 'uncertain'
        with store.tx() as c:
            store.put(c, 'delivery', {**r['data'], 'status': state, 'remote_id': remote_id}, actor(request), id, r['revision_id'])
            store.event(c, actor(request), 'delivery.result', [id], outcome=state, remote_id=remote_id)
        return delivery(id)

    @app.post('/api/deliveries/{id}/reconcile')
    def reconcile(id: str, request: Request, remote_id: int):
        merlin(request)
        r = record(id, 'delivery')
        if r['data']['status'] != 'uncertain':
            raise HTTPException(409, 'Only uncertain delivery requires reconciliation.')
        result = request_graphql(store, LOOKUP, {'id': remote_id}, 'MerlinReceipt').get('reportedFinding_by_pk')
        if not result or str(result.get('reportId')) != r['data']['report_id'] or result.get('extra_fields', {}).get('merlin_proposal_id') != id:
            raise HTTPException(409, 'This remote finding does not prove receipt. The proposal remains uncertain.')
        with store.tx() as c:
            store.put(c, 'delivery', {**r['data'], 'status': 'delivered', 'remote_id': remote_id}, actor(request), id, r['revision_id'])
            store.event(c, actor(request), 'delivery.reconciled', [id], remote_id=remote_id)
        return delivery(id)
