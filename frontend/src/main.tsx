import React, { useEffect, useRef, useState } from 'react'
import cytoscape, { Core } from 'cytoscape'
import { ApiError, api, Asset, downloadJson, Graph, RecordItem, Session } from './api'
import './styles.css'

const TRACKS = ['network', 'web', 'linux', 'windows_ad', 'database_service']
const EVIDENCE_STATES = ['candidate', 'observed', 'confirmed', 'incomplete', 'unsupported'] as const
const WRITING_STATES = ['draft', 'needs_evidence', 'ready', 'submitted'] as const
const nav = [['overview', 'Map'], ['imports', 'Imports'], ['findings', 'Findings'], ['evidence', 'Evidence'], ['transfer', 'Transfer']] as const

function ErrorMessage({ error }: { error: unknown }) { return error ? <div className="error" role="alert"><strong>Could not complete that request.</strong><span>{error instanceof Error ? error.message : 'The service returned an unreadable error.'}</span></div> : null }
function Empty({ title, body }: { title: string; body: string }) { return <div className="empty"><strong>{title}</strong><span>{body}</span></div> }
function Login({ onLogin }: { onLogin: (value: Session) => void }) { const [name, setName] = useState(''); const [password, setPassword] = useState(''); const [error, setError] = useState<unknown>(null); async function submit(e: React.FormEvent) { e.preventDefault(); try { const value = await api.post<Session>('/api/login', { name, password }); api.csrf = value.csrf; onLogin(value) } catch (err) { setError(err) } } return <main className="login"><div className="login-card"><h1>Keep the evidence moving.</h1><form onSubmit={submit}><label>Account name<input required value={name} onChange={e => setName(e.target.value)} /></label><label>Password<input required type="password" value={password} onChange={e => setPassword(e.target.value)} /></label><ErrorMessage error={error} /><button className="primary">Sign in</button></form></div></main> }

function GraphCanvas({ graph, selected, onSelect }: { graph: Graph | null; selected: string | null; onSelect: (id: string) => void }) {
  const host = useRef<HTMLDivElement>(null); const instance = useRef<Core | null>(null); const selectRef = useRef(onSelect); const identity = useRef(''); selectRef.current = onSelect
  useEffect(() => { if (!host.current) return; try { instance.current = cytoscape({ container: host.current, headless: /jsdom/i.test(navigator.userAgent), elements: [], layout: { name: 'preset' }, style: [{ selector: 'node', style: { label: 'data(label)', 'background-color': '#55C7D3', color: '#061524', width: 38, height: 38 } }, { selector: 'edge', style: { 'line-color': '#A8BDC9', 'target-arrow-color': '#A8BDC9', 'target-arrow-shape': 'triangle' } }, { selector: ':selected', style: { 'background-color': '#F1BC5B' } }] }); instance.current.on('tap', 'node', e => selectRef.current(e.target.id())) } catch { instance.current = null }; return () => instance.current?.destroy() }, [])
  useEffect(() => { const cy = instance.current; if (!cy || !graph) return; const nextIdentity = `${graph.nodes.map(n => n.id).sort().join(',')}|${graph.edges.map(e => `${e.id}:${e.source}:${e.target}`).sort().join(',')}`; const changed = identity.current !== nextIdentity; const ids = new Set(graph.nodes.map(n => n.id)); cy.nodes().filter(n => !ids.has(n.id())).remove(); cy.edges().filter(e => !graph.edges.some(next => next.id === e.id())).remove(); graph.nodes.forEach(n => cy.getElementById(n.id).length ? cy.getElementById(n.id).data(n) : cy.add({ data: n })); graph.edges.forEach(e => cy.getElementById(e.id).length ? cy.getElementById(e.id).data(e) : cy.add({ data: e })); if (changed && cy.nodes().length && !/jsdom/i.test(navigator.userAgent)) cy.layout({ name: 'cose', animate: false, randomize: false }).run(); identity.current = nextIdentity }, [graph])
  useEffect(() => { instance.current?.nodes().unselect(); if (selected) instance.current?.getElementById(selected).select() }, [selected])
  return <div className="graph" ref={host} aria-label="Evidence relationship map" />
}

function Overview({ refreshKey }: { refreshKey: number }) {
  const [track, setTrack] = useState(''); const [typed, setTyped] = useState(''); const [q, setQ] = useState(''); const [page, setPage] = useState(0); const [graph, setGraph] = useState<Graph | null>(null); const [assets, setAssets] = useState<Asset[]>([]); const [total, setTotal] = useState(0); const [selected, setSelected] = useState<string | null>(null); const [error, setError] = useState<unknown>(null); const [graphError, setGraphError] = useState<unknown>(null); const [view, setView] = useState<'map' | 'table'>('map'); const limit = 100
  async function load(nextQ = q, nextTrack = track, nextPage = page) { setError(null); const args = new URLSearchParams({ q: nextQ, track: nextTrack }); const [a, g] = await Promise.allSettled([api.get<{ items: Asset[]; total?: number }>(`/api/assets?${new URLSearchParams({ q: nextQ, track: nextTrack, offset: String(nextPage * limit), limit: String(limit) })}`), api.get<Graph>(`/api/graph?${args}`)]); if (a.status === 'fulfilled') { setAssets(a.value.items); setTotal(a.value.total ?? a.value.items.length); setSelected(old => old && a.value.items.some(x => x.id === old) ? old : a.value.items[0]?.id ?? null) } else setError(a.reason); if (g.status === 'fulfilled') setGraph(g.value); else setGraphError(g.reason) }
  useEffect(() => { void load() }, [page, track, q, refreshKey])
  function choosePage(next: number) { setPage(next) }
  function selectRow(id: string) { setSelected(id) }
  return <section><div className="page-head"><div><h2>Evidence map</h2><p className="muted">Select a node or row to keep relationships and source artifacts in view.</p></div><span className="count">Showing {assets.length} of {total} assets · graph {graph?.total_nodes ?? 0} nodes{graph && graph.total_nodes > assets.length ? ' (graph is capped to its own result)' : ''}</span></div><form className="toolbar" onSubmit={e => { e.preventDefault(); setQ(typed); setPage(0) }}><input aria-label="Search assets" value={typed} onChange={e => setTyped(e.target.value)} placeholder="Search assets" /><button>Search</button><div role="group" aria-label="Track filters">{['', ...TRACKS].map(value => <button type="button" aria-pressed={track === value} key={value || 'all'} onClick={() => { setTrack(value); setPage(0) }}>{value || 'All tracks'}</button>)}</div><div className="view-switch"><button type="button" aria-pressed={view === 'map'} onClick={() => setView('map')}>Map</button><button type="button" aria-pressed={view === 'table'} onClick={() => setView('table')}>Table</button></div></form><ErrorMessage error={error} /><div className={`map-grid ${view === 'table' ? 'table-only' : ''}`}>{graph ? <GraphCanvas graph={graph} selected={selected} onSelect={selectRow} /> : <div className="panel"><strong>Relationship map unavailable.</strong><ErrorMessage error={graphError} /></div>}<div className="table-wrap"><table><thead><tr><th>Asset</th><th>Kind</th><th>Track</th><th>Revision</th></tr></thead><tbody>{assets.map(asset => <tr key={asset.id} tabIndex={0} aria-selected={asset.id === selected} className={asset.id === selected ? 'selected' : ''} onClick={() => selectRow(asset.id)} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selectRow(asset.id) } }}><td>{asset.label}</td><td>{asset.kind}</td><td>{asset.track}</td><td className="mono">{asset.revision_id.slice(0, 8)}</td></tr>)}</tbody></table><div className="actions" aria-label="Asset pages"><button disabled={page === 0} onClick={() => choosePage(page - 1)}>Previous</button><span className="count">Page {page + 1}</span><button disabled={(page + 1) * limit >= total} onClick={() => choosePage(page + 1)}>Next</button></div>{selected && <aside className="inspector"><span className="mono">Selected asset: {selected}</span></aside>}</div></div></section>
}

type Upload = RecordItem & { data: { filename?: string; format?: string; status?: string; limitations?: string[]; sha256?: string; size?: number } }
type MergeBinding = { upload_revision_id: string; preview_revision_id: string; preview_hash: string }
type UploadPreview = { _review: MergeBinding; assets: unknown[]; relationships: unknown[]; observations: unknown[]; limitations: string[]; complete: boolean }
function Imports({ refreshKey, online = true }: { refreshKey: number; online?: boolean }) {
  const [items, setItems] = useState<Upload[]>([]); const [file, setFile] = useState<File | null>(null); const [format, setFormat] = useState('manual_json'); const [selected, setSelected] = useState<Upload | null>(null); const [preview, setPreview] = useState<UploadPreview | null>(null); const [binding, setBinding] = useState<MergeBinding | null>(null); const [error, setError] = useState<unknown>(null); const [parsing, setParsing] = useState(false); const request = useRef(0)
  useEffect(() => { setPreview(null); setBinding(null); void api.get<{ items: Upload[] }>('/api/uploads').then(r => setItems(r.items)).catch(setError) }, [refreshKey])
  function choose(item: Upload) { if (parsing) return; request.current++; setSelected(item); setPreview(null); setBinding(null) }
  async function upload() { if (!online || !file || parsing) return; try { const form = new FormData(); form.append('file', file); form.append('format', format); const item = await api.post<Upload>('/api/uploads', form); setItems(old => [item, ...old]); setSelected(item); setPreview(null); setBinding(null); setFile(null) } catch (err) { setError(err) } }
  async function parse() { if (!online || !selected || parsing) return; const number = ++request.current; const item = selected; setParsing(true); setPreview(null); setBinding(null); setError(null); try { const updated = await api.post<Upload>(`/api/uploads/${item.id}/parse`); setSelected(updated); setItems(old => old.map(x => x.id === updated.id ? updated : x)); const value = await api.get<UploadPreview>(`/api/uploads/${updated.id}/preview`); if (number === request.current) { setPreview(value); setBinding(value._review) } } catch (err) { if (number === request.current) setError(err) } finally { if (number === request.current) setParsing(false) } }
  async function merge() { if (!online || !selected || !preview || !binding || parsing) return; try { const item = await api.post<Upload>(`/api/uploads/${selected.id}/merge`, binding); setSelected(item); setItems(old => old.map(x => x.id === item.id ? item : x)); setPreview(null); setBinding(null) } catch (err) { setError(err); if (err instanceof ApiError && err.status === 409) { setPreview(null); setBinding(null) } } }
  return <section><h2>Imports</h2><div className="split"><div className="panel"><label>Format<select value={format} onChange={e => { setFormat(e.target.value); setPreview(null); setBinding(null) }}>{['nmap_xml', 'nmap_text', 'nmap_gnmap', 'zap_json', 'har', 'burp_xml', 'linpeas_text', 'winpeas_text', 'bloodhound', 'manual_json'].map(v => <option key={v}>{v}</option>)}</select></label><label>File<input type="file" disabled={!online} onChange={e => { setFile(e.target.files?.[0] ?? null); setPreview(null); setBinding(null) }} /></label><button className="primary" disabled={!online || !file || parsing} onClick={() => void upload()}>Upload source</button></div><div className="panel"><ErrorMessage error={error} />{items.map(item => <button key={item.id} disabled={parsing} className="list-row" onClick={() => choose(item)}><span><strong>{item.data.filename ?? item.id}</strong><small>{item.data.format} · {item.data.status}</small></span></button>)}</div></div>{selected && <div className="panel"><div className="actions"><button aria-live="polite" disabled={!online || parsing} onClick={() => void parse()}>{parsing ? 'Parsing preview…' : 'Parse preview'}</button><button className="primary" disabled={!online || parsing || !preview || !binding} onClick={() => void merge()}>Merge records</button></div>{preview ? <pre className="preview">{JSON.stringify(preview, null, 2)}</pre> : <p>{parsing ? 'Parsing source in a contained preview…' : 'Preview output appears here after parsing.'}</p>}</div>}</section>
}

function DirtyDialog({ onSave, onDiscard, onStay }: { onSave: () => void; onDiscard: () => void; onStay: () => void }) { return <div className="dialog-backdrop"><div className="dialog" role="dialog" aria-modal="true" aria-labelledby="dirty-title"><h2 id="dirty-title">Unsaved finding changes</h2><p>Save before leaving, stay here, or discard the local changes.</p><button className="primary" onClick={onSave}>Save and leave</button><button onClick={onStay}>Stay</button><button onClick={onDiscard}>Discard changes</button></div></div> }
function Field({ label, value, update, area = false, maxLength }: { label: string; value: string; update: (value: string) => void; area?: boolean; maxLength?: number }) { return <label>{label}{area ? <textarea aria-label={label} rows={4} maxLength={maxLength} value={value} onChange={e => update(e.target.value)} /> : <input aria-label={label} maxLength={maxLength} value={value} onChange={e => update(e.target.value)} />}{maxLength && <small>{value.length}/{maxLength}</small>}</label> }
function Findings({ session, refreshKey, onDirty, online = true }: { session: Session; refreshKey: number; onDirty: (value: boolean, save: () => Promise<boolean>, discard: () => void) => void; online?: boolean }) {
  const [items, setItems] = useState<RecordItem[]>([]); const [selected, setSelected] = useState<RecordItem | null>(null); const [draft, setDraft] = useState<Record<string, unknown>>({}); const [assets, setAssets] = useState<Asset[]>([]); const [evidence, setEvidence] = useState<RecordItem[]>([]); const [error, setError] = useState<unknown>(null); const [conflict, setConflict] = useState<RecordItem | null>(null); const [dirty, setDirty] = useState(false); const [submission, setSubmission] = useState(''); const [pending, setPending] = useState<(() => void) | null>(null)
  const selectedRef = useRef(selected); const draftRef = useRef(draft); const dirtyRef = useRef(dirty); selectedRef.current = selected; draftRef.current = draft; dirtyRef.current = dirty
  function setRecord(item: RecordItem | null, data = item?.data ?? {}) { setSelected(item); setDraft(data); setDirty(false); setConflict(null) }
  async function load() { try { const [records, assetResult, evidenceResult] = await Promise.all([api.get<{ items: RecordItem[] }>('/api/records?kind=finding'), api.get<{ items: Asset[] }>('/api/assets?offset=0&limit=100'), api.get<{ items: RecordItem[] }>('/api/evidence')]); setItems(records.items); setAssets(assetResult.items); setEvidence(evidenceResult.items); const active = selectedRef.current; if (!active && records.items[0]) setRecord(records.items[0]); else if (active) { const current = records.items.find(item => item.id === active.id); if (current && current.revision_id !== active.revision_id) { if (dirtyRef.current) setConflict(current); else setRecord(current) } } } catch (err) { setError(err) } }
  useEffect(() => { void load() }, [refreshKey]); useEffect(() => { const f = (e: BeforeUnloadEvent) => { if (dirty) { e.preventDefault(); e.returnValue = '' } }; addEventListener('beforeunload', f); return () => removeEventListener('beforeunload', f) }, [dirty])
  const text = (key: string) => String(draft[key] ?? '')
  function update(key: string, value: unknown) { setDraft(old => ({ ...old, [key]: value })); setDirty(true); setSubmission('') }
  function choose(action: () => void) { dirty ? setPending(() => action) : action() }
  function valid() { return text('title').trim() && text('title').length <= 180 && text('observation').length <= 12000 }
  async function save() { if (!online) return false; if (!valid()) { setError(new Error('A title is required; title limit is 180 and observation limit is 12,000.')); return false } try { const keys = ['title', 'observation', 'impact', 'steps', 'asset_ids', 'evidence_ids', 'evidence_needed', 'owner_id', 'evidence_state', 'writing_state', 'notes']; const data = Object.fromEntries(keys.map(key => [key, draftRef.current[key]])); data.asset_ids = Array.isArray(data.asset_ids) ? data.asset_ids : []; data.evidence_ids = Array.isArray(data.evidence_ids) ? data.evidence_ids : []; const old = selectedRef.current; const result = old ? await api.put<RecordItem>(`/api/records/${old.id}`, { base_revision_id: old.revision_id, data }) : await api.post<RecordItem>('/api/records', { kind: 'finding', data }); setRecord(result); setItems(all => old ? all.map(x => x.id === result.id ? result : x) : [result, ...all]); return true } catch (err) { if (err instanceof ApiError && err.status === 409) setConflict((err.detail as { current?: RecordItem }).current ?? null); else setError(err); return false } }
  function keepLocal() { if (!conflict) return; const rebased = { ...conflict, data: draftRef.current }; setSelected(rebased); setDraft(draftRef.current); setDirty(true); setConflict(null) }
  useEffect(() => onDirty(dirty, save, () => setRecord(selectedRef.current)), [dirty, draft, selected])
  async function submit() { if (!online || !selected || dirty) return; try { await api.post(`/api/findings/${selected.id}/submit`, { base_revision_id: selected.revision_id }); const current = await api.get<RecordItem>(`/api/records/${selected.id}`); setRecord(current); setItems(all => all.map(item => item.id === current.id ? current : item)); setSubmission('Submitted to lead. The technical finding remains open for editing.') } catch (err) { setError(err); if (err instanceof ApiError && err.status === 409) setSubmission('') } }
  const toggle = (key: 'asset_ids' | 'evidence_ids', id: string) => { const old = Array.isArray(draft[key]) ? draft[key] as string[] : []; update(key, old.includes(id) ? old.filter(x => x !== id) : [...old, id]) }
  return <section><div className="page-head"><h2>Findings</h2><button className="primary" onClick={() => choose(() => { setRecord(null, { title: '', observation: '', impact: '', steps: '', asset_ids: [], evidence_ids: [], evidence_state: 'candidate', writing_state: 'draft', evidence_needed: '', notes: '', owner_id: '' }); setDirty(true) })}>New finding</button></div><ErrorMessage error={error} />{submission && <div className="notice" role="status">{submission} Lead is ready in Transfer.</div>}<div className="editor-grid"><aside className="panel">{items.map(item => <button className="list-row" key={item.id} onClick={() => choose(() => setRecord(item))}>{String(item.data.title || 'Untitled finding')}</button>)}</aside><div className="panel"><div className="actions"><button className="primary" disabled={!online || !dirty} onClick={() => void save()}>Save</button><button disabled={!online || !selected || dirty || text('writing_state') === 'submitted'} onClick={() => void submit()}>Submit to lead</button><button onClick={() => downloadJson('harbinger-finding.json', { kind: 'finding', data: draft })}>Save draft file</button></div>{conflict && <div className="conflict"><strong>Server changed. Local edits remain unsaved.</strong><p>Local: {text('observation')}</p><p>Server: <span>{String(conflict.data.observation ?? '')}</span></p><button onClick={() => setRecord(conflict)}>Use server version</button><button onClick={keepLocal}>Keep local version</button></div>}<div className="form-grid"><Field label="Title" maxLength={180} value={text('title')} update={v => update('title', v)} /><Field label="Owner ID" value={text('owner_id')} update={v => update('owner_id', v)} /><label>Evidence state<select value={text('evidence_state')} onChange={e => update('evidence_state', e.target.value)}>{EVIDENCE_STATES.map(v => <option key={v} disabled={v === 'confirmed' && session.user?.role !== 'captain'}>{v}</option>)}</select>{text('evidence_state') === 'confirmed' && <small>{session.user?.role === 'captain' ? 'Captain-controlled confirmation.' : 'Confirmation is captain-controlled.'}</small>}</label><label>Writing state<select value={text('writing_state')} onChange={e => update('writing_state', e.target.value)}>{WRITING_STATES.filter(v => v !== 'submitted').map(v => <option key={v}>{v}</option>)}</select><small>Submitted is set by lead submission.</small></label><Field label="Observation" area maxLength={12000} value={text('observation')} update={v => update('observation', v)} /><Field label="Impact" area value={text('impact')} update={v => update('impact', v)} /><Field label="Steps to reproduce" area value={text('steps')} update={v => update('steps', v)} /><Field label="Evidence needed" area value={text('evidence_needed')} update={v => update('evidence_needed', v)} /><Field label="Notes" area value={text('notes')} update={v => update('notes', v)} /></div><fieldset><legend>Assets in scope</legend>{assets.map(a => <label key={a.id}><input type="checkbox" checked={Array.isArray(draft.asset_ids) && (draft.asset_ids as string[]).includes(a.id)} onChange={() => toggle('asset_ids', a.id)} />{a.label}</label>)}</fieldset><fieldset><legend>Supporting evidence</legend>{evidence.map(e => <label key={e.id}><input type="checkbox" checked={Array.isArray(draft.evidence_ids) && (draft.evidence_ids as string[]).includes(e.id)} onChange={() => toggle('evidence_ids', e.id)} />{String(e.data.filename || e.id)}</label>)}</fieldset><p className="save-state" aria-live="polite">{conflict ? 'Server changed · local edits are unsaved; compare before saving.' : !online ? 'Not saved · connection lost. Keep editing locally or save a draft file.' : dirty ? 'Unsaved changes · Save before review or navigation.' : 'Saved revision is current.'}</p></div></div>{pending && <DirtyDialog onStay={() => setPending(null)} onDiscard={() => { const next = pending; setRecord(selectedRef.current); setPending(null); next?.() }} onSave={() => void save().then(ok => { if (ok) { const next = pending; setPending(null); next?.() } })} />}</section>
}

type EvidencePreview = { text: string; quarantined: boolean; base_revision_id: string; artifact_sha256: string }
function Evidence({ session, refreshKey, online = true }: { session: Session; refreshKey: number; online?: boolean }) {
  const [items, setItems] = useState<RecordItem[]>([]); const [selected, setSelected] = useState<RecordItem | null>(null); const [preview, setPreview] = useState<EvidencePreview | null>(null); const [reviewed, setReviewed] = useState(false); const [error, setError] = useState<unknown>(null); const request = useRef(0)
  useEffect(() => { setPreview(null); setReviewed(false); void api.get<{ items: RecordItem[] }>('/api/evidence').then(r => setItems(r.items)).catch(setError) }, [refreshKey])
  async function choose(item: RecordItem) { const id = ++request.current; setSelected(item); setPreview(null); setReviewed(false); try { const value = await api.get<EvidencePreview>(`/api/evidence/${item.id}/preview`); if (id === request.current) setPreview(value) } catch (err) { if (id === request.current) setError(err) } }
  async function approve() { if (!online || !selected || !reviewed || !preview || preview.quarantined) return; const reviewedPreview = preview; try { const next = await api.post<RecordItem>(`/api/evidence/${selected.id}/approve-export`, { base_revision_id: reviewedPreview.base_revision_id, artifact_sha256: reviewedPreview.artifact_sha256 }); setSelected(next); setItems(all => all.map(x => x.id === next.id ? next : x)); setPreview(null); setReviewed(false) } catch (err) { setError(err); if (err instanceof ApiError && err.status === 409) { setPreview(null); setReviewed(false) } } }
  const canApprove = Boolean(selected && preview && !preview.quarantined && session.user?.role === 'captain' && !selected.data.reviewed_for_export)
  return <section><h2>Evidence</h2><ErrorMessage error={error} /><div className="editor-grid"><aside className="panel">{items.map(item => <button key={item.id} className="list-row" onClick={() => void choose(item)}>{String(item.data.filename || item.id)}</button>)}</aside><div className="panel">{selected && preview ? <><p>{preview.quarantined ? 'Quarantined source · export approval is unavailable.' : selected.data.reviewed_for_export ? 'Reviewed derivative approved for export.' : 'Review a sanitized derivative before approving export.'}</p><pre className="preview">{preview.text}</pre>{canApprove && <label><input type="checkbox" disabled={!online} checked={reviewed} onChange={e => setReviewed(e.target.checked)} />I reviewed the sanitized derivative</label>}<button disabled={!online || !canApprove || !reviewed} onClick={() => void approve()}>Approve reviewed derivative</button></> : <Empty title="Select evidence" body="Choose a record to inspect its text." />}</div></div></section>
}

type TransferReceipt = { status: 'imported' | 'conflict'; imported: number; duplicates: number; conflicts: string[]; deferred: string[]; bundle_id: string; manifest_hash: string }
type TransferConflict = RecordItem & { data: Record<string, unknown> & { bundle_id?: string; manifest_hash?: string; state?: string; conflict_ids?: string[]; duplicate_ids?: string[]; deferred_ids?: string[]; incoming?: RecordItem[] }; local?: RecordItem[] }
type TransferReview = { review_hash: string; selected_record_ids: string[]; recipient: { id: string; name: string; origin: string }; records: (RecordItem & { selected?: boolean })[]; files: { id: string; size: number; sha256: string }[] }

function TransferRecordDiff({ id, incoming, local }: { id: string; incoming?: RecordItem; local?: RecordItem }) {
  const incomingData = incoming?.data ?? {}; const localData = local?.data ?? {}; const fields = Array.from(new Set([...Object.keys(incomingData), ...Object.keys(localData)])).filter(key => JSON.stringify(incomingData[key]) !== JSON.stringify(localData[key])).sort()
  const value = (item: unknown) => { const text = typeof item === 'string' ? item : JSON.stringify(item, null, 2) ?? 'undefined'; return text.length > 360 ? <details><summary>{text.slice(0, 360)}…</summary><pre>{text}</pre></details> : <pre>{text}</pre> }
  const metadata = (record?: RecordItem) => <dl><dt>Kind</dt><dd>{record?.kind ?? 'missing local record'}</dd><dt>Record ID</dt><dd className="mono">{record?.id ?? id}</dd><dt>Revision</dt><dd className="mono">{record?.revision_id ?? 'not returned'}</dd><dt>Source instance</dt><dd className="mono">{String(record?.data.source_instance ?? 'not recorded')}</dd><dt>Source revision</dt><dd className="mono">{String(record?.data.source_revision_id ?? 'not recorded')}</dd></dl>
  return <details className="record-diff" open><summary>Conflicting record {id}: inspect all differing fields before accepting</summary><div className="diff-metadata"><div><strong>Incoming owner revision</strong>{metadata(incoming)}</div><div><strong>Current local revision</strong>{metadata(local)}</div></div>{fields.length ? <div className="diff-fields">{fields.map(field => <div className="diff-field" key={field}><strong>{field}</strong><div><span>Incoming</span>{value(incomingData[field])}</div><div><span>Local</span>{value(localData[field])}</div></div>)}</div> : <p>No data fields differ; inspect identity, revision, and provenance above.</p>}</details>
}

function TransferConflictReview({ canReview }: { canReview: boolean }) {
  const [items, setItems] = useState<TransferConflict[]>([])
  const [loaded, setLoaded] = useState(false)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState<unknown>(null)
  const [resolution, setResolution] = useState<{ decision: 'keep_local' | 'accept_incoming'; imported: number; duplicates: number; bundle_id: string; manifest_hash: string } | null>(null)
  async function load() {
    if (!canReview) return
    setError(null)
    try {
      const result = await api.get<{ items?: TransferConflict[] }>('/api/transfers/conflicts')
      setItems(result.items ?? [])
      setLoaded(true)
    } catch (err) { setError(err) }
  }
  useEffect(() => { void load() }, [canReview])
  async function resolve(item: TransferConflict, decision: 'keep_local' | 'accept_incoming') {
    if (!canReview) return
    setBusy(item.id)
    setError(null)
    try {
      const local = Array.isArray(item.local) ? item.local : []
      const result = await api.post<TransferConflict>(`/api/transfers/conflicts/${item.id}/resolve`, {
        decision,
        conflict_revision_id: item.revision_id,
        manifest_hash: String(item.data.manifest_hash ?? ''),
        local_revisions: Object.fromEntries(local.map(record => [record.id, record.revision_id])),
      })
      const data = result.data
      const conflicts = Array.isArray(data.conflict_ids) ? data.conflict_ids : []
      const deferred = Array.isArray(data.deferred_ids) ? data.deferred_ids : []
      const duplicates = Array.isArray(data.duplicate_ids) ? data.duplicate_ids : []
      setResolution({ decision, imported: decision === 'accept_incoming' ? conflicts.length + deferred.length : 0, duplicates: duplicates.length, bundle_id: String(data.bundle_id ?? ''), manifest_hash: String(data.manifest_hash ?? '') })
      await load()
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) await load()
      setError(err)
    } finally { setBusy('') }
  }
  if (!canReview) return null
  return <section className="conflict-review" aria-labelledby="transfer-conflicts">
    <h3 id="transfer-conflicts">Transfer conflict review</h3>
    <p className="muted">Keeping local records resolves the review while the encrypted bundle remains retained.</p>
    {resolution && <div className="receipt" role="status"><strong>{resolution.decision === 'accept_incoming' ? 'Incoming acceptance receipt' : 'Local-resolution receipt'}</strong><span>{resolution.decision === 'accept_incoming' ? `${resolution.imported} imported · ${resolution.duplicates} exact duplicates.` : 'Local records kept; encrypted bundle retained.'}</span><span className="mono">bundle {resolution.bundle_id} · manifest {resolution.manifest_hash}</span></div>}
    <ErrorMessage error={error} />
    {loaded && !items.length && <Empty title="No transfer conflicts" body="No encrypted bundles are waiting for host review." />}
    {items.map(item => {
      const data = item.data
      const conflicts = Array.isArray(data.conflict_ids) ? data.conflict_ids : []
      const duplicates = Array.isArray(data.duplicate_ids) ? data.duplicate_ids : []
      const deferred = Array.isArray(data.deferred_ids) ? data.deferred_ids : []
      const incoming = Array.isArray(data.incoming) ? data.incoming : []
      const local = Array.isArray(item.local) ? item.local : []
      const reviewReady = typeof data.manifest_hash === 'string' && local.length === conflicts.length && local.every(record => Boolean(record.revision_id))
      return <article className="panel" key={item.id}>
        <div className="detail-head"><div><strong>{String(data.state ?? 'needs_review')}</strong><p className="mono">bundle {String(data.bundle_id ?? '')}</p></div><span className="count">{conflicts.length} conflicts · {duplicates.length} duplicates · {deferred.length} deferred</span></div>
        <p>Keeping local records retains the encrypted bundle for audit and review. Accepting incoming accepts the preserved owner revision and deferred evidence only when the server confirms this conflict is eligible.</p>
        {conflicts.map(id => <TransferRecordDiff key={id} id={id} incoming={incoming.find(record => record.id === id)} local={local.find(record => record.id === id)} />)}
        <div className="actions"><button className="primary" disabled={data.state !== 'needs_review' || Boolean(busy) || !reviewReady} onClick={() => void resolve(item, 'keep_local')}>{busy === item.id ? 'Resolving…' : 'Keep local records'}</button><button disabled={data.state !== 'needs_review' || Boolean(busy) || !reviewReady} onClick={() => void resolve(item, 'accept_incoming')}>Accept incoming revision and deferred evidence</button></div>
      </article>
    })}
  </section>
}

function Transfer({ role = '', online = true }: { role?: string; online?: boolean }) {
  const [peers, setPeers] = useState<{ id: string; name: string; recipient: string; status: 'enrolled' }[]>([])
  const [leads, setLeads] = useState<RecordItem[]>([])
  const [leadTotal, setLeadTotal] = useState(0)
  const [leadPage, setLeadPage] = useState(0)
  const [selected, setSelected] = useState<string[]>([])
  const [recipient, setRecipient] = useState('')
  const [review, setReview] = useState<TransferReview | null>(null)
  const [file, setFile] = useState<File | null>(null)
  const [message, setMessage] = useState('')
  const [receipt, setReceipt] = useState<TransferReceipt | null>(null)
  const [error, setError] = useState<unknown>(null)
  const limit = 100
  const canTransfer = role === 'captain'
  async function loadLeads(page = leadPage) {
    try {
      const result = await api.get<{ items?: RecordItem[]; total?: number }>(`/api/records?kind=lead&limit=${limit}&offset=${page * limit}`)
      const next = result.items ?? []
      setLeads(next)
      setLeadTotal(result.total ?? next.length)
    } catch (err) { setError(err) }
  }
  useEffect(() => { void api.get<{ peers: typeof peers }>('/api/connections').then(result => setPeers(result.peers)).catch(setError) }, [])
  useEffect(() => { void loadLeads() }, [leadPage])
  function toggle(id: string) {
    setSelected(current => current.includes(id) ? current.filter(value => value !== id) : [...current, id])
    setReview(null)
  }
  async function reviewTransfer() {
    if (!online || !canTransfer) return
    setReview(null)
    setError(null)
    try {
      const result = await api.post<TransferReview>('/api/transfers/preview', { record_ids: selected, recipient_id: recipient })
      setReview(result)
      setMessage('Transfer selection reviewed. Send or save this exact encrypted bundle.')
    } catch (err) { setError(err) }
  }
  async function send() {
    if (!online || !canTransfer || !review) return
    try {
      const result = await api.post<TransferReceipt>('/api/transfers/send', { record_ids: selected, recipient_id: recipient, review_hash: review.review_hash })
      setReceipt(result)
      setMessage(result.status === 'conflict' ? `Conflict: no records imported; bundle ${result.bundle_id} is held for review.` : `Imported receipt for bundle ${result.bundle_id}.`)
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) setReview(null)
      setError(err)
    }
  }
  async function exportRecords() {
    if (!online || !canTransfer || !review) return
    try {
      const response = await fetch('/api/transfers/export', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': api.csrf ?? '' }, body: JSON.stringify({ record_ids: selected, recipient_id: recipient, review_hash: review.review_hash }) })
      if (!response.ok) {
        if (response.status === 409) setReview(null)
        throw new Error(`Export failed (${response.status})`)
      }
      const url = URL.createObjectURL(await response.blob())
      const link = document.createElement('a')
      link.href = url
      link.download = `harbinger-transfer-${Date.now()}.age`
      link.click()
      URL.revokeObjectURL(url)
      setMessage('Encrypted transfer saved locally.')
    } catch (err) { setError(err) }
  }
  async function importFile() {
    if (!online || !file || !canTransfer) return
    try {
      const form = new FormData()
      form.append('file', file)
      const result = await api.post<TransferReceipt>('/api/transfers/import', form)
      setReceipt(result)
      setMessage(result.status === 'conflict' ? `Conflict: no records imported; bundle ${result.bundle_id} is held for review.` : `Imported receipt for bundle ${result.bundle_id}.`)
    } catch (err) { setError(err) }
  }
  return <section>
    <h2>Encrypted transfer</h2>
    <ErrorMessage error={error} />
    {!canTransfer && <div className="uncertainty" role="status">Captain role is required on this host to send, export, import, or review transfer conflicts.</div>}
    {message && <div className="notice" role="status">{message}</div>}
    {receipt && <div className={`receipt ${receipt.status}`} role="status"><strong>{receipt.status}</strong><span>{receipt.status === 'conflict' ? 'No records imported while this bundle is held.' : `${receipt.imported} imported.`} {receipt.duplicates} exact duplicates · {receipt.conflicts.length} conflicts · {receipt.deferred.length} deferred.</span><span className="mono">bundle {receipt.bundle_id} · manifest {receipt.manifest_hash}</span>{receipt.conflicts.length > 0 && <ul aria-label="Conflicting record IDs">{receipt.conflicts.map(id => <li className="mono" key={id}>{id}</li>)}</ul>}{receipt.deferred.length > 0 && <ul aria-label="Deferred record IDs">{receipt.deferred.map(id => <li className="mono" key={id}>{id}</li>)}</ul>}</div>}
    <div className="split"><div className="panel">
      <label>Peer recipient<select value={recipient} onChange={event => { setRecipient(event.target.value); setReview(null) }}><option value="">Choose an enrolled peer</option>{peers.map(peer => <option key={peer.id} value={peer.id}>{peer.name} · {peer.status} · {peer.recipient}</option>)}</select></label>
      <fieldset><legend>Eligible leads</legend>{leads.length ? leads.map(lead => <label key={lead.id}><input type="checkbox" checked={selected.includes(lead.id)} onChange={() => toggle(lead.id)} />{String(lead.data.title || lead.data.finding_title || lead.id)}</label>) : <Empty title="No eligible leads" body="Submitted findings will appear here when ready for transfer." />}</fieldset>
      <div className="actions"><button disabled={leadPage === 0} onClick={() => setLeadPage(leadPage - 1)}>Previous leads</button><span className="count">{leadPage * limit + leads.length} of {leadTotal}</span><button disabled={(leadPage + 1) * limit >= leadTotal} onClick={() => setLeadPage(leadPage + 1)}>Next leads</button></div>
      <button disabled={!online || !canTransfer || !recipient || !selected.length} onClick={() => void reviewTransfer()}>Review transfer</button>
      {review && <div className="receipt" role="status"><strong>Reviewed transfer selection</strong><span>{review.selected_record_ids.length} selected · {review.records.length} total records · {review.files.length} evidence files</span><span>Recipient: {review.recipient.name} at {review.recipient.origin}</span><ul aria-label="Reviewed transfer records">{review.records.map(item => <li key={item.id}><strong>{item.selected ? 'Selected' : 'Dependency'}:</strong> {String(item.data.title ?? item.data.label ?? item.data.filename ?? item.id)} <span className="mono">{item.kind} · {item.revision_id}</span></li>)}</ul></div>}
      <div className="actions"><button className="primary" disabled={!online || !canTransfer || !review} onClick={() => void send()}>Send selected leads to peer</button><button disabled={!online || !canTransfer || !review} onClick={() => void exportRecords()}>Save encrypted file</button></div>
    </div><div className="panel"><input aria-label="Encrypted file" disabled={!online} type="file" onChange={event => setFile(event.target.files?.[0] ?? null)} /><button disabled={!online || !canTransfer || !file} onClick={() => void importFile()}>Import and reconcile</button></div></div>
    <TransferConflictReview canReview={online && canTransfer} />
  </section>
}

function Shell({ session, onLogout }: { session: Session; onLogout: () => void }) { const [route, setRoute] = useState('overview'); const [refresh, setRefresh] = useState(0); const [status, setStatus] = useState('connecting'); const [last, setLast] = useState('not yet'); const dirty = useRef(false); const save = useRef<() => Promise<boolean>>(async () => true); const discard = useRef<() => void>(() => undefined); const [pending, setPending] = useState<(() => void) | null>(null); const online = status === 'connected'; useEffect(() => { const source = new EventSource('/api/events'); const update = () => { setRefresh(x => x + 1); setLast(new Date().toLocaleTimeString()) }; source.addEventListener('open', () => { setStatus('connected'); setLast(new Date().toLocaleTimeString()) }); source.addEventListener('change', update); source.addEventListener('reset', update); source.onerror = () => setStatus('disconnected'); return () => source.close() }, []); function go(next: string) { const action = () => { location.hash = `#/${next}`; setRoute(next) }; dirty.current ? setPending(() => action) : action() } async function logout() { if (!online) return; await api.post('/api/logout'); api.csrf = null; onLogout() } const page = route === 'imports' ? <Imports refreshKey={refresh} online={online} /> : route === 'findings' ? <Findings session={session} refreshKey={refresh} online={online} onDirty={(value, saver, discarder) => { dirty.current = value; save.current = saver; discard.current = discarder }} /> : route === 'evidence' ? <Evidence session={session} refreshKey={refresh} online={online} /> : route === 'transfer' ? <Transfer role={session.user?.role ?? ''} online={online} /> : <Overview refreshKey={refresh} />; return <div className="app-shell"><a className="skip-link" href="#content">Skip to content</a><header className="topbar"><button className="brand" onClick={() => go('overview')}>Harbinger</button><span className="reminder"><em>report as you go</em></span><span className="sse">SSE {status} · last successful sync {last}</span><button disabled={!online} onClick={() => dirty.current ? setPending(() => logout) : void logout()}>Sign out</button></header><div className="layout"><nav className="sidebar" aria-label="Primary navigation">{nav.map(([key, label]) => <a href={`#/${key}`} aria-current={route === key ? 'page' : undefined} className={route === key ? 'active' : ''} onClick={e => { e.preventDefault(); go(key) }} key={key}>{label}</a>)}</nav><main className="content" id="content">{!online && <div className="connection-banner" role="status">Connection lost or not confirmed. Server writes are disabled. Last successful sync: {last}.</div>}{page}</main></div>{pending && <DirtyDialog onStay={() => setPending(null)} onDiscard={() => { const next = pending; discard.current(); setPending(null); next?.() }} onSave={() => void save.current().then(ok => { if (ok) { const next = pending; setPending(null); next?.() } })} />}</div> }
function App() { const [session, setSession] = useState<Session | null>(null); const [loading, setLoading] = useState(true); useEffect(() => { void api.get<Session>('/api/session').then(value => { api.csrf = value.csrf; setSession(value) }).catch(err => { if (!(err instanceof ApiError && err.status === 401)) throw err }).finally(() => setLoading(false)) }, []); return loading ? <div className="loading">Checking session…</div> : session?.user ? <Shell session={session} onLogout={() => setSession(null)} /> : <Login onLogin={setSession} /> }
export { App, Evidence, Findings, GraphCanvas, Imports, Login, Overview, Shell, Transfer }
