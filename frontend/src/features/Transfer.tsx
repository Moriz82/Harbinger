import React, { useEffect, useRef, useState } from 'react'
import { ApiError, api, Asset, downloadJson, Graph, RecordItem, Session } from '../api'
import { ErrorMessage, Empty, DirtyDialog, Field } from '../components/common'
type TransferReceipt = { status: 'imported' | 'conflict'; imported: number; duplicates: number; conflicts: string[]; deferred: string[]; bundle_id: string; manifest_hash: string }
type TransferConflict = RecordItem & { data: Record<string, unknown> & { bundle_id?: string; manifest_hash?: string; state?: string; conflict_ids?: string[]; duplicate_ids?: string[]; deferred_ids?: string[]; incoming?: RecordItem[] }; local?: RecordItem[] }
type TransferReview = { review_hash: string; selected_record_ids: string[]; recipient: { id: string; name: string; origin: string }; records: (RecordItem & { selected?: boolean })[]; files: { id: string; size: number; sha256: string }[] }

function TransferRecordDiff({ id, incoming, local }: { id: string; incoming?: RecordItem; local?: RecordItem }) {
  const incomingData = incoming?.data ?? {}; const localData = local?.data ?? {}; const fields = Array.from(new Set([...Object.keys(incomingData), ...Object.keys(localData)])).filter(key => JSON.stringify(incomingData[key]) !== JSON.stringify(localData[key])).sort()
  const value = (item: unknown) => { const text = typeof item === 'string' ? item : JSON.stringify(item, null, 2) ?? 'undefined'; return text.length > 360 ? <details><summary>{text.slice(0, 360)}…</summary><pre>{text}</pre></details> : <pre>{text}</pre> }
  const metadata = (record?: RecordItem) => <dl><dt>Kind</dt><dd>{record?.kind ?? 'missing local record'}</dd><dt>Record ID</dt><dd className="mono">{record?.id ?? id}</dd><dt>Revision</dt><dd className="mono">{record?.revision_id ?? 'not returned'}</dd><dt>Source instance</dt><dd className="mono">{String(record?.data.source_instance ?? 'not recorded')}</dd><dt>Source revision</dt><dd className="mono">{String(record?.data.source_revision_id ?? 'not recorded')}</dd></dl>
  return <details className="record-diff" open><summary>Conflicting record {id}: inspect all differing fields before accepting</summary><div className="diff-metadata"><div><strong>Incoming owner revision</strong>{metadata(incoming)}</div><div><strong>Current local revision</strong>{metadata(local)}</div></div>{fields.length ? <div className="diff-fields">{fields.map(field => <div className="diff-field" key={field}><strong>{field}</strong><div><span>Incoming</span>{value(incomingData[field])}</div><div><span>Local</span>{value(localData[field])}</div></div>)}</div> : <p>No data fields differ; inspect identity, revision, and provenance above.</p>}</details>
}

function TransferConflictReview({ canReview, online, canWrite, onWriteUnavailable = () => undefined, onWriteAvailable = () => undefined }: { canReview: boolean; online: boolean; canWrite: boolean; onWriteUnavailable?: () => void; onWriteAvailable?: () => void }) {
  const [items, setItems] = useState<TransferConflict[]>([])
  const [loaded, setLoaded] = useState(false)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState<unknown>(null)
  const [resolution, setResolution] = useState<{ decision: 'keep_local' | 'accept_incoming'; imported: number; duplicates: number; bundle_id: string; manifest_hash: string } | null>(null)
  const [loading, setLoading] = useState(false)
  const request = useRef(0)
  async function load() {
    if (!canReview || !online) return
    const ticket = ++request.current
    setError(null); setLoading(true)
    try {
      const result = await api.get<{ items?: TransferConflict[] }>('/api/transfers/conflicts')
      if (ticket !== request.current) return
      setItems(result.items ?? [])
      setLoaded(true)
    } catch (err) { if (ticket === request.current) setError(err) } finally { if (ticket === request.current) setLoading(false) }
  }
  useEffect(() => { if (canReview && online) void load(); else setLoading(false); return () => { request.current++ } }, [canReview, online])
  async function resolve(item: TransferConflict, decision: 'keep_local' | 'accept_incoming') {
    if (!canReview || !canWrite) return
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
      onWriteAvailable()
      await load()
    } catch (err) {
      if (err instanceof ApiError && err.status === 503) onWriteUnavailable()
      if (err instanceof ApiError && err.status === 409) await load()
      setError(err)
    } finally { setBusy('') }
  }
  if (!canReview) return null
  return <section className="conflict-review" aria-labelledby="transfer-conflicts">
    <h3 id="transfer-conflicts">Transfer conflict review</h3>
    <p className="muted">Keeping local records resolves the review while the encrypted bundle remains retained.</p>
    {!canWrite && <p className="uncertainty" role="status">{loaded ? 'Showing previously loaded conflict details. Resolution is disabled until the connection and write readiness recover.' : 'Conflict resolution is disabled until the connection and write readiness recover.'}</p>}
    {resolution && <div className="receipt" role="status"><strong>{resolution.decision === 'accept_incoming' ? 'Incoming acceptance receipt' : 'Local-resolution receipt'}</strong><span>{resolution.decision === 'accept_incoming' ? `${resolution.imported} imported · ${resolution.duplicates} exact duplicates.` : 'Local records kept; encrypted bundle retained.'}</span><span className="mono">bundle {resolution.bundle_id} · manifest {resolution.manifest_hash}</span></div>}
    <ErrorMessage error={error} />{loading && <p role="status">Loading transfer conflicts…</p>}{Boolean(error) && <button onClick={() => void load()}>Retry conflict review</button>}
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
        <div className="actions"><button className="primary" disabled={!canWrite || loading || data.state !== 'needs_review' || Boolean(busy) || !reviewReady} onClick={() => void resolve(item, 'keep_local')}>{busy === item.id ? 'Resolving…' : 'Keep local records'}</button><button disabled={!canWrite || loading || data.state !== 'needs_review' || Boolean(busy) || !reviewReady} onClick={() => void resolve(item, 'accept_incoming')}>Accept incoming revision and deferred evidence</button></div>
      </article>
    })}
  </section>
}

function Transfer({ role = '', online = true, writeReady = true, onWriteUnavailable = () => undefined, onWriteAvailable = () => undefined }: { role?: string; online?: boolean; writeReady?: boolean; onWriteUnavailable?: () => void; onWriteAvailable?: () => void }) {
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
  const [loadingLeads, setLoadingLeads] = useState(false), [loadingConnections, setLoadingConnections] = useState(false), [operation, setOperation] = useState('')
  const limit = 100
  const canTransfer = role === 'captain'
  const canWrite = online && writeReady
  async function loadLeads(page = leadPage) {
    setLoadingLeads(true)
    try {
      const result = await api.get<{ items?: RecordItem[]; total?: number }>(`/api/records?kind=lead&limit=${limit}&offset=${page * limit}`)
      const next = result.items ?? []
      setLeads(next)
      setLeadTotal(result.total ?? next.length)
    } catch (err) { setError(err) } finally { setLoadingLeads(false) }
  }
  useEffect(() => { setLoadingConnections(true); void api.get<{ peers: typeof peers }>('/api/connections').then(result => setPeers(result.peers)).catch(setError).finally(() => setLoadingConnections(false)) }, [])
  useEffect(() => { void loadLeads() }, [leadPage])
  function toggle(id: string) {
    setSelected(current => current.includes(id) ? current.filter(value => value !== id) : [...current, id])
    setReview(null)
  }
  async function reviewTransfer() {
    if (!canWrite || !canTransfer) return
    setReview(null)
    setError(null)
    setOperation('Reviewing transfer selection…')
    try {
      const result = await api.post<TransferReview>('/api/transfers/preview', { record_ids: selected, recipient_id: recipient })
      setReview(result)
      setMessage('Transfer selection reviewed. Send or save this exact encrypted bundle.')
      onWriteAvailable()
    } catch (err) { if (err instanceof ApiError && err.status === 503) onWriteUnavailable(); setError(err); setOperation('Transfer review failed. Retry the review.') } finally { setOperation('') }
  }
  async function send() {
    if (!canWrite || !canTransfer || !review) return
    setOperation('Sending encrypted transfer…')
    try {
      const result = await api.post<TransferReceipt>('/api/transfers/send', { record_ids: selected, recipient_id: recipient, review_hash: review.review_hash })
      setReceipt(result)
      setMessage(result.status === 'conflict' ? `Conflict: no records imported; bundle ${result.bundle_id} is held for review.` : `Imported receipt for bundle ${result.bundle_id}.`)
      onWriteAvailable()
    } catch (err) {
      if (err instanceof ApiError && err.status === 503) onWriteUnavailable()
      if (err instanceof ApiError && err.status === 409) setReview(null)
      setError(err)
    } finally { setOperation('') }
  }
  async function exportRecords() {
    if (!canWrite || !canTransfer || !review) return
    setOperation('Saving encrypted transfer…')
    try {
      const response = await fetch('/api/transfers/export', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': api.csrf ?? '' }, body: JSON.stringify({ record_ids: selected, recipient_id: recipient, review_hash: review.review_hash }) })
      if (!response.ok) {
        if (response.status === 409) setReview(null)
        if (response.status === 503) onWriteUnavailable()
        throw new Error(`Export failed (${response.status})`)
      }
      const url = URL.createObjectURL(await response.blob())
      const link = document.createElement('a')
      link.href = url
      link.download = `harbinger-transfer-${Date.now()}.age`
      link.click()
      URL.revokeObjectURL(url)
      setMessage('Encrypted transfer saved locally.')
      onWriteAvailable()
    } catch (err) { if (err instanceof ApiError && err.status === 503) onWriteUnavailable(); setError(err) } finally { setOperation('') }
  }
  async function importFile() {
    if (!canWrite || !file || !canTransfer) return
    setOperation('Importing and reconciling encrypted file…')
    try {
      const form = new FormData()
      form.append('file', file)
      const result = await api.post<TransferReceipt>('/api/transfers/import', form)
      setReceipt(result)
      setMessage(result.status === 'conflict' ? `Conflict: no records imported; bundle ${result.bundle_id} is held for review.` : `Imported receipt for bundle ${result.bundle_id}.`)
      onWriteAvailable()
    } catch (err) { if (err instanceof ApiError && err.status === 503) onWriteUnavailable(); setError(err) } finally { setOperation('') }
  }
  return <section>
    <h2>Encrypted transfer</h2>
    <ErrorMessage error={error} />
    {!canTransfer && <div className="uncertainty" role="status">Captain role is required on this host to send, export, import, or review transfer conflicts.</div>}
    {message && <div className="notice" role="status">{message}</div>}{operation && <p role="status" aria-live="polite">{operation}</p>}{!writeReady && online && <div className="uncertainty" role="status">SSE is connected, but transfer writes are unavailable until the writer recovers.</div>}
    {receipt && <div className={`receipt ${receipt.status}`} role="status"><strong>{receipt.status}</strong><span>{receipt.status === 'conflict' ? 'No records imported while this bundle is held.' : `${receipt.imported} imported.`} {receipt.duplicates} exact duplicates · {receipt.conflicts.length} conflicts · {receipt.deferred.length} deferred.</span><span className="mono">bundle {receipt.bundle_id} · manifest {receipt.manifest_hash}</span>{receipt.conflicts.length > 0 && <ul aria-label="Conflicting record IDs">{receipt.conflicts.map(id => <li className="mono" key={id}>{id}</li>)}</ul>}{receipt.deferred.length > 0 && <ul aria-label="Deferred record IDs">{receipt.deferred.map(id => <li className="mono" key={id}>{id}</li>)}</ul>}</div>}
    <div className="split"><div className="panel">
      <label>Peer recipient<select value={recipient} disabled={loadingConnections} onChange={event => { setRecipient(event.target.value); setReview(null) }}><option value="">{loadingConnections ? 'Loading enrolled peers…' : 'Choose an enrolled peer'}</option>{peers.map(peer => <option key={peer.id} value={peer.id}>{peer.name} · {peer.status} · {peer.recipient}</option>)}</select></label>
      <fieldset><legend>Eligible leads</legend>{loadingLeads && <p role="status">Loading eligible leads…</p>}{leads.length ? leads.map(lead => <label key={lead.id}><input type="checkbox" checked={selected.includes(lead.id)} disabled={!canWrite} onChange={() => toggle(lead.id)} />{String(lead.data.title || lead.data.finding_title || lead.id)}</label>) : !loadingLeads && <Empty title="No eligible leads" body="Submitted findings will appear here when ready for transfer." />}</fieldset>
      <div className="actions"><button disabled={leadPage === 0} onClick={() => setLeadPage(leadPage - 1)}>Previous leads</button><span className="count">{leadPage * limit + leads.length} of {leadTotal}</span><button disabled={(leadPage + 1) * limit >= leadTotal} onClick={() => setLeadPage(leadPage + 1)}>Next leads</button></div>
      <button disabled={!canWrite || !canTransfer || !recipient || !selected.length || Boolean(operation)} onClick={() => void reviewTransfer()}>Review transfer</button>
      {review && <div className="receipt" role="status"><strong>Reviewed transfer selection</strong><span>{review.selected_record_ids.length} selected · {review.records.length} total records · {review.files.length} evidence files</span><span>Recipient: {review.recipient.name} at {review.recipient.origin}</span><ul aria-label="Reviewed transfer records">{review.records.map(item => <li key={item.id}><strong>{item.selected ? 'Selected' : 'Dependency'}:</strong> {String(item.data.title ?? item.data.label ?? item.data.filename ?? item.id)} <span className="mono">{item.kind} · {item.revision_id}</span></li>)}</ul></div>}
      <div className="actions"><button className="primary" disabled={!canWrite || !canTransfer || !review || Boolean(operation)} onClick={() => void send()}>Send selected leads to peer</button><button disabled={!canWrite || !canTransfer || !review || Boolean(operation)} onClick={() => void exportRecords()}>Save encrypted file</button></div>
    </div><div className="panel"><input aria-label="Encrypted file" disabled={!canWrite || loadingConnections} type="file" onChange={event => setFile(event.target.files?.[0] ?? null)} /><button disabled={!canWrite || !canTransfer || !file || Boolean(operation)} onClick={() => void importFile()}>Import and reconcile</button></div></div>
    <TransferConflictReview canReview={canTransfer} online={online} canWrite={canWrite} onWriteUnavailable={onWriteUnavailable} onWriteAvailable={onWriteAvailable} />
  </section>
}
export { Transfer }
