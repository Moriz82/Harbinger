import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { App, Findings, Shell, Transfer } from '../src/main'

const session = { user: { id: 'u1', name: 'Casey', role: 'captain' }, csrf: 'csrf-1', app: 'harbinger', engagement: { id: 'e1', name: 'Northwind' }, mode: 'lan' }
const asset = { id: 'asset-1', label: 'portal.example', kind: 'host', track: 'web', revision_id: 'rev-a', data: {} }
const finding = { id: 'finding-1', kind: 'finding', revision_id: 'rev-f', updated_at: '2026-09-08T19:00:00Z', data: { title: 'Old finding', observation: 'Server observation', impact: 'Impact', steps: 'Step', evidence_state: 'needed', writing_state: 'draft', source_instance: 'source-a' } }

const eventSources: MockEventSource[] = []
class MockEventSource {
  private listeners = new Map<string, (() => void)[]>()
  onerror?: () => void
  constructor() { eventSources.push(this) }
  addEventListener(type: string, listener: () => void) { this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]); if (type === 'open') queueMicrotask(listener) }
  emit(type: string) { for (const listener of this.listeners.get(type) ?? []) listener() }
  fail() { this.onerror?.() }
  close() {}
}
const response = (body: unknown, status = 200, contentType = 'application/json') => new Response(contentType === 'application/json' ? JSON.stringify(body) : String(body), { status, headers: { 'content-type': contentType } })
let fetchMock: ReturnType<typeof vi.fn>

function baseFetch(path: string, init?: RequestInit) {
  if (path === '/api/session') return response(session)
  if (path.startsWith('/api/graph')) return response({ nodes: [{ id: asset.id, label: asset.label, kind: asset.kind, track: asset.track }], edges: [], total_nodes: 1, total_edges: 0 })
  if (path.startsWith('/api/assets')) return response({ items: [asset], total: 1 })
  if (path === '/api/events') return response('')
  if (path === '/api/uploads') return response({ items: [], total: 0 })
  if (path === '/api/records?kind=finding') return response({ items: [], total: 0 })
  if (path === '/api/users') return response({ items: [], total: 0 })
  if (path === '/api/evidence') return response({ items: [], total: 0 })
  if (path === '/api/connections') return response({ peers: [], ghostwriter: { status: 'ready', origin: '', report_id: '' } })
  return response({})
}

beforeEach(() => { history.replaceState(null, '', '#/overview'); eventSources.length = 0; vi.stubGlobal('EventSource', MockEventSource); fetchMock = vi.fn(baseFetch); vi.stubGlobal('fetch', fetchMock) })
afterEach(() => { cleanup(); vi.restoreAllMocks() })

describe('Harbinger UI contract', () => {
  it('uses dispatchable SSE events and blocks writes until the stream opens', async () => {
    render(<Shell session={session} onLogout={() => undefined} />)
    expect(screen.getByText(/Connection lost or not confirmed\. Server writes are disabled/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeDisabled()
    act(() => eventSources[0]?.emit('change'))
    act(() => eventSources[0]?.emit('reset'))
    await waitFor(() => expect(screen.getByText(/SSE connected/)).toBeInTheDocument())
    act(() => eventSources[0]?.fail())
    expect(screen.getByText(/Connection lost or not confirmed/)).toBeInTheDocument()
  })

  it('logs in and renders the exact sticky report reminder', async () => {
    fetchMock.mockReset().mockImplementationOnce(() => response({ detail: 'unauthenticated' }, 401)).mockImplementationOnce(() => response(session)).mockImplementation(baseFetch)
    render(<App />)
    await screen.findByRole('heading', { name: 'Keep the evidence moving.' })
    fireEvent.change(screen.getByLabelText('Account name'), { target: { value: 'Casey' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'secret' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByText('report as you go')).toBeInTheDocument()
    expect(screen.getByText('report as you go').tagName).toBe('EM')
    for (const track of ['network', 'web', 'linux', 'windows_ad', 'database_service']) expect(screen.getByRole('button', { name: track })).toBeInTheDocument()
  })

  it('keeps the asset table usable when graph loading fails and synchronizes row selection', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => { const path = String(input); if (path.startsWith('/api/graph')) return response({ detail: 'graph unavailable' }, 503); return baseFetch(path) })
    render(<App />)
    expect(await screen.findByText('Relationship map unavailable.')).toBeInTheDocument()
    const row = screen.getByText('portal.example').closest('tr')!
    fireEvent.click(row)
    expect(row).toHaveClass('selected')
    expect(screen.getByText('portal.example')).toBeInTheDocument()
  })

  it('requires upload parsing before merge', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => { const path = String(input); if (path === '/api/uploads' && init?.method === 'POST') return response({ id: 'upload-1', kind: 'upload', revision_id: 'rev-u', updated_at: '', data: { filename: 'scan.xml', format: 'nmap_xml', status: 'uploaded', size: 10 } }); if (path === '/api/uploads/upload-1/parse') return response({ id: 'upload-1', kind: 'upload', revision_id: 'rev-u2', updated_at: '', data: { filename: 'scan.xml', format: 'nmap_xml', status: 'parsed', size: 10 } }); if (path === '/api/uploads/upload-1/preview') return response({ assets: [], relationships: [], observations: [], limitations: [], complete: true, _review: { upload_revision_id: 'rev-u2', preview_revision_id: 'preview-r', preview_hash: 'a'.repeat(64) } }); return baseFetch(path, init) })
    render(<App />)
    fireEvent.click(await screen.findByRole('link', { name: 'Imports' }))
    const input = await screen.findByLabelText('File')
    fireEvent.change(input, { target: { files: [new File(['<nmap/>'], 'scan.xml', { type: 'text/xml' })] } })
    fireEvent.click(screen.getByRole('button', { name: 'Upload source' }))
    const merge = await screen.findByRole('button', { name: 'Merge records' })
    expect(merge).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Parse preview' }))
    await waitFor(() => expect(merge).toBeEnabled())
  })

  it('does not show a phantom saved state after a failed finding save', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => { const path = String(input); if (path === '/api/records' && init?.method === 'POST') return response({ detail: 'storage unavailable' }, 503); return baseFetch(path, init) })
    render(<App />)
    fireEvent.click(await screen.findByRole('link', { name: 'Findings' }))
    fireEvent.click(await screen.findByRole('button', { name: 'New finding' }))
    fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'Local finding' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await screen.findByRole('alert')
    expect(screen.queryByText('Saved revision is current.')).not.toBeInTheDocument()
    expect(screen.getByText('Unsaved changes · Save before review or navigation.')).toBeInTheDocument()
  })

  it('preserves local and server versions on a stale finding revision', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => { const path = String(input); if (path === '/api/records?kind=finding') return response({ items: [finding], total: 1 }); if (path.startsWith('/api/records/finding-1/revisions')) return response({ items: [] }); if (path === '/api/records/finding-1' && init?.method === 'PUT') return response({ detail: { message: 'stale revision', current: { ...finding, revision_id: 'rev-current', data: { ...finding.data, observation: 'Server version' } } } }, 409); return baseFetch(path, init) })
    render(<App />)
    fireEvent.click(await screen.findByRole('link', { name: 'Findings' }))
    const observation = await screen.findByLabelText('Observation')
    fireEvent.change(observation, { target: { value: 'Local version' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Server changed. Local edits remain unsaved.')).toBeInTheDocument()
    expect(observation).toHaveValue('Local version')
    expect(screen.getByText('Server version')).toBeInTheDocument()
  })

  it('reconciles an open clean finding to the revision returned after refresh', async () => {
    const current = { ...finding, revision_id: 'rev-r2', data: { ...finding.data, observation: 'Remote revision R2' } }
    let refreshed = false
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const path = String(input)
      if (path === '/api/records?kind=finding') return response({ items: [refreshed ? current : finding], total: 1 })
      return baseFetch(path)
    })
    const view = render(<Findings session={session} refreshKey={0} onDirty={() => undefined} />)
    expect(await screen.findByLabelText('Observation')).toHaveValue('Server observation')
    refreshed = true
    view.rerender(<Findings session={session} refreshKey={1} onDirty={() => undefined} />)
    await waitFor(() => expect(screen.getByLabelText('Observation')).toHaveValue('Remote revision R2'))
    expect(screen.getByText('Saved revision is current.')).toBeInTheDocument()
  })

  it('keeps local finding edits and labels the server change after refresh', async () => {
    const current = { ...finding, revision_id: 'rev-r2', data: { ...finding.data, observation: 'Remote revision R2' } }
    let refreshed = false
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const path = String(input)
      if (path === '/api/records?kind=finding') return response({ items: [refreshed ? current : finding], total: 1 })
      return baseFetch(path)
    })
    const view = render(<Findings session={session} refreshKey={0} onDirty={() => undefined} />)
    const observation = await screen.findByLabelText('Observation')
    fireEvent.change(observation, { target: { value: 'Local revision R1' } })
    refreshed = true
    view.rerender(<Findings session={session} refreshKey={1} onDirty={() => undefined} />)
    expect(await screen.findByText('Server changed. Local edits remain unsaved.')).toBeInTheDocument()
    expect(observation).toHaveValue('Local revision R1')
    expect(screen.getByText('Server changed · local edits are unsaved; compare before saving.')).toBeInTheDocument()
    expect(screen.queryByText('Saved revision is current.')).toBeNull()
  })

  it('keeps incoming source metadata read-only while sending the complete finding schema', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => { const path = String(input); if (path === '/api/records?kind=finding') return response({ items: [finding], total: 1 }); if (path === '/api/assets?offset=0&limit=100') return response({ items: [asset], total: 1 }); if (path === '/api/records/finding-1' && init?.method === 'PUT') return response({ ...finding, data: { ...finding.data, asset_ids: ['asset-1'], evidence_ids: [] } }); return baseFetch(path, init) })
    render(<App />)
    fireEvent.click(await screen.findByRole('link', { name: 'Findings' }))
    fireEvent.click(await screen.findByLabelText(/portal\.example/))
    fireEvent.change(await screen.findByLabelText('Title'), { target: { value: 'Updated finding' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(call => String(call[0]) === '/api/records/finding-1')).toBe(true))
    const save = fetchMock.mock.calls.find(call => String(call[0]) === '/api/records/finding-1')
    const body = JSON.parse(String(save?.[1]?.body))
    expect(body.data.source_instance).toBeUndefined()
    expect(body.data.asset_ids).toEqual(['asset-1'])
    expect(body.data.evidence_ids).toEqual([])
  })

  it('keeps quarantined evidence out of the export approval path', async () => {
    const evidence = { id: 'e1', kind: 'evidence', revision_id: 'r1', updated_at: 'now', data: { filename: 'Raw output', finding_id: 'finding-1' } }
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => { const path = String(input); if (path === '/api/evidence') return response({ items: [evidence], total: 1 }); if (path === '/api/evidence/e1/preview') return response({ text: '<script>unsafe</script>', quarantined: true }); if (path === '/api/evidence/e1/approve-export' && init?.method === 'POST') return response({ ...evidence, data: { ...evidence.data, reviewed_for_export: true } }); return baseFetch(path, init) })
    render(<App />)
    fireEvent.click(await screen.findByRole('link', { name: 'Evidence' }))
    fireEvent.click(await screen.findByRole('button', { name: /Raw output/ }))
    expect(await screen.findByText('Quarantined source · export approval is unavailable.')).toBeInTheDocument()
    const approve = screen.getByRole('button', { name: 'Approve reviewed derivative' })
    expect(approve).toBeDisabled()
    fireEvent.click(approve)
    expect(fetchMock.mock.calls.some(call => String(call[0]).includes('approve-export'))).toBe(false)
  })

  it('renders an imported receipt from direct peer send', async () => {
    const lead = { id: 'lead-1', kind: 'lead', revision_id: 'lead-r', updated_at: '', data: { title: 'Ready finding', finding_id: 'finding-1' } }
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => { const path = String(input); if (path === '/api/connections') return response({ peers: [{ id: 'peer-1', name: 'Merlin', origin: 'https://merlin.test', recipient: 'age1peer', status: 'enrolled' }], ghostwriter: { status: 'unavailable', origin: '', report_id: '' } }); if (path === '/api/records?kind=lead&limit=100&offset=0') return response({ items: [lead], total: 1 }); if (path === '/api/transfers/preview' && init?.method === 'POST') return response({ review_hash: 'a'.repeat(64), selected_record_ids: ['lead-1'], recipient: { id: 'peer-1', name: 'Merlin', origin: 'https://merlin.test' }, records: [{ ...lead, selected: true }], files: [] }); if (path === '/api/transfers/send' && init?.method === 'POST') return response({ status: 'imported', imported: 1, duplicates: 0, conflicts: [], deferred: [], bundle_id: 'peer-ok', manifest_hash: 'manifest-ok' }); return baseFetch(path, init) })
    render(<App />)
    fireEvent.click(await screen.findByRole('link', { name: 'Transfer' }))
    fireEvent.change(await screen.findByLabelText('Peer recipient'), { target: { value: 'peer-1' } })
    fireEvent.click(await screen.findByLabelText('Ready finding'))
    expect(screen.getByRole('button', { name: 'Send selected leads to peer' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Review transfer' }))
    expect(await screen.findByText(/1 selected · 1 total records/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Send selected leads to peer' }))
    expect(await screen.findByText(/1 imported/)).toBeInTheDocument()
    expect(screen.getAllByText(/bundle peer-ok/)).toHaveLength(2)
    const send = fetchMock.mock.calls.find(call => String(call[0]) === '/api/transfers/send')
    expect(JSON.parse(String(send?.[1]?.body))).toEqual({ record_ids: ['lead-1'], recipient_id: 'peer-1', review_hash: 'a'.repeat(64) })
    expect(screen.queryByText('Casey', { selector: 'option' })).not.toBeInTheDocument()
  })

  it('renders a retained conflict receipt from direct peer send', async () => {
    const lead = { id: 'lead-1', kind: 'lead', revision_id: 'lead-r', updated_at: '', data: { title: 'Ready finding' } }
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => { const path = String(input); if (path === '/api/connections') return response({ peers: [{ id: 'peer-1', name: 'Merlin', recipient: 'age1peer', status: 'enrolled' }] }); if (path === '/api/records?kind=lead&limit=100&offset=0') return response({ items: [lead], total: 1 }); if (path === '/api/transfers/preview' && init?.method === 'POST') return response({ review_hash: 'b'.repeat(64), selected_record_ids: ['lead-1'], recipient: { id: 'peer-1', name: 'Merlin', origin: 'https://merlin.test' }, records: [{ ...lead, selected: true }], files: [] }); if (path === '/api/transfers/send' && init?.method === 'POST') return response({ status: 'conflict', imported: 0, duplicates: 1, conflicts: ['lead-7'], deferred: ['lead-8'], bundle_id: 'peer-held', manifest_hash: 'manifest-held' }); return baseFetch(path, init) })
    render(<App />)
    fireEvent.click(await screen.findByRole('link', { name: 'Transfer' }))
    fireEvent.change(await screen.findByLabelText('Peer recipient'), { target: { value: 'peer-1' } })
    fireEvent.click(await screen.findByLabelText('Ready finding'))
    fireEvent.click(screen.getByRole('button', { name: 'Review transfer' }))
    await screen.findByText(/1 selected · 1 total records/)
    fireEvent.click(screen.getByRole('button', { name: 'Send selected leads to peer' }))
    expect(await screen.findByText(/No records imported while this bundle is held/)).toBeInTheDocument()
    expect(screen.getByLabelText('Conflicting record IDs')).toHaveTextContent('lead-7')
    expect(screen.getByLabelText('Deferred record IDs')).toHaveTextContent('lead-8')
  })

  it('rebases kept local conflict text onto the server revision before saving again', async () => {
    let attempts = 0
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      if (path === '/api/records?kind=finding') return response({ items: [finding], total: 1 })
      if (path === '/api/records/finding-1' && init?.method === 'PUT') {
        attempts++
        if (attempts === 1) return response({ detail: { current: { ...finding, revision_id: 'rev-current', data: { ...finding.data, observation: 'Server version' } } } }, 409)
        return response({ ...finding, revision_id: 'rev-next', data: { ...finding.data, observation: 'Local version' } })
      }
      return baseFetch(path, init)
    })
    render(<App />)
    fireEvent.click(await screen.findByRole('link', { name: 'Findings' }))
    fireEvent.change(await screen.findByLabelText('Observation'), { target: { value: 'Local version' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Keep local version' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(attempts).toBe(2))
    const saves = fetchMock.mock.calls.filter(call => String(call[0]) === '/api/records/finding-1')
    expect(JSON.parse(String(saves[1][1]?.body)).base_revision_id).toBe('rev-current')
    expect(screen.getByLabelText('Observation')).toHaveValue('Local version')
  })

  it('keeps the finding selected after submission even when the receipt is a lead', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      if (path === '/api/records?kind=finding') return response({ items: [finding], total: 1 })
      if (path === '/api/findings/finding-1/submit' && init?.method === 'POST') return response({ id: 'lead-1', kind: 'lead', revision_id: 'lead-r', updated_at: '', data: { finding_id: finding.id } })
      if (path === '/api/records/finding-1' && !init?.method) return response({ ...finding, revision_id: 'rev-submitted', data: { ...finding.data, writing_state: 'submitted' } })
      return baseFetch(path, init)
    })
    render(<App />)
    fireEvent.click(await screen.findByRole('link', { name: 'Findings' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Submit to lead' }))
    expect(await screen.findByText(/Submitted to lead\. The technical finding/)).toBeInTheDocument()
    expect(screen.getByLabelText('Title')).toHaveValue('Old finding')
    expect(screen.getByRole('button', { name: 'Submit to lead' })).toBeDisabled()
    const submit = fetchMock.mock.calls.find(call => String(call[0]) === '/api/findings/finding-1/submit')
    expect(JSON.parse(String(submit?.[1]?.body))).toEqual({ base_revision_id: 'rev-f' })
  })

  it('sends the exact preview bindings for merge and clears them after a stale response', async () => {
    const review = { upload_revision_id: 'rev-u2', preview_revision_id: 'preview-r', preview_hash: 'a'.repeat(64) }
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => { const path = String(input); if (path === '/api/uploads') return response({ items: [{ id: 'upload-1', kind: 'upload', revision_id: 'rev-u', updated_at: '', data: { filename: 'scan.xml', format: 'nmap_xml', status: 'uploaded' } }], total: 1 }); if (path === '/api/uploads/upload-1/parse') return response({ id: 'upload-1', kind: 'upload', revision_id: 'rev-u2', updated_at: '', data: { filename: 'scan.xml', format: 'nmap_xml', status: 'preview' } }); if (path === '/api/uploads/upload-1/preview') return response({ assets: [], relationships: [], observations: [], limitations: [], complete: true, _review: review }); if (path === '/api/uploads/upload-1/merge') return response({ detail: { message: 'stale' } }, 409); return baseFetch(path, init) })
    render(<App />)
    fireEvent.click(await screen.findByRole('link', { name: 'Imports' }))
    fireEvent.click(await screen.findByRole('button', { name: /scan\.xml/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Parse preview' }))
    const merge = await screen.findByRole('button', { name: 'Merge records' })
    fireEvent.click(merge)
    await screen.findByRole('alert')
    const call = fetchMock.mock.calls.find(item => String(item[0]) === '/api/uploads/upload-1/merge')
    expect(JSON.parse(String(call?.[1]?.body))).toEqual(review)
    expect(screen.getByRole('button', { name: 'Merge records' })).toBeDisabled()
  })

  it('serializes parsing and exposes a busy state', async () => {
    let resolveParse!: (value: Response) => void
    const delayedParse = new Promise<Response>(resolve => { resolveParse = resolve })
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      if (path === '/api/uploads' && init?.method === 'POST') return response({ id: 'upload-1', kind: 'upload', revision_id: 'rev-u', updated_at: '', data: { filename: 'scan.xml', format: 'nmap_xml', status: 'uploaded' } })
      if (path === '/api/uploads/upload-1/parse') return delayedParse
      if (path === '/api/uploads/upload-1/preview') return response({ complete: true })
      return baseFetch(path, init)
    })
    render(<App />)
    fireEvent.click(await screen.findByRole('link', { name: 'Imports' }))
    fireEvent.change(await screen.findByLabelText('File'), { target: { files: [new File(['x'], 'scan.xml')] } })
    fireEvent.click(screen.getByRole('button', { name: 'Upload source' }))
    const parse = await screen.findByRole('button', { name: 'Parse preview' })
    fireEvent.click(parse); fireEvent.click(parse)
    expect(screen.getByRole('button', { name: 'Parsing preview…' })).toBeDisabled()
    expect(fetchMock.mock.calls.filter(call => String(call[0]) === '/api/uploads/upload-1/parse')).toHaveLength(1)
    resolveParse(response({ id: 'upload-1', kind: 'upload', revision_id: 'rev-u2', updated_at: '', data: { filename: 'scan.xml', status: 'parsed' } }))
    await screen.findByRole('button', { name: 'Parse preview' })
  })

  it('pages assets through the backend and makes rows keyboard selectable', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.startsWith('/api/assets?')) return response({ items: [asset], total: 101 })
      return baseFetch(path)
    })
    render(<App />)
    expect(await screen.findByText('Showing 1 of 101 assets', { exact: false })).toBeInTheDocument()
    const row = screen.getByText('portal.example').closest('tr')!
    fireEvent.keyDown(row, { key: 'Enter' })
    expect(row).toHaveClass('selected')
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(call => String(call[0]).includes('offset=100&limit=100'))).toBe(true))
  })

  it('renders imported and mixed-conflict receipts with their actual record IDs', async () => {
    const receipts = [
      { status: 'imported', imported: 2, duplicates: 1, conflicts: [], deferred: [], bundle_id: 'bundle-ok', manifest_hash: 'hash-ok' },
      { status: 'conflict', imported: 0, duplicates: 1, conflicts: ['lead-7'], deferred: ['lead-8'], bundle_id: 'bundle-held', manifest_hash: 'hash-held' },
    ]
    let next = 0
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === '/api/transfers/import' && init?.method === 'POST') return response(receipts[next++])
      return baseFetch(String(input), init)
    })
    render(<Transfer role="captain" />)
    const input = screen.getByLabelText('Encrypted file')
    fireEvent.change(input, { target: { files: [new File(['bundle'], 'handoff.age')] } })
    fireEvent.click(screen.getByRole('button', { name: 'Import and reconcile' }))
    expect(await screen.findByText(/2 imported/)).toBeInTheDocument()
    expect(screen.getAllByText(/bundle bundle-ok/)).toHaveLength(2)
    fireEvent.click(screen.getByRole('button', { name: 'Import and reconcile' }))
    expect(await screen.findByText(/No records imported while this bundle is held/)).toBeInTheDocument()
    expect(screen.getByLabelText('Conflicting record IDs')).toHaveTextContent('lead-7')
    expect(screen.getByLabelText('Deferred record IDs')).toHaveTextContent('lead-8')
  })

  it('fails closed for a tester on host transfer actions', async () => {
    render(<Transfer role="tester" />)
    expect(await screen.findByText(/Captain role is required on this host/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Review transfer' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Send selected leads to peer' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Save encrypted file' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Import and reconcile' })).toBeDisabled()
    expect(screen.queryByText(/connected peer/i)).toBeNull()
    expect(fetchMock.mock.calls.some(call => String(call[0]) === '/api/transfers/conflicts')).toBe(false)
  })

  it('reviews a transfer conflict, preserves local text, and refreshes after keeping local', async () => {
    let resolved = false
    const incoming = { id: 'lead-7', kind: 'lead', revision_id: 'remote-r', updated_at: '', data: { title: 'Incoming title', observation: 'Incoming summary' } }
    const local = { id: 'lead-7', kind: 'lead', revision_id: 'local-r', updated_at: '', data: { title: 'Local title', observation: 'Local summary' } }
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      if (path === '/api/transfers/conflicts') return response({ items: [{ id: 'conflict-1', kind: 'transfer_conflict', revision_id: 'conflict-r', updated_at: '', data: { state: resolved ? 'resolved' : 'needs_review', bundle_id: 'bundle-held', manifest_hash: 'a'.repeat(64), conflict_ids: ['lead-7'], duplicate_ids: ['asset-1'], deferred_ids: ['upload-1'], incoming: [incoming] }, local: [local] }], total: 1 })
      if (path === '/api/transfers/conflicts/conflict-1/resolve' && init?.method === 'POST') { expect(JSON.parse(String(init.body))).toEqual({ decision: 'keep_local', conflict_revision_id: 'conflict-r', manifest_hash: 'a'.repeat(64), local_revisions: { 'lead-7': 'local-r' } }); resolved = true; return response({ id: 'conflict-1', kind: 'transfer_conflict', revision_id: 'conflict-r2', updated_at: '', data: { state: 'resolved', bundle_id: 'bundle-held', manifest_hash: 'a'.repeat(64), conflict_ids: ['lead-7'], duplicate_ids: ['asset-1'], deferred_ids: ['upload-1'] } }) }
      return baseFetch(path, init)
    })
    render(<Transfer role="captain" />)
    expect(await screen.findByText('Incoming title')).toBeInTheDocument()
    expect(screen.getByText('Local title')).toBeInTheDocument()
    expect(screen.getByText(/1 conflicts · 1 duplicates · 1 deferred/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Keep local records' }))
    await waitFor(() => expect(fetchMock.mock.calls.filter(call => String(call[0]) === '/api/transfers/conflicts').length).toBeGreaterThan(1))
    expect(screen.getByText('resolved')).toBeInTheDocument()
  })

  it('accepts an eligible incoming revision and shows its resolution receipt', async () => {
    let resolved = false
    let resolveAccept!: (value: Response) => void
    const accepted = new Promise<Response>(resolve => { resolveAccept = resolve })
    const conflict = { id: 'conflict-accept', kind: 'transfer_conflict', revision_id: 'conflict-r', updated_at: '', data: { state: 'needs_review', bundle_id: 'bundle-accept', manifest_hash: 'b'.repeat(64), conflict_ids: ['lead-7'], duplicate_ids: ['asset-1'], deferred_ids: ['upload-1'], incoming: [{ id: 'lead-7', kind: 'lead', revision_id: 'remote-r', updated_at: '', data: { title: 'Incoming lead', observation: 'Incoming detail', relationships: ['asset-remote'], evidence_needed: 'Incoming question', source_instance: 'owner-a', source_revision_id: 'source-r' } }] }, local: [{ id: 'lead-7', kind: 'lead', revision_id: 'local-r', updated_at: '', data: { title: 'Local lead', observation: 'Local detail', relationships: ['asset-local'], evidence_needed: 'Local question', source_instance: 'owner-a', source_revision_id: 'source-local' } }] }
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => { const path = String(input); if (path === '/api/transfers/conflicts') return response({ items: [{ ...conflict, data: { ...conflict.data, state: resolved ? 'resolved' : 'needs_review' } }], total: 1 }); if (path === '/api/transfers/conflicts/conflict-accept/resolve' && init?.method === 'POST') { expect(JSON.parse(String(init.body))).toEqual({ decision: 'accept_incoming', conflict_revision_id: 'conflict-r', manifest_hash: 'b'.repeat(64), local_revisions: { 'lead-7': 'local-r' } }); return accepted } return baseFetch(path, init) })
    render(<Transfer role="captain" />)
    const accept = await screen.findByRole('button', { name: 'Accept incoming revision and deferred evidence' })
    expect(screen.getByText('relationships')).toBeInTheDocument()
    expect(screen.getByText('evidence_needed')).toBeInTheDocument()
    expect(screen.getAllByText('Source revision')).toHaveLength(2)
    fireEvent.click(accept)
    expect(accept).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Resolving…' })).toBeDisabled()
    resolved = true
    resolveAccept(response({ ...conflict, revision_id: 'conflict-r2', data: { ...conflict.data, state: 'resolved', resolution: 'accept_incoming' } }))
    expect(await screen.findByText('Incoming acceptance receipt')).toBeInTheDocument()
    expect(screen.getByText(/2 imported · 1 exact duplicates/)).toBeInTheDocument()
    expect(screen.getAllByText(new RegExp(`bundle bundle-accept · manifest ${'b'.repeat(64)}`))).toHaveLength(1)
    expect(await screen.findByText('resolved')).toBeInTheDocument()
  })

  it('shows an accept-incoming rejection while retaining the conflict for review', async () => {
    const conflict = { id: 'conflict-reject', kind: 'transfer_conflict', revision_id: 'conflict-r', updated_at: '', data: { state: 'needs_review', bundle_id: 'bundle-reject', manifest_hash: 'c'.repeat(64), conflict_ids: ['lead-7'], duplicate_ids: [], deferred_ids: [], incoming: [{ id: 'lead-7', kind: 'lead', revision_id: 'remote-r', updated_at: '', data: { title: 'Incoming lead', observation: 'Incoming detail' } }] }, local: [{ id: 'lead-7', kind: 'lead', revision_id: 'local-r', updated_at: '', data: { title: 'Local lead', observation: 'Local detail' } }] }
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => { const path = String(input); if (path === '/api/transfers/conflicts') return response({ items: [conflict], total: 1 }); if (path === '/api/transfers/conflicts/conflict-reject/resolve' && init?.method === 'POST') { expect(JSON.parse(String(init.body))).toEqual({ decision: 'accept_incoming', conflict_revision_id: 'conflict-r', manifest_hash: 'c'.repeat(64), local_revisions: { 'lead-7': 'local-r' } }); return response({ detail: 'Server rejected incoming revision' }, 409) } return baseFetch(path, init) })
    render(<Transfer role="captain" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Accept incoming revision and deferred evidence' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Server rejected incoming revision')
    expect(screen.getByText('Incoming lead')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Accept incoming revision and deferred evidence' })).toBeEnabled()
  })
})
