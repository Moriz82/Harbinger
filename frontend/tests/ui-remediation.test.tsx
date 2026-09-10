import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { Evidence, Imports, Overview, Shell, Transfer } from '../src/main'

const session = { user: { id: 'u1', name: 'Casey', role: 'captain' }, csrf: 'csrf', app: 'Harbinger', engagement: { id: 'e1', name: 'Synthetic engagement' }, mode: 'lan' }
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
const deferred = () => { let resolve!: (value: Response) => void; const promise = new Promise<Response>(done => { resolve = done }); return { promise, resolve } }
let fetchMock: ReturnType<typeof vi.fn>
let stream: { emit: (type: string) => void; fail: () => void }
function baseFetch(path: string) {
  if (path === '/api/readiness') return response({ write_ready: true })
  if (path === '/api/connections') return response({ peers: [] })
  if (path.startsWith('/api/graph')) return response({ nodes: [], edges: [], total_nodes: 0, total_edges: 0 })
  return response({ items: [], total: 0 })
}
beforeEach(() => {
  history.replaceState(null, '', '#/overview')
  vi.stubGlobal('EventSource', class {
    listeners = new Map<string, (() => void)[]>()
    onerror?: () => void
    constructor() { stream = { emit: type => this.listeners.get(type)?.forEach(listener => listener()), fail: () => this.onerror?.() } }
    addEventListener(type: string, listener: () => void) { this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]) }
    close() {}
  })
  fetchMock = vi.fn(baseFetch)
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

it('defines every workspace theme variable in the shared token sheet', () => {
  const tokens = readFileSync('src/styles/tokens.css', 'utf8')
  const workspaces = readFileSync('src/styles/workspaces.css', 'utf8')
  const defined = new Set([...tokens.matchAll(/(--[a-z0-9-]+)\s*:/gi)].map(match => match[1]))
  const used = [...workspaces.matchAll(/var\((--[a-z0-9-]+)/gi)].map(match => match[1])
  expect(used.length).toBeGreaterThan(0)
  for (const name of used) expect(defined).toContain(name)
})

it('labels an unapproved image as available for review', async () => {
  const item = { id: 'image-1', kind: 'upload', revision_id: 'r1', updated_at: '', data: { filename: 'synthetic.png', sha256: 'a'.repeat(64), reviewed_for_export: false } }
  fetchMock.mockImplementation((path: string) => path === '/api/evidence'
    ? response({ items: [item] })
    : response({ text: 'Synthetic preview', quarantined: false, base_revision_id: 'r1', artifact_sha256: 'a'.repeat(64), inline_image_media_type: 'image/png' }))
  render(<Evidence session={session} />)
  fireEvent.click(await screen.findByRole('button', { name: 'synthetic.png' }))
  expect(await screen.findByText('Local image available for review. Source bytes remain restricted.')).toBeInTheDocument()
  expect(screen.queryByText('Approved local image. Source bytes remain restricted.')).not.toBeInTheDocument()
  expect(screen.getByText('synthetic.png · local image available for review')).toBeInTheDocument()
})

it('announces upload progress before the server creates an upload record', async () => {
  const pending = deferred()
  fetchMock.mockImplementation((path: string, init?: RequestInit) => path === '/api/uploads' && init?.method === 'POST' ? pending.promise : baseFetch(path))
  render(<Imports />)
  await screen.findByText('No imports yet')
  fireEvent.change(screen.getByLabelText('File'), { target: { files: [new File(['synthetic'], 'synthetic.xml', { type: 'text/xml' })] } })
  fireEvent.click(screen.getByRole('button', { name: 'Upload source' }))
  expect(screen.getAllByRole('status').some(node => node.textContent === 'Uploading source…')).toBe(true)
  await act(async () => pending.resolve(response({ id: 'upload-1', kind: 'upload', revision_id: 'r1', updated_at: '', data: { filename: 'synthetic.xml', format: 'nmap_xml', status: 'uploaded' } })))
})

it('keeps isolated map nodes keyboard-selectable in the accessible list', async () => {
  fetchMock.mockImplementation((path: string) => path.startsWith('/api/graph')
    ? response({ nodes: [{ id: 'isolated-1', label: 'Isolated asset', kind: 'host', track: 'network' }], edges: [], total_nodes: 1, total_edges: 0 })
    : path.startsWith('/api/assets')
      ? response({ items: [{ id: 'isolated-1', label: 'Isolated asset', kind: 'host', track: 'network', revision_id: 'r1', data: {} }], total: 1 })
      : baseFetch(path))
  render(<Overview refreshKey={0} />)
  expect(await screen.findByRole('button', { name: 'Isolated asset' })).toBeInTheDocument()
})

it('distinguishes an in-progress readiness check from a blocked writer and permits manual recovery', async () => {
  const pending = deferred()
  fetchMock.mockImplementation((path: string) => path === '/api/readiness' ? pending.promise : baseFetch(path))
  render(<Shell session={session} onLogout={() => undefined} />)
  await act(async () => stream.emit('open'))
  expect(screen.getByText(/Checking server write readiness/)).toBeInTheDocument()
  expect(screen.queryByText(/server refused a mutation/)).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Retry readiness' })).toBeDisabled()
  await act(async () => pending.resolve(response({ write_ready: false })))
  expect(screen.getByRole('button', { name: 'Sign out' })).toBeDisabled()
  fetchMock.mockImplementation(baseFetch)
  fireEvent.click(screen.getByRole('button', { name: 'Retry readiness' }))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Sign out' })).toBeEnabled())
})

it('reports a failed readiness request and recovers without reopening the stream', async () => {
  fetchMock.mockImplementation((path: string) => path === '/api/readiness' ? Promise.reject(new Error('Synthetic network failure')) : baseFetch(path))
  render(<Shell session={session} onLogout={() => undefined} />)
  act(() => stream.emit('open'))
  expect(await screen.findByText(/Readiness check failed/)).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Sign out' })).toBeDisabled()
  fetchMock.mockImplementation(baseFetch)
  fireEvent.click(screen.getByRole('button', { name: 'Retry readiness' }))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Sign out' })).toBeEnabled())
})

it('ignores readiness responses from a disconnected stream generation', async () => {
  const oldCheck = deferred(), currentCheck = deferred()
  let checks = 0
  fetchMock.mockImplementation((path: string) => path === '/api/readiness' ? (++checks === 1 ? oldCheck.promise : currentCheck.promise) : baseFetch(path))
  render(<Shell session={session} onLogout={() => undefined} />)
  act(() => stream.emit('open'))
  act(() => { stream.fail(); stream.emit('open') })
  await act(async () => currentCheck.resolve(response({ write_ready: false })))
  await act(async () => oldCheck.resolve(response({ write_ready: true })))
  expect(screen.getByRole('button', { name: 'Sign out' })).toBeDisabled()
  expect(screen.getByRole('button', { name: 'Retry readiness' })).toBeEnabled()
})

it('does not let an older readiness response override a newer mutation failure', async () => {
  const mutation = deferred(), check = deferred()
  let checks = 0
  fetchMock.mockImplementation((path: string) => {
    if (path === '/api/readiness') return ++checks === 1 ? response({ write_ready: true }) : check.promise
    if (path === '/api/logout') return mutation.promise
    return baseFetch(path)
  })
  render(<Shell session={session} onLogout={() => undefined} />)
  act(() => stream.emit('open'))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Sign out' })).toBeEnabled())
  fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
  fireEvent.click(screen.getByRole('button', { name: 'Retry readiness' }))
  await act(async () => mutation.resolve(response({ detail: 'Synthetic writer blocked' }, 503)))
  await act(async () => check.resolve(response({ write_ready: true })))
  expect(screen.getByRole('button', { name: 'Sign out' })).toBeDisabled()
})

it('records server update events without claiming a successful sync on connection open', async () => {
  vi.useFakeTimers({ toFake: ['Date'] })
  vi.setSystemTime(new Date('2026-09-09T12:00:00Z'))
  render(<Shell session={session} onLogout={() => undefined} />)
  await act(async () => stream.emit('open'))
  expect(screen.getByText(/SSE connected/)).toHaveTextContent('Last server update: not yet')
  expect(screen.queryByText(/successful sync/i)).not.toBeInTheDocument()
  act(() => stream.emit('change'))
  const received = screen.getByText(/SSE connected/).textContent
  expect(received).not.toContain('Last server update: not yet')
  vi.setSystemTime(new Date('2026-09-09T13:00:00Z'))
  await act(async () => { stream.fail(); stream.emit('open') })
  expect(screen.getByText(/SSE connected/).textContent).toBe(received)
  vi.useRealTimers()
})

it('moves skip-link focus to content with a visible focus outline', async () => {
  const style = document.createElement('style')
  style.textContent = readFileSync('src/styles/base.css', 'utf8')
  document.head.append(style)
  try {
    render(<Shell session={session} onLogout={() => undefined} />)
    await act(async () => fireEvent.click(screen.getByRole('link', { name: 'Skip to content' })))
    const content = screen.getByRole('main')
    expect(content).toHaveFocus()
    expect(getComputedStyle(content).outline).not.toBe('none')
    expect(getComputedStyle(content).outline).not.toBe('')
  } finally { style.remove() }
})

it.each([
  ['synthetic.png', undefined],
  ['synthetic.webp', undefined],
  ['synthetic.jpg', null],
  ['synthetic.gif', 'image/webp'],
])('uses text when %s has no supported server image metadata', async (filename, mediaType) => {
  const item = { id: 'image-1', kind: 'upload', revision_id: 'r1', updated_at: '', data: { filename, reviewed_for_export: true } }
  fetchMock.mockImplementation((path: string) => path === '/api/evidence' ? response({ items: [item] }) : response({ text: 'Synthetic text fallback', quarantined: false, base_revision_id: 'r1', artifact_sha256: 'a'.repeat(64), inline_image_media_type: mediaType }))
  render(<Evidence session={session} />)
  fireEvent.click(await screen.findByRole('button', { name: filename }))
  expect(await screen.findByText('Synthetic text fallback')).toBeInTheDocument()
  expect(screen.queryByRole('img')).not.toBeInTheDocument()
})

it('uses verified image metadata regardless of filename and preserves text after image load failure', async () => {
  const item = { id: 'image-1', kind: 'upload', revision_id: 'r1', updated_at: '', data: { filename: 'synthetic.dat', reviewed_for_export: true } }
  fetchMock.mockImplementation((path: string) => path === '/api/evidence' ? response({ items: [item] }) : response({ text: 'Synthetic text fallback', quarantined: false, base_revision_id: 'r1', artifact_sha256: 'a'.repeat(64), inline_image_media_type: 'image/png' }))
  render(<Evidence session={session} />)
  fireEvent.click(await screen.findByRole('button', { name: 'synthetic.dat' }))
  const image = await screen.findByRole('img', { name: 'synthetic.dat' })
  expect(image).toHaveAttribute('src', '/api/evidence/image-1/render')
  fireEvent.error(image)
  expect(screen.getByText(/Image preview could not load/)).toBeInTheDocument()
  expect(screen.getByText('Synthetic text fallback')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'synthetic.dat' }))
  expect(await screen.findByRole('img', { name: 'synthetic.dat' })).toBeInTheDocument()
})

it('shows approved image status when restricted binary preview metadata is approved', async () => {
  const item = { id: 'image-1', kind: 'upload', revision_id: 'r1', updated_at: '', data: { filename: 'synthetic.png', sha256: 'a'.repeat(64), reviewed_for_export: true } }
  fetchMock.mockImplementation((path: string) => path === '/api/evidence'
    ? response({ items: [item] })
    : response({ text: 'Binary preview is restricted.', quarantined: true, base_revision_id: 'r1', artifact_sha256: 'a'.repeat(64), inline_image_media_type: 'image/png' }))
  render(<Evidence session={session} />)
  fireEvent.click(await screen.findByRole('button', { name: 'synthetic.png' }))
  expect(await screen.findByText('Approved local image. Source bytes remain restricted.')).toBeInTheDocument()
  expect(screen.queryByText(/Quarantined source/)).not.toBeInTheDocument()
  expect(screen.getByRole('img', { name: 'synthetic.png' })).toBeInTheDocument()
})

it('retains a rendered image across its audit refresh and clears it after revision drift', async () => {
  history.replaceState(null, '', '#/evidence')
  let revision = 'r1'
  let artifact = 'a'.repeat(64)
  fetchMock.mockImplementation((path: string) => {
    if (path === '/api/readiness') return response({ write_ready: true })
    if (path === '/api/connections') return response({ peers: [] })
    if (path === '/api/evidence') return response({ items: [{ id: 'image-1', kind: 'upload', revision_id: revision, updated_at: '', data: { filename: 'synthetic.png', sha256: artifact, reviewed_for_export: true } }] })
    if (path === '/api/evidence/image-1/preview') return response({ text: 'Binary preview is restricted.', quarantined: true, base_revision_id: 'r1', artifact_sha256: 'a'.repeat(64), inline_image_media_type: 'image/png' })
    return baseFetch(path)
  })
  render(<Shell session={session} onLogout={() => undefined} />)
  await act(async () => stream.emit('open'))
  fireEvent.click(await screen.findByRole('button', { name: 'synthetic.png' }))
  expect(await screen.findByRole('img', { name: 'synthetic.png' })).toBeInTheDocument()

  act(() => stream.emit('change'))
  await waitFor(() => expect(fetchMock.mock.calls.filter(call => call[0] === '/api/evidence').length).toBeGreaterThan(1))
  expect(screen.getByRole('img', { name: 'synthetic.png' })).toBeInTheDocument()

  revision = 'r2'
  artifact = 'b'.repeat(64)
  act(() => stream.emit('change'))
  expect(await screen.findByText(/Evidence preview is unavailable/)).toBeInTheDocument()
  expect(screen.queryByRole('img', { name: 'synthetic.png' })).not.toBeInTheDocument()
})

it('finishes an unchanged preview request that overlaps an SSE refresh', async () => {
  history.replaceState(null, '', '#/evidence')
  const pendingPreview = deferred()
  const item = { id: 'image-1', kind: 'upload', revision_id: 'r1', updated_at: '', data: { filename: 'synthetic.png', sha256: 'a'.repeat(64), reviewed_for_export: true } }
  fetchMock.mockImplementation((path: string) => {
    if (path === '/api/readiness') return response({ write_ready: true })
    if (path === '/api/connections') return response({ peers: [] })
    if (path === '/api/evidence') return response({ items: [item] })
    if (path === '/api/evidence/image-1/preview') return pendingPreview.promise
    return baseFetch(path)
  })
  render(<Shell session={session} onLogout={() => undefined} />)
  await act(async () => stream.emit('open'))
  fireEvent.click(await screen.findByRole('button', { name: 'synthetic.png' }))
  expect(screen.getByText('Loading evidence preview…')).toBeInTheDocument()
  act(() => stream.emit('change'))
  await waitFor(() => expect(fetchMock.mock.calls.filter(call => call[0] === '/api/evidence').length).toBeGreaterThan(1))
  await act(async () => pendingPreview.resolve(response({ text: 'Binary preview is restricted.', quarantined: true, base_revision_id: 'r1', artifact_sha256: 'a'.repeat(64), inline_image_media_type: 'image/png' })))
  expect(await screen.findByRole('img', { name: 'synthetic.png' })).toBeInTheDocument()
  expect(screen.queryByText('Loading evidence preview…')).not.toBeInTheDocument()
})

it('rejects a stale pending preview and ends loading after SSE binding drift', async () => {
  history.replaceState(null, '', '#/evidence')
  const pendingPreview = deferred()
  let item = { id: 'image-1', kind: 'upload', revision_id: 'r1', updated_at: '', data: { filename: 'synthetic.png', sha256: 'a'.repeat(64), reviewed_for_export: true } }
  fetchMock.mockImplementation((path: string) => {
    if (path === '/api/readiness') return response({ write_ready: true })
    if (path === '/api/connections') return response({ peers: [] })
    if (path === '/api/evidence') return response({ items: [item] })
    if (path === '/api/evidence/image-1/preview') return pendingPreview.promise
    return baseFetch(path)
  })
  render(<Shell session={session} onLogout={() => undefined} />)
  await act(async () => stream.emit('open'))
  fireEvent.click(await screen.findByRole('button', { name: 'synthetic.png' }))
  expect(screen.getByText('Loading evidence preview…')).toBeInTheDocument()
  item = { ...item, revision_id: 'r2', data: { ...item.data, sha256: 'b'.repeat(64) } }
  act(() => stream.emit('change'))
  expect(await screen.findByText(/Evidence preview is unavailable/)).toBeInTheDocument()
  await act(async () => pendingPreview.resolve(response({ text: 'Old binary preview.', quarantined: true, base_revision_id: 'r1', artifact_sha256: 'a'.repeat(64), inline_image_media_type: 'image/png' })))
  expect(screen.queryByText('Loading evidence preview…')).not.toBeInTheDocument()
  expect(screen.queryByRole('img', { name: 'synthetic.png' })).not.toBeInTheDocument()
})

it.each([{ online: false, writeReady: true }, { online: true, writeReady: false }])('retains loaded conflict details while resolution is disabled: %j', async state => {
  const conflict = { id: 'conflict-1', kind: 'transfer_conflict', revision_id: 'r1', updated_at: '', data: { state: 'needs_review', bundle_id: 'synthetic-bundle', manifest_hash: 'b'.repeat(64), conflict_ids: ['lead-1'], duplicate_ids: [], deferred_ids: [], incoming: [{ id: 'lead-1', kind: 'lead', revision_id: 'remote-r1', updated_at: '', data: { title: 'Synthetic incoming title' } }] }, local: [{ id: 'lead-1', kind: 'lead', revision_id: 'local-r1', updated_at: '', data: { title: 'Synthetic retained local title' } }] }
  fetchMock.mockImplementation((path: string) => path === '/api/transfers/conflicts' ? response({ items: [conflict] }) : baseFetch(path))
  const { rerender } = render(<Transfer role="captain" />)
  expect(await screen.findByText('Synthetic retained local title')).toBeInTheDocument()
  rerender(<Transfer role="captain" {...state} />)
  expect(screen.getByText('Synthetic retained local title')).toBeInTheDocument()
  expect(screen.getByText('Synthetic incoming title')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Keep local records' })).toBeDisabled()
  expect(screen.getByRole('button', { name: 'Accept incoming revision and deferred evidence' })).toBeDisabled()
  expect(screen.getByText(/previously loaded conflict details/i)).toBeInTheDocument()
})
