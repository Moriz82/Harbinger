import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { Evidence, Imports, Overview, Shell } from '../src/main'

const session = { user: { id: 'u1', name: 'Casey', role: 'captain' }, csrf: 'csrf', app: 'Harbinger', engagement: { id: 'e1', name: 'Synthetic engagement' }, mode: 'lan' }
const finding = { id: 'f1', kind: 'finding', revision_id: 'r1', updated_at: '', data: { title: 'Synthetic finding', observation: 'Synthetic observation', impact: '', steps: '', evidence_state: 'observed', writing_state: 'draft', asset_ids: [], evidence_ids: [], evidence_needed: '', notes: '', owner_id: '' } }
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
let fetchMock: ReturnType<typeof vi.fn>
let eventSource: { emit: (type: string) => void; fail: () => void }

beforeEach(() => {
  history.replaceState(null, '', '#/overview')
  vi.stubGlobal('EventSource', class {
    private listeners = new Map<string, (() => void)[]>()
    onerror?: () => void
    constructor() { eventSource = { emit: type => { for (const listener of this.listeners.get(type) ?? []) listener() }, fail: () => this.onerror?.() } }
    addEventListener(type: string, listener: () => void) { this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]) }
    close() {}
  })
  fetchMock = vi.fn((path: string) => {
    if (path === '/api/records?kind=finding') return response({ items: [finding], total: 1 })
    if (path === '/api/evidence') return response({ items: [] })
    if (path.startsWith('/api/assets')) return response({ items: [], total: 0 })
    if (path.startsWith('/api/graph')) return response({ nodes: [], edges: [], total_nodes: 0, total_edges: 0 })
    if (path === '/api/users') return response({ items: [] })
    if (path === '/api/uploads') return response({ items: [] })
    if (path === '/api/readiness') return response({ write_ready: true })
    return response({})
  })
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

it('restores writes only after an SSE reconnect confirms server readiness', async () => {
  fetchMock.mockImplementation((path: string, init?: RequestInit) => {
    if (path === '/api/records?kind=finding') return response({ items: [finding], total: 1 })
    if (path === '/api/evidence') return response({ items: [] })
    if (path === '/api/users') return response({ items: [] })
    if (path.startsWith('/api/assets')) return response({ items: [], total: 0 })
    if (path.startsWith('/api/graph')) return response({ nodes: [], edges: [], total_nodes: 0, total_edges: 0 })
    if (path === '/api/readiness') return response({ write_ready: true })
    if (init?.method === 'PUT') return response({ detail: 'writer blocked' }, 503)
    return response({})
  })
  render(<Shell session={session} onLogout={() => undefined} />)
  act(() => eventSource.emit('open'))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Sign out' })).toBeEnabled())
  fireEvent.click(await screen.findByRole('link', { name: 'Findings' }))
  const observation = await screen.findByLabelText('Observation')
  fireEvent.change(observation, { target: { value: 'Local edit' } })
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  expect(await screen.findByText(/Writes unavailable/)).toBeInTheDocument()
  expect(screen.getByText(/SSE connected/)).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()

  act(() => { eventSource.fail(); eventSource.emit('open') })
  await waitFor(() => expect(screen.getByText(/SSE connected · writes ready/)).toBeInTheDocument())
  expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled()
})

it('keeps writes disabled when reconnect readiness fails', async () => {
  fetchMock.mockImplementation((path: string) => {
    if (path === '/api/readiness') return response({ detail: 'writer blocked' }, 503)
    if (path.startsWith('/api/graph')) return response({ nodes: [], edges: [], total_nodes: 0, total_edges: 0 })
    return response({ items: [], total: 0 })
  })
  render(<Shell session={session} onLogout={() => undefined} />)
  act(() => eventSource.emit('open'))
  await waitFor(() => expect(screen.getByText(/SSE connected · writes unavailable/)).toBeInTheDocument())
  expect(screen.getByRole('button', { name: 'Sign out' })).toBeDisabled()

  act(() => { eventSource.fail(); eventSource.emit('open') })
  await waitFor(() => expect(fetchMock.mock.calls.filter(call => call[0] === '/api/readiness')).toHaveLength(2))
  expect(screen.getByText(/SSE connected · writes unavailable/)).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Sign out' })).toBeDisabled()
})

it('keeps an unsaved finding visible when the session expires', async () => {
  const leave = vi.fn()
  fetchMock.mockImplementation((path: string) => {
    if (path === '/api/session-status') return response({ active: false })
    if (path === '/api/records?kind=finding') return response({ items: [finding], total: 1 })
    if (path === '/api/evidence') return response({ items: [] })
    if (path === '/api/users') return response({ items: [] })
    if (path === '/api/readiness') return response({ write_ready: true })
    if (path.startsWith('/api/graph')) return response({ nodes: [], edges: [], total_nodes: 0, total_edges: 0 })
    if (path.startsWith('/api/assets')) return response({ items: [], total: 0 })
    return response({ items: [], total: 0 })
  })
  render(<Shell session={session} onLogout={leave} />)
  act(() => eventSource.emit('open'))
  fireEvent.click(await screen.findByRole('link', { name: 'Findings' }))
  const observation = await screen.findByLabelText('Observation')
  fireEvent.change(observation, { target: { value: 'Unsaved local finding' } })
  act(() => eventSource.fail())
  expect(await screen.findByText(/Session expired/)).toBeInTheDocument()
  expect(observation).toHaveValue('Unsaved local finding')
  expect(screen.getByRole('button', { name: 'Save draft file' })).toBeEnabled()
  fireEvent.click(screen.getByRole('button', { name: 'Sign in again' }))
  expect(await screen.findByRole('dialog', { name: 'Unsaved finding changes' })).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Stay and save draft file' }))
  expect(observation).toHaveValue('Unsaved local finding')
  expect(leave).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Sign in again' }))
  fireEvent.click(screen.getByRole('button', { name: 'Sign in again and clear local text' }))
  expect(leave).toHaveBeenCalledTimes(1)
})

it('requires explicit review of partial import limitations before merge', async () => {
  const upload = { id: 'upload-1', kind: 'upload', revision_id: 'u1', updated_at: '', data: { filename: 'partial.xml', format: 'nmap_text', status: 'uploaded' } }
  fetchMock.mockImplementation((path: string, init?: RequestInit) => {
    if (path === '/api/uploads') return response({ items: [upload] })
    if (path.endsWith('/parse')) return response({ ...upload, revision_id: 'u2', data: { ...upload.data, status: 'preview' } })
    if (path.endsWith('/preview')) return response({ complete: false, quarantined: false, limitations: ['Text import is lossy.'], assets: [], relationships: [], observations: [], _review: { upload_revision_id: 'u2', preview_revision_id: 'p1', preview_hash: 'a'.repeat(64) } })
    return response({})
  })
  render(<Imports />)
  fireEvent.click(await screen.findByRole('button', { name: /partial.xml/ }))
  fireEvent.click(screen.getByRole('button', { name: 'Parse preview' }))
  expect(await screen.findByText('Partial')).toBeInTheDocument()
  const merge = screen.getByRole('button', { name: 'Merge records' })
  expect(merge).toBeDisabled()
  fireEvent.click(screen.getByLabelText(/reviewed this preview/i))
  expect(merge).toBeEnabled()
})

it('renders an approved local image with alternative text', async () => {
  const item = { id: 'image-1', kind: 'upload', revision_id: 'r1', updated_at: '', data: { filename: 'synthetic.png', reviewed_for_export: true } }
  fetchMock.mockImplementation((path: string) => {
    if (path === '/api/evidence') return response({ items: [item] })
    if (path.endsWith('/preview')) return response({ text: 'binary image', quarantined: false, base_revision_id: 'r1', artifact_sha256: 'b'.repeat(64), inline_image_media_type: 'image/png' })
    return response({})
  })
  render(<Evidence session={session} />)
  fireEvent.click(await screen.findByRole('button', { name: 'synthetic.png' }))
  expect(await screen.findByRole('img', { name: 'synthetic.png' })).toHaveAttribute('src', '/api/evidence/image-1/render')
})

it('provides a synchronized accessible relationship list and reports map initialization failure', async () => {
  render(<Overview refreshKey={0} />)
  expect(await screen.findByRole('region', { name: 'Accessible relationship list' })).toBeInTheDocument()
  expect(screen.getByRole('table', { name: 'Imported assets' })).toBeInTheDocument()
})
