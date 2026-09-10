import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { App, Evidence, Findings, Imports, Overview, Shell } from '../src/main'

const session = { user: { id: 'u1', name: 'Casey', role: 'captain' }, csrf: 'csrf', app: 'Harbinger', engagement: { id: 'e1', name: 'Synthetic engagement' }, mode: 'lan' }
const finding = { id: 'f1', kind: 'finding', revision_id: 'r1', updated_at: '2026-09-09T12:00:00Z', data: { title: 'Synthetic finding', observation: 'Original observation', impact: 'Original impact', writing_state: 'draft', evidence_state: 'observed', asset_ids: [], evidence_ids: [] } }
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
let fetchMock: ReturnType<typeof vi.fn>
function base(path: string) {
  if (path === '/api/readiness') return response({ write_ready: true })
  if (path === '/api/records?kind=finding') return response({ items: [finding], total: 1 })
  if (path.startsWith('/api/assets')) { const page = new URL(path, 'http://localhost').searchParams; return response({ items: [{ id: page.get('offset') === '100' ? 'a151' : 'a1', label: page.get('offset') === '100' ? 'Asset 151' : 'Asset 1', kind: 'host', track: 'network', revision_id: 'ra' }], total: 151 }) }
  if (path.startsWith('/api/graph')) return response({ nodes: [], edges: [], total_nodes: 0, total_edges: 0 })
  return response({ items: [], total: 0 })
}
beforeEach(() => {
  history.replaceState(null, '', '#/overview')
  vi.stubGlobal('EventSource', class { addEventListener(type: string, fn: () => void) { if (type === 'open') queueMicrotask(fn) } close() {} })
  fetchMock = vi.fn((path: string) => base(path)); vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

it('retains later keystrokes when a delayed finding PUT acknowledges an older snapshot', async () => {
  let finish!: (value: Response) => void
  fetchMock.mockImplementation((path: string, init?: RequestInit) => init?.method === 'PUT' ? new Promise<Response>(resolve => { finish = resolve }) : base(path))
  render(<Findings session={session} refreshKey={0} onDirty={() => undefined} />)
  const observation = await screen.findByLabelText('Observation')
  fireEvent.change(observation, { target: { value: 'Snapshot A' } }); fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  fireEvent.change(observation, { target: { value: 'Later keystrokes B' } })
  await act(async () => finish(response({ ...finding, revision_id: 'r2', data: { ...finding.data, observation: 'Snapshot A' } })))
  expect(observation).toHaveValue('Later keystrokes B')
  expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled()
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  const calls = fetchMock.mock.calls.filter(call => call[1]?.method === 'PUT')
  expect(JSON.parse(calls[1][1].body)).toMatchObject({ base_revision_id: 'r2', data: { observation: 'Later keystrokes B' } })
  await act(async () => finish(response({ ...finding, revision_id: 'r3', data: { ...finding.data, observation: 'Later keystrokes B' } })))
})

it('serializes a first finding save and uses its returned ID for later edits', async () => {
  let finish!: (value: Response) => void
  fetchMock.mockImplementation((path: string, init?: RequestInit) => {
    if (init?.method === 'POST') return new Promise<Response>(resolve => { finish = resolve })
    if (init?.method === 'PUT') return response({ ...finding, id: 'f2', revision_id: 'r3', data: JSON.parse(String(init.body)).data })
    return base(path)
  })
  render(<Findings session={session} refreshKey={0} onDirty={() => undefined} />)
  await screen.findByLabelText('Observation'); fireEvent.click(screen.getByRole('button', { name: 'New finding' }))
  fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'New finding' } })
  fireEvent.change(screen.getByLabelText('Observation'), { target: { value: 'First' } })
  fireEvent.click(screen.getByRole('button', { name: 'Save' })); fireEvent.click(screen.getByRole('button', { name: /^Sav(e|ing…)$/ }))
  expect(fetchMock.mock.calls.filter(call => call[1]?.method === 'POST')).toHaveLength(1)
  fireEvent.change(screen.getByLabelText('Observation'), { target: { value: 'Second' } })
  await act(async () => finish(response({ ...finding, id: 'f2', revision_id: 'r2', data: { ...finding.data, title: 'New finding', observation: 'First' } })))
  expect(screen.getByLabelText('Observation')).toHaveValue('Second')
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(fetchMock.mock.calls.filter(call => call[1]?.method === 'PUT')).toHaveLength(1))
})

it('selects finding assets beyond the first hundred and retains selections across pages', async () => {
  render(<Findings session={session} refreshKey={0} onDirty={() => undefined} />)
  const group = await screen.findByRole('group', { name: 'Assets in scope' })
  fireEvent.click(await within(group).findByLabelText('Asset 1'))
  fireEvent.click(within(group).getByRole('button', { name: 'Next assets' }))
  fireEvent.click(await within(group).findByLabelText('Asset 151'))
  fireEvent.click(within(group).getByRole('button', { name: 'Previous assets' }))
  expect(await within(group).findByLabelText('Asset 1')).toBeChecked()
  expect(within(group).getByText(/2 selected/)).toBeInTheDocument()
})

it('contains dialog focus, closes with Escape, restores focus, and clears discarded shell state', async () => {
  render(<Shell session={session} onLogout={() => undefined} />)
  fireEvent.click(screen.getByRole('link', { name: 'Findings' }))
  fireEvent.change(await screen.findByLabelText('Observation'), { target: { value: 'Local work' } })
  const trigger = screen.getByRole('link', { name: 'Imports' }); trigger.focus(); fireEvent.click(trigger)
  const dialog = screen.getByRole('dialog'); const stay = within(dialog).getByRole('button', { name: 'Stay' })
  expect(stay).toHaveFocus()
  const buttons = within(dialog).getAllByRole('button'); buttons[buttons.length - 1].focus(); fireEvent.keyDown(dialog, { key: 'Tab' })
  expect(buttons[0]).toHaveFocus()
  fireEvent.keyDown(dialog, { key: 'Escape' }); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(trigger).toHaveFocus()
  fireEvent.click(trigger); fireEvent.click(screen.getByRole('button', { name: 'Discard changes' }))
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  await act(async () => fireEvent.click(screen.getByRole('link', { name: 'Evidence' }))); expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
})

it('shows submitted findings as submitted and compares every differing editable field', async () => {
  let changed = false
  fetchMock.mockImplementation((path: string) => path === '/api/records?kind=finding' ? response({ items: [{ ...finding, revision_id: changed ? 'r2' : 'r1', data: { ...finding.data, writing_state: 'submitted', impact: changed ? 'Remote impact' : 'Original impact', title: changed ? 'Remote title' : finding.data.title } }], total: 1 }) : base(path))
  const view = render(<Findings session={session} refreshKey={0} onDirty={() => undefined} />)
  expect(await screen.findByRole('combobox', { name: /Writing state/ })).toHaveDisplayValue('Submitted')
  fireEvent.change(screen.getByLabelText('Observation'), { target: { value: 'Local edits' } })
  changed = true; view.rerender(<Findings session={session} refreshKey={1} onDirty={() => undefined} />)
  expect(await screen.findByText('Remote impact')).toBeInTheDocument()
  expect(within(screen.getByLabelText('Editable field comparison')).getByText('Remote title')).toBeInTheDocument()
})

it('opens a deep route and ignores the skip link as an application route', async () => {
  history.replaceState(null, '', '#/findings')
  render(<Shell session={session} onLogout={() => undefined} />)
  await screen.findByLabelText('Observation')
  fireEvent.click(screen.getByRole('link', { name: 'Skip to content' }))
  expect(location.hash).toBe('#/findings'); expect(screen.getByRole('main')).toHaveFocus()
  await act(async () => { location.hash = '#/imports'; dispatchEvent(new HashChangeEvent('hashchange')) })
  expect(await screen.findByLabelText('File')).toBeInTheDocument()
})

it('reports graph caps and marks retained graph data stale after a refresh failure', async () => {
  let failed = false
  fetchMock.mockImplementation((path: string) => path.startsWith('/api/graph') ? failed ? response({ detail: 'Graph refresh failed' }, 503) : response({ nodes: [{ id: 'a1', label: 'Asset 1', kind: 'host', track: 'network' }], edges: [], total_nodes: 2000, total_edges: 0 }) : base(path))
  const view = render(<Overview refreshKey={0} />)
  expect(await screen.findByText('Graph: 1 of 2,000 matching assets')).toBeInTheDocument()
  failed = true; view.rerender(<Overview refreshKey={1} />)
  expect(await screen.findByText(/Map is stale/)).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Retry map' })).toBeInTheDocument()
})

it('distinguishes an initial finding request failure from an empty queue', async () => {
  fetchMock.mockImplementation((path: string) => path === '/api/records?kind=finding' ? response({ detail: 'Cannot load findings' }, 503) : base(path))
  render(<Findings session={session} refreshKey={0} onDirty={() => undefined} />)
  expect(await screen.findByText('Cannot load findings')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Retry findings' })).toBeInTheDocument()
  expect(screen.queryByText('No findings yet')).not.toBeInTheDocument()
})

it('shows an evidence preview loading state until the selected request resolves', async () => {
  let finish!: (value: Response) => void
  fetchMock.mockImplementation((path: string) => path === '/api/evidence' ? response({ items: [{ id: 'e1', kind: 'upload', revision_id: 'r1', data: { filename: 'Synthetic.txt' } }] }) : path === '/api/evidence/e1/preview' ? new Promise<Response>(resolve => { finish = resolve }) : base(path))
  render(<Evidence session={session} refreshKey={0} />)
  fireEvent.click(await screen.findByRole('button', { name: 'Synthetic.txt' }))
  expect(screen.getByText('Loading evidence preview…')).toBeInTheDocument()
  expect(screen.queryByText('Select evidence')).not.toBeInTheDocument()
  await act(async () => finish(response({ text: 'Synthetic text', quarantined: false })))
  expect(screen.getByText('Synthetic text')).toBeInTheDocument()
})

it('shows loading and retry when the import list request fails', async () => {
  let finish!: (value: Response) => void
  fetchMock.mockImplementation((path: string) => path === '/api/uploads' ? new Promise<Response>(resolve => { finish = resolve }) : base(path))
  render(<Imports refreshKey={0} />)
  expect(screen.getByText('Loading imports…')).toBeInTheDocument()
  await act(async () => finish(response({ detail: 'Import list unavailable' }, 503)))
  expect(screen.getByRole('button', { name: 'Retry imports' })).toBeInTheDocument()
})

it('keeps a session service failure distinct from a signed-out account', async () => {
  fetchMock.mockImplementation((path: string) => path === '/api/session' ? response({ detail: 'Session service unavailable' }, 503) : base(path))
  render(<App />)
  expect(await screen.findByRole('alert')).toHaveTextContent('Session service unavailable')
  expect(screen.getByRole('button', { name: 'Retry session' })).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Sign in' })).not.toBeInTheDocument()
})
