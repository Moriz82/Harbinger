import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { Evidence, Findings, Imports } from '../src/main'

const session = { user: { id: 'u1', name: 'Casey', role: 'captain' }, csrf: 'csrf', app: 'Harbinger', engagement: { id: 'e1', name: 'Synthetic engagement' }, mode: 'lan' }
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
const upload = (n: number) => ({ id: `u${n}`, kind: 'upload', revision_id: 'r1', updated_at: '', data: { filename: `Source ${n}`, format: 'manual_json', status: 'uploaded', sha256: 'a'.repeat(64) } })
const finding = (n: number) => ({ id: `f${n}`, kind: 'finding', revision_id: 'r1', updated_at: '', data: { title: `Finding ${n}`, observation: `Observation ${n}`, writing_state: 'draft', evidence_state: 'observed', asset_ids: [], evidence_ids: [] } })
let fetchMock: ReturnType<typeof vi.fn>
beforeEach(() => { fetchMock = vi.fn(); vi.stubGlobal('fetch', fetchMock) })
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

it('loads the 101st import and deduplicates an overlapping page without losing selection', async () => {
  const first = Array.from({ length: 100 }, (_, i) => upload(i + 1))
  fetchMock.mockImplementation((path: string) => path === '/api/uploads' ? response({ items: first, total: 101 }) : path === '/api/uploads?limit=100&offset=100' ? response({ items: [upload(100), upload(101)], total: 101 }) : response({}))
  render(<Imports />)
  await screen.findByRole('button', { name: /Source 100/ })
  fireEvent.click(screen.getByRole('button', { name: /Source 1 manual_json/ }))
  fireEvent.click(screen.getByRole('button', { name: 'Load more imports' }))
  await screen.findByRole('button', { name: /Source 101/ })
  expect(screen.getAllByRole('button', { name: /Source 100/ })).toHaveLength(1)
  expect(screen.getByRole('button', { name: 'Parse preview' })).toBeInTheDocument()
  expect(fetchMock).toHaveBeenCalledWith('/api/uploads?limit=100&offset=100', expect.anything())
})

it('keeps an evidence preview while loading the 101st evidence record', async () => {
  const first = Array.from({ length: 100 }, (_, i) => upload(i + 1))
  fetchMock.mockImplementation((path: string) => path === '/api/evidence' ? response({ items: first, total: 101 }) : path === '/api/evidence?limit=100&offset=100' ? response({ items: [upload(101)], total: 101 }) : path === '/api/evidence/u1/preview' ? response({ text: 'Synthetic preview', quarantined: false, base_revision_id: 'r1', artifact_sha256: 'a'.repeat(64) }) : response({}))
  render(<Evidence session={session} />)
  await screen.findByRole('button', { name: 'Source 100' })
  fireEvent.click(screen.getByRole('button', { name: 'Source 1' }))
  await screen.findByText('Synthetic preview')
  fireEvent.click(screen.getByRole('button', { name: 'Load more evidence' }))
  await screen.findByRole('button', { name: 'Source 101' })
  expect(screen.getByText('Synthetic preview')).toBeInTheDocument()
})

it('revalidates a selected older evidence record before showing its refreshed preview', async () => {
  const first = Array.from({ length: 100 }, (_, i) => upload(i + 1))
  const older = upload(101)
  const changed = { ...older, revision_id: 'r2', data: { ...older.data, sha256: 'b'.repeat(64) } }
  let refreshed = false
  fetchMock.mockImplementation((path: string) => {
    if (path === '/api/evidence') return response({ items: first, total: 101 })
    if (path === '/api/evidence?limit=100&offset=100') return response({ items: [older], total: 101 })
    if (path === '/api/records/u101') return response(changed)
    if (path === '/api/evidence/u101/preview') return response({ text: refreshed ? 'Changed synthetic proof' : 'Old synthetic proof', quarantined: false, base_revision_id: refreshed ? 'r2' : 'r1', artifact_sha256: (refreshed ? 'b' : 'a').repeat(64) })
    return response({})
  })
  const view = render(<Evidence session={session} refreshKey={0} />)
  fireEvent.click(await screen.findByRole('button', { name: 'Load more evidence' }))
  fireEvent.click(await screen.findByRole('button', { name: 'Source 101' }))
  expect(await screen.findByText('Old synthetic proof')).toBeInTheDocument()
  refreshed = true
  view.rerender(<Evidence session={session} refreshKey={1} />)
  expect(await screen.findByText('Changed synthetic proof')).toBeInTheDocument()
  expect(screen.queryByText('Old synthetic proof')).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Approve reviewed derivative' })).toBeDisabled()
  expect(fetchMock.mock.calls.some(call => call[0] === '/api/records/u101')).toBe(true)
})

it('clears a deleted older selection and ignores its delayed preview', async () => {
  const first = Array.from({ length: 100 }, (_, i) => upload(i + 1))
  let finishPreview!: (value: Response) => void
  let refreshed = false
  fetchMock.mockImplementation((path: string) => {
    if (path === '/api/evidence') return response({ items: first, total: refreshed ? 100 : 101 })
    if (path === '/api/evidence?limit=100&offset=100') return response({ items: [upload(101)], total: 101 })
    if (path === '/api/records/u101') return response({ detail: 'Not found' }, 404)
    if (path === '/api/evidence/u101/preview') return new Promise<Response>(resolve => { finishPreview = resolve })
    return response({})
  })
  const view = render(<Evidence session={session} refreshKey={0} />)
  fireEvent.click(await screen.findByRole('button', { name: 'Load more evidence' }))
  fireEvent.click(await screen.findByRole('button', { name: 'Source 101' }))
  await waitFor(() => expect(finishPreview).toBeTypeOf('function'))
  refreshed = true
  view.rerender(<Evidence session={session} refreshKey={1} />)
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Source 101' })).not.toBeInTheDocument())
  await act(async () => finishPreview(response({ text: 'Deleted stale proof', quarantined: false, base_revision_id: 'r1', artifact_sha256: 'a'.repeat(64) })))
  expect(screen.queryByText('Deleted stale proof')).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Approve reviewed derivative' })).not.toBeInTheDocument()
})

it('loads the 501st finding and 101st supporting evidence while retaining an unsaved draft', async () => {
  const first = Array.from({ length: 500 }, (_, i) => finding(i + 1))
  const evidence = Array.from({ length: 100 }, (_, i) => upload(i + 1))
  fetchMock.mockImplementation((path: string) => {
    if (path === '/api/records?kind=finding') return response({ items: first, total: 501 })
    if (path === '/api/records?kind=finding&limit=500&offset=500') return response({ items: [finding(500), finding(501)], total: 501 })
    if (path === '/api/evidence') return response({ items: evidence, total: 101 })
    if (path === '/api/evidence?limit=100&offset=100') return response({ items: [upload(100), upload(101)], total: 101 })
    if (path === '/api/users') return response({ items: [] })
    if (path.startsWith('/api/assets')) return response({ items: [], total: 0 })
    return response({})
  })
  render(<Findings session={session} refreshKey={0} onDirty={() => undefined} />)
  await screen.findByRole('button', { name: /Finding 500/ })
  fireEvent.change(screen.getByLabelText('Observation'), { target: { value: 'Unsaved synthetic edit' } })
  fireEvent.click(screen.getByRole('button', { name: 'Load more findings' }))
  await screen.findByRole('button', { name: /Finding 501/ })
  expect(screen.getByLabelText('Observation')).toHaveValue('Unsaved synthetic edit')
  expect(screen.getAllByRole('button', { name: /Finding 500/ })).toHaveLength(1)
  fireEvent.click(screen.getByRole('button', { name: 'Load more supporting evidence' }))
  const picker = screen.getByRole('group', { name: 'Supporting evidence' })
  await within(picker).findByRole('checkbox', { name: 'Source 101' })
  fireEvent.click(within(picker).getByRole('checkbox', { name: 'Source 101' }))
  expect(within(picker).getByRole('checkbox', { name: 'Source 101' })).toBeChecked()
  expect(screen.getByLabelText('Observation')).toHaveValue('Unsaved synthetic edit')
})

it('ignores an old evidence page after refresh and permits the new page to load', async () => {
  let finishOld!: (value: Response) => void
  let firstLoads = 0
  fetchMock.mockImplementation((path: string) => {
    if (path === '/api/evidence') { firstLoads++; return response({ items: Array.from({ length: 100 }, (_, i) => upload(firstLoads === 1 ? i + 1 : i + 201)), total: 101 }) }
    if (path === '/api/evidence?limit=100&offset=100') return firstLoads === 1 ? new Promise<Response>(resolve => { finishOld = resolve }) : response({ items: [upload(301)], total: 101 })
    return response({})
  })
  const view = render(<Evidence session={session} refreshKey={0} />)
  await screen.findByRole('button', { name: 'Source 100' })
  fireEvent.click(screen.getByRole('button', { name: 'Load more evidence' }))
  await waitFor(() => expect(finishOld).toBeTypeOf('function'))
  view.rerender(<Evidence session={session} refreshKey={1} />)
  await screen.findByRole('button', { name: 'Source 300' })
  await act(async () => finishOld(response({ items: [upload(101)], total: 101 })))
  expect(screen.queryByRole('button', { name: 'Source 101' })).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Load more evidence' }))
  await screen.findByRole('button', { name: 'Source 301' })
})
