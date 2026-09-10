import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { Imports } from '../src/main'

const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
const trust = {
  trusted: true,
  source_id: 'source-1',
  key_id: 'fixture-key-1',
  profile: 'cptc11_smb2_security_mode_v1',
  outcome: 'observed',
  envelope_id: 'envelope-1',
  observation_id: 'observation-1',
  signed_sha256: 'a'.repeat(64),
  observation_sha256: 'b'.repeat(64),
  evidence_count: 1,
  evidence_sha256: ['c'.repeat(64)],
}
const upload = { id: 'upload-1', kind: 'upload', revision_id: 'u1', updated_at: '', data: { filename: 'reviewed.json', format: 'harness_observation_v1', status: 'uploaded', harness_trust: trust } }
let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  fetchMock = vi.fn((path: string, init?: RequestInit) => {
    if (path === '/api/uploads') return response({ items: [upload], total: 1 })
    if (path.endsWith('/parse')) return response({ ...upload, revision_id: 'u2', data: { ...upload.data, status: 'preview' } })
    if (path.endsWith('/preview')) return response({
      complete: true, quarantined: false, limitations: [], assets: [], relationships: [], observations: [], harness_trust: trust,
      _review: { upload_revision_id: 'u2', preview_revision_id: 'p1', preview_hash: 'd'.repeat(64) },
    })
    if (path.endsWith('/merge') && init?.method === 'POST') return response({ ...upload, revision_id: 'u3', data: { ...upload.data, status: 'merged' } })
    return response({})
  })
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

it('shows bounded trust metadata and requires server acknowledgement for a complete harness preview', async () => {
  render(<Imports />)
  fireEvent.click(await screen.findByRole('button', { name: /reviewed.json/ }))
  fireEvent.click(screen.getByRole('button', { name: 'Parse preview' }))

  expect(await screen.findByText('Verified reviewed broker')).toBeInTheDocument()
  expect(screen.getByText('source-1')).toBeInTheDocument()
  expect(screen.getByText('fixture-key-1')).toBeInTheDocument()
  expect(screen.getByText('cptc11_smb2_security_mode_v1')).toBeInTheDocument()
  expect(screen.getByText('observed')).toBeInTheDocument()
  expect(screen.getByText('c'.repeat(64))).toBeInTheDocument()
  const merge = screen.getByRole('button', { name: 'Merge records' })
  expect(merge).toBeDisabled()
  fireEvent.click(screen.getByLabelText(/reviewed this signed harness preview/i))
  expect(merge).toBeEnabled()
  fireEvent.click(merge)

  await waitFor(() => expect(fetchMock.mock.calls.some(call => String(call[0]).endsWith('/merge'))).toBe(true))
  const call = fetchMock.mock.calls.find(call => String(call[0]).endsWith('/merge'))
  expect(JSON.parse(String(call?.[1]?.body))).toEqual({ upload_revision_id: 'u2', preview_revision_id: 'p1', preview_hash: 'd'.repeat(64), acknowledged: true })
})
