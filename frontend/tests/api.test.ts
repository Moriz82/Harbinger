import { describe, expect, it, vi } from 'vitest'
import { ApiClient, ApiError } from '../src/api'

describe('Harbinger API client', () => {
  it('adds JSON and CSRF headers to mutations', async () => {
    const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'content-type': 'application/json' } }))
    const client = new ApiClient(); client.csrf = 'csrf-token'
    await client.post('/api/records', { kind: 'finding' })
    expect(fetcher.mock.calls[0][1]).toMatchObject({ method: 'POST' })
    expect(new Headers(fetcher.mock.calls[0][1]?.headers).get('x-csrf-token')).toBe('csrf-token')
    expect(new Headers(fetcher.mock.calls[0][1]?.headers).get('content-type')).toBe('application/json')
    fetcher.mockRestore()
  })
  it('keeps structured conflict detail on errors', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ detail: { message: 'stale', current: { revision_id: 'r2' } } }), { status: 409, headers: { 'content-type': 'application/json' } }))
    await expect(new ApiClient().put('/api/records/r1', {})).rejects.toMatchObject({ status: 409, detail: { message: 'stale' } } satisfies Partial<ApiError>)
    vi.restoreAllMocks()
  })
})
