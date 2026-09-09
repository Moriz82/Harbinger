import { useEffect, useState } from 'react'
import { api, Asset } from '../../api'

export function AssetPicker({ selected, onToggle }: { selected: string[]; onToggle: (id: string) => void }) {
  const [items, setItems] = useState<Asset[]>([])
  const [typed, setTyped] = useState(''), [query, setQuery] = useState(''), [page, setPage] = useState(0)
  const [total, setTotal] = useState(0), [loading, setLoading] = useState(true), [error, setError] = useState('')
  const [retry, setRetry] = useState(0)
  useEffect(() => {
    let cancelled = false
    setLoading(true); setError('')
    void api.get<{ items: Asset[]; total: number }>(`/api/assets?offset=${page * 100}&limit=100${query ? `&q=${encodeURIComponent(query)}` : ''}`).then(result => {
      if (!cancelled) { setItems(result.items); setTotal(result.total ?? result.items.length) }
    }).catch(err => { if (!cancelled) setError(err instanceof Error ? err.message : 'Assets could not load.') }).finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [page, query, retry])
  return <fieldset className="asset-picker"><legend>Assets in scope</legend>
    <form className="picker-search" onSubmit={event => { event.preventDefault(); setQuery(typed); setPage(0) }}>
      <input aria-label="Find scope assets" maxLength={200} placeholder="Search all assets" value={typed} onChange={event => setTyped(event.target.value)} />
      <button type="submit">Search assets</button>
    </form>
    <small>{selected.length} selected. Selections are kept across pages and searches.</small>
    {loading ? <p role="status">Loading assets…</p> : error ? <div role="alert">{error}<button onClick={() => setRetry(value => value + 1)}>Retry assets</button></div> : <>
      <div className="picker-options">{items.map(asset => <label key={asset.id}><input type="checkbox" checked={selected.includes(asset.id)} onChange={() => onToggle(asset.id)} />{asset.label}</label>)}</div>
      {!items.length && <p>{query ? 'No assets match this search.' : 'No assets have been imported.'}</p>}
    </>}
    <div className="actions"><button disabled={loading || page === 0} onClick={() => setPage(value => value - 1)}>Previous assets</button><span>{total ? `${page * 100 + 1}–${Math.min(page * 100 + items.length, total)} of ${total}` : '0 assets'}</span><button disabled={loading || (page + 1) * 100 >= total} onClick={() => setPage(value => value + 1)}>Next assets</button></div>
  </fieldset>
}
