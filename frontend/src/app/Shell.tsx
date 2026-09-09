import React, { useEffect, useRef, useState } from 'react'
import { ApiError, api, Asset, downloadJson, Graph, RecordItem, Session } from '../api'
import { ErrorMessage, Empty, DirtyDialog, Field } from '../components/common'
import { Overview } from '../features/Map'
import { Imports } from '../features/Imports'
import { Findings } from '../features/Findings'
import { Evidence } from '../features/Evidence'
import { Transfer } from '../features/Transfer'
const nav = [['overview', 'Map'], ['imports', 'Imports'], ['findings', 'Findings'], ['evidence', 'Evidence'], ['transfer', 'Transfer']] as const
function parseRoute() { const path = location.hash.startsWith('#/') ? location.hash.slice(2).split('?')[0] : 'overview'; return path === 'map' || !path ? 'overview' : path }
function Shell({ session, onLogout }: { session: Session; onLogout: () => void }) {
  const [route, setRoute] = useState(parseRoute), [refresh, setRefresh] = useState(0), [status, setStatus] = useState('connecting'), [last, setLast] = useState('not yet')
  const dirty = useRef(false), save = useRef<() => Promise<boolean>>(async () => true), discard = useRef<() => void>(() => undefined)
  const [pending, setPending] = useState<(() => void) | null>(null), [error, setError] = useState<unknown>(null)
  const acceptedHash = useRef(location.hash || '#/overview')
  const online = status === 'connected'
  useEffect(() => {
    const source = new EventSource('/api/events')
    const update = () => { setRefresh(value => value + 1); setLast(new Date().toLocaleTimeString()) }
    source.addEventListener('open', () => { setStatus('connected'); setLast(new Date().toLocaleTimeString()) })
    source.addEventListener('change', update); source.addEventListener('reset', update); source.onerror = () => setStatus('disconnected')
    return () => source.close()
  }, [])
  useEffect(() => {
    const changed = () => {
      if (!location.hash.startsWith('#/') || location.hash === acceptedHash.current) return
      const target = location.hash, next = parseRoute()
      if (dirty.current) { history.replaceState(null, '', acceptedHash.current); setPending(() => () => { history.pushState(null, '', target); acceptedHash.current = target; setRoute(next) }) }
      else { acceptedHash.current = target; setRoute(next) }
    }
    addEventListener('hashchange', changed); addEventListener('popstate', changed)
    return () => { removeEventListener('hashchange', changed); removeEventListener('popstate', changed) }
  }, [])
  function go(next: string) {
    const action = () => { const hash = `#/${next}`; if (hash !== location.hash) history.pushState(null, '', hash); acceptedHash.current = hash; setRoute(next) }
    dirty.current ? setPending(() => action) : action()
  }
  async function logout() { if (!online) return; try { await api.post('/api/logout'); api.csrf = null; onLogout() } catch (err) { setError(err) } }
  const page = route === 'imports' ? <Imports refreshKey={refresh} online={online} /> : route === 'findings' ? <Findings session={session} refreshKey={refresh} online={online} onDirty={(value, saver, discarder) => { dirty.current = value; save.current = saver; discard.current = discarder }} /> : route === 'evidence' ? <Evidence session={session} refreshKey={refresh} online={online} /> : route === 'transfer' ? <Transfer role={session.user?.role ?? ''} online={online} /> : route === 'overview' ? <Overview refreshKey={refresh} /> : <section><h1>Page not found</h1><p>This address does not match a workspace page.</p><button onClick={() => go('overview')}>Open map</button></section>
  return <div className="app-shell"><a className="skip-link" href="#content" onClick={event => { event.preventDefault(); document.getElementById('content')?.focus() }}>Skip to content</a><header className="topbar"><button className="brand" onClick={() => go('overview')}><span className="brand-symbol" aria-hidden="true">H</span>Harbinger</button><span className="reminder"><em>report as you go</em></span><span className="sse"><i className={`status-dot ${status}`} />SSE {status} · last successful sync {last}</span><button disabled={!online} onClick={() => dirty.current ? setPending(() => logout) : void logout()}>Sign out</button></header><div className="layout"><nav className="sidebar" aria-label="Primary navigation"><p className="engagement-name">{session.engagement.name}</p>{nav.map(([key, label]) => <a href={`#/${key}`} aria-current={route === key ? 'page' : undefined} className={route === key ? 'active' : ''} onClick={event => { event.preventDefault(); go(key) }} key={key}>{label}</a>)}<div className="sidebar-foot"><strong>{session.user?.name}</strong><span>{session.user?.role.replace(/_/g, ' ')}</span><small>Private engagement workspace</small></div></nav><main className="content" id="content" tabIndex={-1}>{!online && <div className="connection-banner" role="status">Connection lost or not confirmed. Server writes are disabled. Last successful sync: {last}.</div>}<ErrorMessage error={error} />{page}</main></div>{pending && <DirtyDialog onStay={() => setPending(null)} onDiscard={() => { const next = pending; dirty.current = false; discard.current(); setPending(null); next?.() }} onSave={() => void save.current().then(ok => { if (ok) { dirty.current = false; const next = pending; setPending(null); next?.() } })} />}</div>
}
export { Shell }
