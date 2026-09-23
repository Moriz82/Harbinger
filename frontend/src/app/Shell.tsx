import React, { useEffect, useRef, useState } from 'react'
import { ApiError, api, Asset, downloadJson, Graph, RecordItem, Session } from '../api'
import { ErrorMessage, Empty, DirtyDialog, Field } from '../components/common'
import { Modal } from '../components/Modal'
import { Overview } from '../features/Map'
import { Imports } from '../features/Imports'
import { Findings } from '../features/Findings'
import { Evidence } from '../features/Evidence'
import { Transfer } from '../features/Transfer'
const nav = [['overview', 'Map'], ['imports', 'Imports'], ['findings', 'Findings'], ['evidence', 'Evidence'], ['transfer', 'Transfer']] as const
function parseRoute() { const path = location.hash.startsWith('#/') ? location.hash.slice(2).split('?')[0] : 'overview'; return path === 'map' || !path ? 'overview' : path }
type WriteReadiness = 'unconfirmed' | 'checking' | 'ready' | 'blocked' | 'check-failed'
function Shell({ session, onLogout }: { session: Session; onLogout: () => void }) {
  const [route, setRoute] = useState(parseRoute), [refresh, setRefresh] = useState(0), [status, setStatus] = useState('connecting'), [last, setLast] = useState('not yet'), [readiness, setReadiness] = useState<WriteReadiness>('unconfirmed')
  const [reauthPrompt, setReauthPrompt] = useState(false)
  const dirty = useRef(false), save = useRef<() => Promise<boolean>>(async () => true), discard = useRef<() => void>(() => undefined)
  const readinessProbe = useRef(0), authProbe = useRef(0), connected = useRef(false)
  const [pending, setPending] = useState<(() => void) | null>(null), [error, setError] = useState<unknown>(null)
  const acceptedHash = useRef(location.hash || '#/overview')
  const online = status === 'connected'
  const writeReady = readiness === 'ready'
  const canWrite = online && writeReady
  const writeUnavailable = () => { readinessProbe.current++; setReadiness(connected.current ? 'blocked' : 'unconfirmed') }
  const writeAvailable = () => { readinessProbe.current++; setReadiness(connected.current ? 'ready' : 'unconfirmed') }
  async function checkReadiness() {
    if (!connected.current) return
    const probe = ++readinessProbe.current
    setReadiness('checking')
    try {
      const result = await api.get<{ write_ready: boolean }>('/api/readiness')
      if (connected.current && readinessProbe.current === probe) setReadiness(result.write_ready === true ? 'ready' : 'blocked')
    } catch {
      if (connected.current && readinessProbe.current === probe) setReadiness('check-failed')
    }
  }
  useEffect(() => {
    const source = new EventSource('/api/events')
    const update = () => { setRefresh(value => value + 1); setLast(new Date().toLocaleTimeString()) }
    source.addEventListener('open', () => {
      authProbe.current++; connected.current = true; setStatus('connected')
      void checkReadiness()
    })
    source.addEventListener('change', update); source.addEventListener('reset', update); source.onerror = () => {
      connected.current = false; readinessProbe.current++; setStatus('disconnected'); setReadiness('unconfirmed')
      const probe = ++authProbe.current
      void api.get<{ active: boolean }>('/api/session-status').then(current => {
        if (authProbe.current === probe && !connected.current && current.active === false) {
          setStatus('expired')
          source.close()
        }
      }).catch(() => undefined)
    }
    return () => { connected.current = false; readinessProbe.current++; authProbe.current++; source.close() }
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
  async function logout() { if (!canWrite) return; try { await api.post('/api/logout'); writeAvailable(); api.csrf = null; onLogout() } catch (err) { if (err instanceof ApiError && err.status === 503) writeUnavailable(); setError(err) } }
  function reauthenticate() { api.csrf = null; onLogout() }
  const connectionBanner = status === 'expired'
    ? <div className="connection-banner" role="alert">Session expired. Server writes are disabled. Save any unsaved finding with <strong>Save draft file</strong>, then sign in again. <button onClick={() => dirty.current ? setReauthPrompt(true) : reauthenticate()}>Sign in again</button></div>
    : !online ? <div className="connection-banner" role="status">Connection lost or not confirmed. Server writes are disabled. Last server update: {last}.</div> : null
  const reauthDialog = reauthPrompt ? <Modal titleId="reauth-title" onDismiss={() => setReauthPrompt(false)}><h2 id="reauth-title">Unsaved finding changes</h2><p>Save a draft file before signing in again. Signing in again clears the text on this page.</p><div className="actions"><button data-initial-focus onClick={() => setReauthPrompt(false)}>Stay and save draft file</button><button onClick={reauthenticate}>Sign in again and clear local text</button></div></Modal> : null
  const page = route === 'imports' ? <Imports refreshKey={refresh} online={online} writeReady={writeReady} onWriteUnavailable={writeUnavailable} onWriteAvailable={writeAvailable} /> : route === 'findings' ? <Findings session={session} refreshKey={refresh} online={online} writeReady={writeReady} onWriteUnavailable={writeUnavailable} onWriteAvailable={writeAvailable} onDirty={(value, saver, discarder) => { dirty.current = value; save.current = saver; discard.current = discarder }} /> : route === 'evidence' ? <Evidence session={session} refreshKey={refresh} online={online} writeReady={writeReady} onWriteUnavailable={writeUnavailable} onWriteAvailable={writeAvailable} /> : route === 'transfer' ? <Transfer role={session.user?.role ?? ''} online={online} writeReady={writeReady} onWriteUnavailable={writeUnavailable} onWriteAvailable={writeAvailable} /> : route === 'overview' ? <Overview refreshKey={refresh} /> : <section><h1>Page not found</h1><p>This address does not match a workspace page.</p><button onClick={() => go('overview')}>Open map</button></section>
  return <div className="app-shell"><a className="skip-link" href="#content" onClick={event => { event.preventDefault(); document.getElementById('content')?.focus() }}>Skip to content</a><header className="topbar"><button className="brand" onClick={() => go('overview')}><span className="brand-symbol" aria-hidden="true">H</span>Harbinger</button><span className="reminder"><em>report as you go</em></span><span className="sse"><i className={`status-dot ${status}`} />SSE {status} · {writeReady ? 'writes ready' : readiness === 'checking' ? 'checking writes' : readiness === 'unconfirmed' ? 'writes unconfirmed' : 'writes unavailable'} · Last server update: {last}</span><button disabled={!online || readiness === 'checking'} onClick={() => void checkReadiness()}>Retry readiness</button><button disabled={!canWrite} onClick={() => dirty.current ? setPending(() => logout) : void logout()}>Sign out</button></header><div className="layout"><nav className="sidebar" aria-label="Primary navigation"><p className="engagement-name">{session.engagement.name}</p>{nav.map(([key, label]) => <a href={`#/${key}`} aria-current={route === key ? 'page' : undefined} className={route === key ? 'active' : ''} onClick={event => { event.preventDefault(); go(key) }} key={key}>{label}</a>)}<div className="sidebar-foot"><strong>{session.user?.name}</strong><span>{session.user?.role.replace(/_/g, ' ')}</span><small>Private engagement workspace</small></div></nav><main className="content" id="content" tabIndex={-1}>{connectionBanner}{online && !writeReady && <div className="connection-banner" role="status">{readiness === 'checking' ? 'Checking server write readiness. Writes are disabled until the check completes.' : readiness === 'check-failed' ? 'Readiness check failed. Writes remain disabled. Retry readiness to check again.' : readiness === 'blocked' ? 'Writes unavailable: the server reports that writes are blocked. Retry readiness when the writer recovers.' : 'Write readiness is not confirmed. Retry readiness before writing.'}</div>}<ErrorMessage error={error} />{page}</main></div>{pending && <DirtyDialog onStay={() => setPending(null)} onDiscard={() => { const next = pending; dirty.current = false; discard.current(); setPending(null); next?.() }} onSave={() => void save.current().then(ok => { if (ok) { dirty.current = false; const next = pending; setPending(null); next?.() } })} />}{reauthDialog}</div>
}
export { Shell }
