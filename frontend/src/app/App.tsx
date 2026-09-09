import React, { useEffect, useRef, useState } from 'react'
import { ApiError, api, Asset, downloadJson, Graph, RecordItem, Session } from '../api'
import { ErrorMessage, Empty, DirtyDialog, Field } from '../components/common'
import { Shell } from './Shell'
function Login({ onLogin }: { onLogin: (value: Session) => void }) { const [name, setName] = useState(''); const [password, setPassword] = useState(''); const [error, setError] = useState<unknown>(null); async function submit(e: React.FormEvent) { e.preventDefault(); try { const value = await api.post<Session>('/api/login', { name, password }); api.csrf = value.csrf; onLogin(value) } catch (err) { setError(err) } } return <main className="login"><div className="login-card"><h1>Keep the evidence moving.</h1><form onSubmit={submit}><label>Account name<input required value={name} onChange={e => setName(e.target.value)} /></label><label>Password<input required type="password" value={password} onChange={e => setPassword(e.target.value)} /></label><ErrorMessage error={error} /><button className="primary">Sign in</button></form></div></main> }
function App() {
  const [session, setSession] = useState<Session | null>(null)
  const [loading, setLoading] = useState(true), [error, setError] = useState<unknown>(null), [retry, setRetry] = useState(0)
  useEffect(() => {
    let cancelled = false; setLoading(true); setError(null)
    void api.get<Session>('/api/session').then(value => { if (!cancelled) { api.csrf = value.csrf; setSession(value) } }).catch(err => {
      if (!cancelled) { if (err instanceof ApiError && err.status === 401) setSession(null); else setError(err) }
    }).finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [retry])
  if (loading) return <div className="loading" role="status">Checking session…</div>
  if (error) return <main className="login"><div className="login-card"><h1>Workspace unavailable</h1><ErrorMessage error={error} /><button onClick={() => setRetry(value => value + 1)}>Retry session</button></div></main>
  return session?.user ? <Shell session={session} onLogout={() => setSession(null)} /> : <Login onLogin={setSession} />
}
export { App, Login }
