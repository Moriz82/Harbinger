import React from 'react'
import { Modal } from './Modal'
function ErrorMessage({ error }: { error: unknown }) { return error ? <div className="error" role="alert"><strong>Could not complete that request.</strong><span>{error instanceof Error ? error.message : 'The service returned an unreadable error.'}</span></div> : null }
function Empty({ title, body }: { title: string; body: string }) { return <div className="empty"><strong>{title}</strong><span>{body}</span></div> }
function DirtyDialog({ onSave, onDiscard, onStay }: { onSave: () => void; onDiscard: () => void; onStay: () => void }) { return <Modal titleId="dirty-title" onDismiss={onStay}><h2 id="dirty-title">Unsaved finding changes</h2><p>Save before leaving, stay here, or discard the local changes.</p><div className="actions"><button className="primary" onClick={onSave}>Save and leave</button><button data-initial-focus onClick={onStay}>Stay</button><button onClick={onDiscard}>Discard changes</button></div></Modal> }

function Field({ label, value, update, area = false, maxLength }: { label: string; value: string; update: (value: string) => void; area?: boolean; maxLength?: number }) { return <label>{label}{area ? <textarea aria-label={label} rows={4} maxLength={maxLength} value={value} onChange={e => update(e.target.value)} /> : <input aria-label={label} maxLength={maxLength} value={value} onChange={e => update(e.target.value)} />}{maxLength && <small>{value.length}/{maxLength}</small>}</label> }
export { ErrorMessage, Empty, DirtyDialog, Field }
