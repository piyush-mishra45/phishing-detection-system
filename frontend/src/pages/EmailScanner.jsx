import { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Loader2, Upload } from 'lucide-react'
import { errMsg, scanApi } from '../services/api'
import { ErrorBox, PageHeader } from '../components/ui'

export default function EmailScanner() {
  const nav = useNavigate(); const fileRef = useRef()
  const [f, setF] = useState({ sender_email: '', subject: '', email_content: '' })
  const [file, setFile] = useState(null); const [busy, setBusy] = useState(false); const [err, setErr] = useState('')
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })

  const submit = async (e) => {
    e.preventDefault(); setErr('')
    if (!file && f.email_content.trim().length < 10) return setErr('Paste the email content or upload an .eml file.')
    if (file && !file.name.toLowerCase().endsWith('.eml')) return setErr('Only .eml files are supported.')
    if (file && file.size > 2 * 1024 * 1024) return setErr('File is larger than 2 MB.')
    setBusy(true)
    try {
      let payload = f
      if (file) { payload = new FormData(); payload.append('file', file); if (f.sender_email) payload.append('sender_email', f.sender_email); if (f.subject) payload.append('subject', f.subject) }
      const d = await scanApi.email(payload); nav(`/results/${d.scan_id}`)
    } catch (x) { setErr(errMsg(x)) } finally { setBusy(false) }
  }
  return (
    <>
      <PageHeader title="Email scanner" subtitle="Paste a suspicious email or upload an .eml file. Links are analysed, never visited; attachments are never opened." />
      <form onSubmit={submit} className="card space-y-4 max-w-3xl">
        <div className="grid sm:grid-cols-2 gap-4">
          <div><label className="label" htmlFor="s">Sender (optional with .eml)</label><input id="s" className="input" placeholder="Name <support@example.com>" value={f.sender_email} onChange={set('sender_email')} /></div>
          <div><label className="label" htmlFor="sub">Subject</label><input id="sub" className="input" value={f.subject} onChange={set('subject')} /></div>
        </div>
        <div><label className="label" htmlFor="c">Email content</label><textarea id="c" rows={10} className="input font-mono" placeholder="Paste the email body here..." value={f.email_content} onChange={set('email_content')} disabled={!!file} /></div>
        <div className="flex flex-wrap items-center gap-3">
          <input ref={fileRef} type="file" accept=".eml,message/rfc822" className="hidden" onChange={(e) => setFile(e.target.files[0] || null)} />
          <button type="button" className="btn-ghost" onClick={() => fileRef.current.click()}><Upload size={16} />{file ? file.name : 'Upload .eml file'}</button>
          {file && <button type="button" className="text-xs text-slate-400 underline" onClick={() => { setFile(null); fileRef.current.value = '' }}>remove</button>}
        </div>
        <p className="text-xs text-slate-500">Privacy: only a short excerpt with e-mail addresses and phone numbers redacted is stored, never the full message.</p>
        <ErrorBox>{err}</ErrorBox>
        <button className="btn-primary" disabled={busy}>{busy ? <><Loader2 className="animate-spin" size={16} />Analysing...</> : 'Analyse email'}</button>
      </form>
    </>
  )
}
