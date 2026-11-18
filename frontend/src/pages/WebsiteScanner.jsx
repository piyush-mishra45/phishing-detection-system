import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Loader2, ShieldCheck } from 'lucide-react'
import { errMsg, scanApi } from '../services/api'
import { ErrorBox, PageHeader } from '../components/ui'

export default function WebsiteScanner() {
  const nav = useNavigate(); const [url, setUrl] = useState(''); const [busy, setBusy] = useState(false); const [err, setErr] = useState('')
  const submit = async (e) => {
    e.preventDefault(); setErr('')
    if (!url.trim()) return setErr('Enter a URL to analyse.')
    setBusy(true)
    try { const d = await scanApi.website(url.trim()); nav(`/results/${d.scan_id}`) } catch (x) { setErr(errMsg(x)) } finally { setBusy(false) }
  }
  return (
    <>
      <PageHeader title="Website scanner" subtitle="Analyse a URL for phishing indicators using safe, read-only requests." />
      <form onSubmit={submit} className="card space-y-4 max-w-3xl">
        <div><label className="label" htmlFor="url">Website URL</label><input id="url" className="input font-mono" placeholder="https://example.com/login" value={url} onChange={(e) => setUrl(e.target.value)} maxLength={2048} /></div>
        <ErrorBox>{err}</ErrorBox>
        <button className="btn-primary" disabled={busy}>{busy ? <><Loader2 className="animate-spin" size={16} />Scanning (up to ~30s)...</> : 'Scan website'}</button>
        <div className="flex gap-2 text-xs text-slate-400 border-t border-white/5 pt-3"><ShieldCheck size={16} className="text-cyan-300 shrink-0" />
          <span>The scanner fetches the page with a short timeout and size limit, never runs JavaScript, never submits forms, and refuses local/private network addresses. Checks that can't be completed are reported as <b>unknown</b>, not safe.</span></div>
      </form>
    </>
  )
}
