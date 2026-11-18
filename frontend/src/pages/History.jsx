import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Download, Search } from 'lucide-react'
import { dataApi, errMsg } from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { ErrorBox, PageHeader, Spinner, VerdictBadge } from '../components/ui'
import { fmtDate, levelFor } from '../utils'

export default function History() {
  const [f, setF] = useState({ q: '', type: '', category: '', date_from: '', date_to: '' })
  const [applied, setApplied] = useState(f); const [page, setPage] = useState(1); const [exportErr, setExportErr] = useState('')
  const params = Object.fromEntries(Object.entries({ ...applied, page, per_page: 15 }).filter(([, v]) => v !== ''))
  const { data, loading, error } = useAsync(() => dataApi.history(params), [JSON.stringify(params)])
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  const apply = (e) => { e.preventDefault(); setPage(1); setApplied(f) }
  const exp = async () => { setExportErr(''); try { const { page: _p, per_page: _n, ...p } = params; await dataApi.exportCsv(p) } catch (x) { setExportErr(errMsg(x)) } }
  const pages = data ? Math.max(1, Math.ceil(data.total / data.per_page)) : 1
  return (
    <>
      <PageHeader title="Scan history" subtitle="Every scan is stored so you can review and export it" actions={<button className="btn-ghost" onClick={exp}><Download size={16} />Export CSV</button>} />
      <form onSubmit={apply} className="card grid md:grid-cols-6 gap-3 items-end mb-4">
        <div className="md:col-span-2"><label className="label">Search</label><input className="input" placeholder="URL, subject, sender, domain" value={f.q} onChange={set('q')} /></div>
        <div><label className="label">Type</label><select className="input" value={f.type} onChange={set('type')}><option value="">All</option><option value="email">Email</option><option value="website">Website</option></select></div>
        <div><label className="label">Threat level</label><select className="input" value={f.category} onChange={set('category')}><option value="">All</option><option value="low">Low (0-30)</option><option value="medium">Medium (31-60)</option><option value="high">High (61-80)</option><option value="critical">Critical (81-100)</option></select></div>
        <div><label className="label">From</label><input type="date" className="input" value={f.date_from} onChange={set('date_from')} /></div>
        <div><label className="label">To</label><input type="date" className="input" value={f.date_to} onChange={set('date_to')} /></div>
        <button className="btn-primary md:col-span-6 md:w-40"><Search size={16} />Apply</button>
      </form>
      <ErrorBox>{exportErr}</ErrorBox>
      <div className="card p-0 overflow-x-auto">
        {loading ? <Spinner /> : error ? <div className="p-4"><ErrorBox>{error}</ErrorBox></div> : data.items.length === 0 ? <p className="p-6 text-sm text-slate-400">No scans match.</p> :
          <table className="w-full"><thead><tr><th className="th">Type</th><th className="th">Target</th><th className="th">Verdict</th><th className="th">Risk</th><th className="th">Date</th></tr></thead>
            <tbody>{data.items.map((s) => (<tr key={s.id} className="hover:bg-white/[.03]">
              <td className="td uppercase text-xs text-slate-400">{s.scan_type}</td>
              <td className="td max-w-md"><Link className="hover:text-cyan-300 break-all" to={`/results/${s.id}`}>{s.title || '(no subject)'}</Link><div className="text-xs text-slate-500 break-all">{s.subtitle}</div></td>
              <td className="td"><VerdictBadge verdict={s.prediction} /></td><td className="td">{s.risk_score} <span className="text-xs text-slate-500">{levelFor(s.risk_score)}</span></td>
              <td className="td text-xs text-slate-400">{fmtDate(s.created_at)}</td></tr>))}</tbody></table>}
      </div>
      {data && data.total > data.per_page && <div className="flex items-center justify-center gap-3 mt-4 text-sm"><button className="btn-ghost" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button><span className="text-slate-400">Page {page} of {pages}</span><button className="btn-ghost" disabled={page >= pages} onClick={() => setPage(page + 1)}>Next</button></div>}
    </>
  )
}
