import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, Trash2 } from 'lucide-react'
import { dataApi } from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { ErrorBox, PageHeader, Spinner } from '../components/ui'
import { EmailReport, WebsiteReport } from '../components/Reports'
import { fmtDate } from '../utils'

export default function ScanResults() {
  const { id } = useParams(); const nav = useNavigate()
  const { data, loading, error } = useAsync(() => dataApi.detail(id), [id])
  if (loading) return <Spinner label="Loading report..." />
  if (error) return <ErrorBox>{error}</ErrorBox>
  const del = async () => { if (confirm('Delete this scan permanently?')) { await dataApi.remove(id); nav('/history') } }
  return (
    <>
      <PageHeader title={`${data.scan_type === 'email' ? 'Email' : 'Website'} scan report`} subtitle={`Scan #${data.id} - ${fmtDate(data.created_at)}`}
        actions={<div className="flex gap-2"><Link to="/history" className="btn-ghost"><ArrowLeft size={16} />History</Link><button onClick={del} className="btn-ghost text-red-300"><Trash2 size={16} />Delete</button></div>} />
      {data.scan_type === 'email' ? <EmailReport r={data.report} meta={data} /> : <WebsiteReport r={data.report} />}
    </>
  )
}
