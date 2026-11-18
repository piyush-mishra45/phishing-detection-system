import { Link } from 'react-router-dom'
import { AlertOctagon, CheckCircle2, Globe, Mail, MailWarning, Percent, ShieldAlert, ScanLine } from 'lucide-react'
import { dataApi } from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { ErrorBox, PageHeader, Spinner, StatCard, Section, VerdictBadge } from '../components/ui'
import { DistributionPie, WeeklyChart } from '../charts/Charts'
import { fmtDate } from '../utils'

export default function Dashboard() {
  const { data, loading, error } = useAsync(() => dataApi.stats(), [])
  if (loading) return <Spinner />
  if (error) return <ErrorBox>{error}</ErrorBox>
  const t = data.totals
  return (
    <>
      <PageHeader title="Security dashboard" subtitle="Your scanning activity and detected threats"
        actions={<div className="flex gap-2"><Link to="/scan/email" className="btn-primary"><Mail size={16} />Scan email</Link><Link to="/scan/website" className="btn-ghost"><Globe size={16} />Scan website</Link></div>} />
      <div className="grid sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard icon={Mail} label="Emails scanned" value={t.emails_scanned} />
        <StatCard icon={Globe} label="Websites scanned" value={t.websites_scanned} />
        <StatCard icon={MailWarning} label="Phishing emails" value={t.phishing_emails} accent="text-red-300" />
        <StatCard icon={ShieldAlert} label="Malicious websites" value={t.malicious_websites} accent="text-red-300" />
        <StatCard icon={CheckCircle2} label="Safe results" value={t.safe_results} accent="text-emerald-300" />
        <StatCard icon={AlertOctagon} label="Critical threats" value={t.critical_threats} accent="text-orange-300" hint="risk score above 80" />
        <StatCard icon={Percent} label="Phishing detection rate" value={`${t.phishing_detection_rate}%`} hint="phishing verdicts / all scans" />
        <StatCard icon={ScanLine} label="Total scans" value={t.total_scans} />
      </div>
      <div className="grid lg:grid-cols-3 gap-4 mt-4">
        <div className="lg:col-span-2"><Section title="Last 7 days"><WeeklyChart data={data.weekly} /></Section></div>
        <Section title="Result distribution"><DistributionPie data={data.distribution} /></Section>
      </div>
      <div className="mt-4"><Section title="Recent scans" right={<Link className="text-sm text-cyan-300" to="/history">View all</Link>}>
        {data.recent_scans.length === 0 ? <p className="text-sm text-slate-400">No scans yet. Run your first scan above.</p> :
          <div className="overflow-x-auto"><table className="w-full"><tbody>{data.recent_scans.map((s) => (
            <tr key={s.id}><td className="td"><span className="text-xs uppercase text-slate-400">{s.scan_type}</span></td>
              <td className="td"><Link className="hover:text-cyan-300 break-all" to={`/results/${s.id}`}>{s.title || s.subtitle || '(untitled)'}</Link></td>
              <td className="td"><VerdictBadge verdict={s.prediction} /></td><td className="td text-slate-400">{s.risk_score}</td><td className="td text-slate-500 text-xs">{fmtDate(s.created_at)}</td></tr>))}</tbody></table></div>}
      </Section></div>
    </>
  )
}
