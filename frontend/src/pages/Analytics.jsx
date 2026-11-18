import { dataApi } from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { ErrorBox, PageHeader, Section, Spinner, StatCard } from '../components/ui'
import { DistributionPie, MonthlyChart, WeeklyChart } from '../charts/Charts'
import { Percent, ShieldAlert, AlertOctagon } from 'lucide-react'

export default function Analytics() {
  const { data, loading, error } = useAsync(() => dataApi.stats(), [])
  if (loading) return <Spinner />
  if (error) return <ErrorBox>{error}</ErrorBox>
  const t = data.totals
  return (
    <>
      <PageHeader title="Threat analytics" subtitle="Trends across your scans" />
      <div className="grid sm:grid-cols-3 gap-4 mb-4">
        <StatCard icon={Percent} label="Phishing detection rate" value={`${t.phishing_detection_rate}%`} />
        <StatCard icon={ShieldAlert} label="Suspicious" value={t.suspicious} accent="text-amber-300" />
        <StatCard icon={AlertOctagon} label="Critical threats" value={t.critical_threats} accent="text-orange-300" />
      </div>
      <div className="grid lg:grid-cols-2 gap-4">
        <Section title="Weekly scan statistics"><WeeklyChart data={data.weekly} /></Section>
        <Section title="Monthly threat statistics">{data.monthly.length ? <MonthlyChart data={data.monthly} /> : <p className="text-sm text-slate-400 p-6">Not enough data yet.</p>}</Section>
        <Section title="Result distribution"><DistributionPie data={data.distribution} /></Section>
      </div>
    </>
  )
}
