import { useState } from 'react'
import { Users, ScanLine, ShieldAlert } from 'lucide-react'
import { adminApi, errMsg } from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { ErrorBox, PageHeader, Section, Spinner, StatCard } from '../components/ui'
import { WeeklyChart } from '../charts/Charts'
import { useAuth } from '../hooks/useAuth'

export default function AdminDashboard() {
  const { user: me } = useAuth()
  const users = useAsync(() => adminApi.users(), []); const stats = useAsync(() => adminApi.stats(), [])
  const [err, setErr] = useState('')
  const act = (fn) => async () => { setErr(''); try { await fn(); users.reload() } catch (x) { setErr(errMsg(x)) } }
  if (users.loading || stats.loading) return <Spinner />
  if (users.error || stats.error) return <ErrorBox>{users.error || stats.error}</ErrorBox>
  const t = stats.data.totals
  return (
    <>
      <PageHeader title="Admin dashboard" subtitle="System-wide statistics and user management" />
      <div className="grid sm:grid-cols-3 gap-4 mb-4"><StatCard icon={Users} label="Users" value={stats.data.users} /><StatCard icon={ScanLine} label="Total scans" value={t.total_scans} /><StatCard icon={ShieldAlert} label="Phishing verdicts" value={t.phishing_emails + t.malicious_websites} accent="text-red-300" /></div>
      <Section title="Platform activity (7 days)"><WeeklyChart data={stats.data.weekly} /></Section>
      <div className="mt-4"><ErrorBox>{err}</ErrorBox></div>
      <div className="card mt-2 p-0 overflow-x-auto"><table className="w-full"><thead><tr>{['User', 'Email', 'Role', 'Scans', 'Joined', ''].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
        <tbody>{users.data.map((u) => (<tr key={u.id}><td className="td">{u.username}</td><td className="td">{u.email}</td><td className="td">{u.role}</td><td className="td">{u.scans}</td><td className="td text-xs text-slate-400">{new Date(u.created_at).toLocaleDateString()}</td>
          <td className="td text-right space-x-2">{u.id !== me.id && <>
            <button className="btn-ghost py-1" onClick={act(() => adminApi.setRole(u.id, u.role === 'admin' ? 'user' : 'admin'))}>{u.role === 'admin' ? 'Make user' : 'Make admin'}</button>
            <button className="btn-ghost py-1 text-red-300" onClick={() => confirm(`Delete ${u.username} and all their scans?`) && act(() => adminApi.remove(u.id))()}>Delete</button></>}</td></tr>))}</tbody></table></div>
    </>
  )
}
