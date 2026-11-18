import { Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

const axis = { stroke: '#64748b', fontSize: 12 }
const tip = { contentStyle: { background: '#0f1b3d', border: '1px solid rgba(255,255,255,.1)', borderRadius: 8, color: '#e2e8f0' } }

export const WeeklyChart = ({ data }) => (
  <ResponsiveContainer width="100%" height={260}>
    <BarChart data={data}>
      <CartesianGrid stroke="rgba(255,255,255,.06)" vertical={false} />
      <XAxis dataKey="date" {...axis} /><YAxis allowDecimals={false} {...axis} /><Tooltip {...tip} /><Legend />
      <Bar dataKey="emails" name="Emails" fill="#3b82f6" radius={[4, 4, 0, 0]} />
      <Bar dataKey="websites" name="Websites" fill="#22d3ee" radius={[4, 4, 0, 0]} />
      <Bar dataKey="threats" name="Threats" fill="#f87171" radius={[4, 4, 0, 0]} />
    </BarChart>
  </ResponsiveContainer>
)

export const MonthlyChart = ({ data }) => (
  <ResponsiveContainer width="100%" height={260}>
    <LineChart data={data}>
      <CartesianGrid stroke="rgba(255,255,255,.06)" vertical={false} />
      <XAxis dataKey="month" {...axis} /><YAxis allowDecimals={false} {...axis} /><Tooltip {...tip} /><Legend />
      <Line type="monotone" dataKey="phishing" name="Phishing" stroke="#f87171" strokeWidth={2} dot={{ r: 3 }} />
      <Line type="monotone" dataKey="suspicious" name="Suspicious" stroke="#fbbf24" strokeWidth={2} dot={{ r: 3 }} />
      <Line type="monotone" dataKey="safe" name="Safe" stroke="#34d399" strokeWidth={2} dot={{ r: 3 }} />
    </LineChart>
  </ResponsiveContainer>
)

const COLORS = { Phishing: '#f87171', Suspicious: '#fbbf24', Safe: '#34d399', Unknown: '#94a3b8' }
export const DistributionPie = ({ data }) => {
  const d = data.filter((x) => x.value > 0)
  if (!d.length) return <div className="h-[260px] flex items-center justify-center text-slate-500 text-sm">No scans yet</div>
  return (
    <ResponsiveContainer width="100%" height={260}>
      <PieChart>
        <Pie data={d} dataKey="value" nameKey="name" innerRadius={55} outerRadius={90} paddingAngle={3}>{d.map((x) => <Cell key={x.name} fill={COLORS[x.name]} />)}</Pie>
        <Tooltip {...tip} /><Legend />
      </PieChart>
    </ResponsiveContainer>
  )
}

export const MetricsBar = ({ data }) => (
  <ResponsiveContainer width="100%" height={300}>
    <BarChart data={data}>
      <CartesianGrid stroke="rgba(255,255,255,.06)" vertical={false} />
      <XAxis dataKey="name" {...axis} interval={0} angle={-12} height={60} /><YAxis domain={[0, 1]} {...axis} /><Tooltip {...tip} /><Legend />
      <Bar dataKey="accuracy" fill="#3b82f6" /><Bar dataKey="precision" fill="#22d3ee" /><Bar dataKey="recall" fill="#a78bfa" /><Bar dataKey="f1" name="F1" fill="#34d399" />
    </BarChart>
  </ResponsiveContainer>
)
