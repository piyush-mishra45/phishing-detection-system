import { Loader2, AlertTriangle, CheckCircle2, HelpCircle, ShieldAlert } from 'lucide-react'
import { levelHex, styleFor } from '../utils'

export const Spinner = ({ label = 'Loading...' }) => (
  <div className="flex items-center gap-2 text-slate-400 text-sm p-6"><Loader2 className="animate-spin" size={18} />{label}</div>
)
export const ErrorBox = ({ children }) =>
  children ? <div role="alert" className="rounded-lg border border-red-400/30 bg-red-500/10 text-red-200 text-sm px-3 py-2">{children}</div> : null

export const PageHeader = ({ title, subtitle, actions }) => (
  <div className="flex flex-wrap items-end justify-between gap-3 mb-6">
    <div><h1 className="text-2xl font-bold text-white">{title}</h1>{subtitle && <p className="text-slate-400 text-sm mt-1">{subtitle}</p>}</div>
    {actions}
  </div>
)

export function StatCard({ icon: Icon, label, value, accent = 'text-cyan-300', hint }) {
  return (
    <div className="card hover:-translate-y-0.5 hover:border-cyan-400/30 transition">
      <div className="flex items-center justify-between"><span className="text-xs uppercase tracking-wide text-slate-400">{label}</span>{Icon && <Icon size={18} className={accent} />}</div>
      <div className="text-3xl font-bold text-white mt-2">{value}</div>
      {hint && <div className="text-xs text-slate-500 mt-1">{hint}</div>}
    </div>
  )
}

const icons = { SAFE: CheckCircle2, LEGITIMATE: CheckCircle2, SUSPICIOUS: AlertTriangle, PHISHING: ShieldAlert, UNKNOWN: HelpCircle }
export function VerdictBadge({ verdict, big = false }) {
  const s = styleFor(verdict); const Icon = icons[verdict] || HelpCircle
  return (
    <span data-testid="verdict" className={`inline-flex items-center gap-1.5 rounded-full ring-1 ${s.bg} ${s.ring} ${s.text} font-semibold ${big ? 'px-4 py-2 text-lg' : 'px-2.5 py-1 text-xs'}`}>
      <Icon size={big ? 20 : 14} />{s.label}
    </span>
  )
}

export function ScoreGauge({ score = 0, size = 150 }) {
  const r = 52, c = 2 * Math.PI * r, color = levelHex(score)
  return (
    <div className="relative" style={{ width: size, height: size }} role="img" aria-label={`Risk score ${score} out of 100`}>
      <svg viewBox="0 0 120 120" width={size} height={size} className="-rotate-90">
        <circle cx="60" cy="60" r={r} fill="none" stroke="rgba(255,255,255,.08)" strokeWidth="10" />
        <circle cx="60" cy="60" r={r} fill="none" stroke={color} strokeWidth="10" strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c * (1 - score / 100)} style={{ transition: 'stroke-dashoffset .8s ease' }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center"><span className="text-3xl font-bold text-white">{score}</span><span className="text-[10px] uppercase tracking-wider text-slate-400">risk / 100</span></div>
    </div>
  )
}

export const Pill = ({ children, tone = 'slate' }) => {
  const t = { slate: 'bg-white/5 text-slate-300', red: 'bg-red-500/15 text-red-300', amber: 'bg-amber-500/15 text-amber-300', green: 'bg-emerald-500/15 text-emerald-300', cyan: 'bg-cyan-500/15 text-cyan-300' }[tone]
  return <span className={`inline-block rounded-md px-2 py-0.5 text-xs ${t}`}>{children}</span>
}

export const KV = ({ k, v, mono }) => (
  <div className="flex justify-between gap-4 py-1.5 border-b border-white/5 text-sm"><span className="text-slate-400 shrink-0">{k}</span><span className={`text-right break-all ${mono ? 'font-mono text-xs' : ''}`}>{v === null || v === undefined || v === '' ? <Pill>unknown</Pill> : String(v)}</span></div>
)

export const Section = ({ title, icon: Icon, children, right }) => (
  <div className="card">
    <div className="flex items-center justify-between mb-3"><h3 className="font-semibold text-white flex items-center gap-2">{Icon && <Icon size={18} className="text-cyan-300" />}{title}</h3>{right}</div>
    {children}
  </div>
)

/** Renders signals: risky ones in red with their reason; OK in green. Unknown checks listed separately by the caller. */
export function SignalList({ signals = [] }) {
  return (
    <ul className="space-y-1.5">
      {signals.map((s) => (
        <li key={s.id} className="flex items-start justify-between gap-3 text-sm">
          <span className="flex items-start gap-2">
            <span className={`mt-1.5 h-2 w-2 rounded-full shrink-0 ${s.status === 'risk' ? 'bg-red-400' : s.status === 'unknown' ? 'bg-slate-500' : 'bg-emerald-400'}`} />
            <span><span className="text-slate-200">{s.label}</span>{s.status === 'risk' && s.reason && <span className="block text-xs text-red-300/90">{s.reason}</span>}</span>
          </span>
          <span className="text-xs text-slate-400 font-mono text-right max-w-[40%] break-all">{typeof s.value === 'object' ? JSON.stringify(s.value) : String(s.value)}</span>
        </li>
      ))}
    </ul>
  )
}
