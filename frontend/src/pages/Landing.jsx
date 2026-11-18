import { Link } from 'react-router-dom'
import { Brain, Globe, Lock, Mail, ShieldCheck, BarChart3 } from 'lucide-react'
import { useAuth } from '../hooks/useAuth'

const features = [
  { icon: Mail, t: 'Email analysis', d: 'NLP + ML on message text, sender spoofing checks, header (SPF/DKIM/DMARC) review and link inspection of pasted text or .eml files.' },
  { icon: Globe, t: 'Website analysis', d: 'URL structure, TLS, DNS, domain age, redirects and static HTML inspection through a hardened, SSRF-protected fetcher.' },
  { icon: Brain, t: 'Explainable risk scoring', d: 'Calibrated probabilities, a 0-100 risk score and plain-language reasons. Unavailable checks are shown as unknown, never as safe.' },
  { icon: BarChart3, t: 'Analytics & history', d: 'Searchable scan history, threat trends and CSV export.' },
  { icon: Lock, t: 'Safe by design', d: 'Never executes scripts, never submits forms, size/time limits, rate limiting, hashed passwords.' },
  { icon: ShieldCheck, t: 'Honest results', d: 'No tool catches everything. We show what was checked and what could not be.' },
]
export default function Landing() {
  const { user } = useAuth()
  return (
    <div className="min-h-screen">
      <header className="max-w-6xl mx-auto flex items-center justify-between px-6 py-5">
        <div className="flex items-center gap-2 text-xl font-bold text-white"><ShieldCheck className="text-cyan-300" />Phish<span className="text-cyan-300">Guard</span></div>
        <div className="flex gap-2">{user ? <Link className="btn-primary" to="/dashboard">Open dashboard</Link> : <><Link className="btn-ghost" to="/login">Log in</Link><Link className="btn-primary" to="/register">Get started</Link></>}</div>
      </header>
      <section className="max-w-4xl mx-auto text-center px-6 pt-16 pb-20 animate-fade-up">
        <span className="inline-block rounded-full border border-cyan-400/30 bg-cyan-400/10 text-cyan-300 text-xs px-3 py-1 mb-5">Machine-learning powered cyber defence</span>
        <h1 className="text-4xl sm:text-6xl font-extrabold text-white leading-tight">Detect phishing emails and websites <span className="bg-gradient-to-r from-blue-400 to-cyan-300 bg-clip-text text-transparent">before they strike</span></h1>
        <p className="mt-5 text-slate-400 text-lg max-w-2xl mx-auto">Paste an email, upload an .eml file or enter a URL. Get a calibrated risk score, the reasons behind it and clear next steps.</p>
        <div className="mt-8 flex justify-center gap-3"><Link className="btn-primary px-6 py-3" to="/register">Start scanning</Link><Link className="btn-ghost px-6 py-3" to="/login">Log in</Link></div>
      </section>
      <section className="max-w-6xl mx-auto grid sm:grid-cols-2 lg:grid-cols-3 gap-4 px-6 pb-24">
        {features.map(({ icon: I, t, d }) => (<div key={t} className="card hover:border-cyan-400/30 transition"><I className="text-cyan-300 mb-3" /><h3 className="text-white font-semibold mb-1">{t}</h3><p className="text-sm text-slate-400">{d}</p></div>))}
      </section>
    </div>
  )
}
