import { AlertTriangle, FileCode2, Globe2, Link2, Lock, Network, Route, ShieldCheck, Tags, Brain, Info } from 'lucide-react'
import { KV, Pill, ScoreGauge, Section, SignalList, VerdictBadge } from './ui'
import { pct, styleFor } from '../utils'

function Summary({ r, title, sub }) {
  const s = styleFor(r.prediction)
  return (
    <div className={`card ring-1 ${s.ring} ${s.bg}`}>
      <div className="flex flex-wrap items-center gap-6">
        <ScoreGauge score={r.risk_score} />
        <div className="flex-1 min-w-[220px] space-y-2">
          <VerdictBadge verdict={r.prediction} big />
          <div className="text-white font-semibold break-all">{title}</div>
          {sub && <div className="text-xs text-slate-400 break-all">{sub}</div>}
          <div className="flex flex-wrap gap-2 text-xs"><Pill tone="cyan">{r.risk_level}</Pill>{r.threat_category && <Pill>{r.threat_category}</Pill>}</div>
          {r.verdict_note && <p className="text-xs text-slate-300 flex gap-1.5"><Info size={14} className="shrink-0 mt-0.5" />{r.verdict_note}</p>}
        </div>
      </div>
    </div>
  )
}

const Model = ({ r }) => (
  <Section title="ML prediction & confidence" icon={Brain}>
    <KV k="Phishing probability (calibrated)" v={pct(r.ml_probability)} />
    <KV k="Legitimate probability" v={r.ml_probability == null ? null : pct(1 - r.ml_probability)} />
    <KV k="Model confidence" v={pct(r.model_confidence)} />
    <KV k="Heuristic score" v={`${r.heuristic_score}/100`} />
    <KV k="Overall risk score" v={`${r.risk_score}/100`} />
    <p className="text-xs text-slate-500 mt-2">Confidence says how decisive the model is. The risk score blends the model with rule-based evidence, so they can differ.</p>
  </Section>
)

const Why = ({ r }) => (
  <div className="grid lg:grid-cols-2 gap-4">
    <Section title="Reasons for flagging" icon={AlertTriangle}>
      {r.reasons?.length ? <ul className="list-disc pl-5 space-y-1 text-sm text-slate-200">{r.reasons.map((x, i) => <li key={i}>{x}</li>)}</ul> : <p className="text-sm text-slate-400">No strong risk indicators were found among the checks that could be run.</p>}
      {r.unknown_checks?.length > 0 && <div className="mt-4"><div className="label">Checks that could not be performed (not counted as safe)</div><div className="flex flex-wrap gap-1.5">{r.unknown_checks.map((u) => <Pill key={u}>{u}</Pill>)}</div></div>}
    </Section>
    <Section title="Recommended security actions" icon={ShieldCheck}>
      <ul className="list-disc pl-5 space-y-1 text-sm text-slate-200">{r.recommended_actions?.map((x, i) => <li key={i}>{x}</li>)}</ul>
    </Section>
  </div>
)

export function EmailReport({ r, meta }) {
  const kws = Object.entries(r.suspicious_keywords || {})
  return (
    <div className="space-y-4">
      <Summary r={r} title={meta?.subject || '(no subject)'} sub={meta?.sender_email} />
      <div className="grid lg:grid-cols-2 gap-4"><Model r={r} />
        <Section title="Suspicious keywords" icon={Tags}>
          {kws.length ? kws.map(([g, w]) => <div key={g} className="mb-2"><div className="label">{g.replace('_', ' ')}</div><div className="flex flex-wrap gap-1.5">{w.map((x) => <Pill key={x} tone="red">{x}</Pill>)}</div></div>) : <p className="text-sm text-slate-400">None found.</p>}
        </Section>
      </div>
      <Section title="Detected malicious links" icon={Link2} right={<Pill>{r.links?.length || 0} links analysed (never visited)</Pill>}>
        {r.links?.length ? <div className="space-y-2">{r.links.map((l, i) => (
          <div key={i} className={`rounded-lg p-3 text-sm border ${l.malicious ? 'border-red-400/30 bg-red-500/10' : 'border-white/5 bg-white/[.02]'}`}>
            <div className="font-mono text-xs break-all">{l.url}</div>
            {l.text && <div className="text-xs text-slate-400 mt-1">Link text: {l.text}</div>}
            <div className="flex gap-2 mt-1.5 text-xs"><Pill tone={l.malicious ? 'red' : 'green'}>{l.malicious ? 'suspicious' : 'no strong signs'}</Pill>{l.ml_probability != null && <Pill>ML {pct(l.ml_probability)}</Pill>}</div>
            {l.reasons?.map((x, j) => <div key={j} className="text-xs text-red-300 mt-1">{x}</div>)}
          </div>))}</div> : <p className="text-sm text-slate-400">No links found.</p>}
      </Section>
      <Section title="Sender, header & content checks" icon={Network}><SignalList signals={r.signals} /></Section>
      {r.attachments?.length > 0 && <Section title="Attachments (listed only, never opened)" icon={FileCode2}>{r.attachments.map((a, i) => <KV key={i} k={a.filename} v={a.type} />)}</Section>}
      <Why r={r} />
      <p className="text-xs text-slate-500">{r.disclaimer}</p>
    </div>
  )
}

export function WebsiteReport({ r }) {
  const ssl = r.ssl || {}, dns = r.dns || {}, age = r.domain_age || {}, h = r.html, red = r.redirects || {}
  return (
    <div className="space-y-4">
      <Summary r={r} title={r.url} sub={`Domain: ${r.domain}`} />
      <div className="grid lg:grid-cols-2 gap-4">
        <Model r={r} />
        <Section title="SSL / TLS information" icon={Lock}>
          <KV k="Status" v={ssl.status} />
          {ssl.status === 'valid' ? <><KV k="Issuer" v={ssl.issuer} /><KV k="Subject" v={ssl.subject} /><KV k="Valid" v={`${ssl.valid_from} to ${ssl.valid_to}`} /><KV k="Days remaining" v={ssl.days_remaining} /><KV k="Protocol" v={ssl.protocol} /></> : ssl.error && <p className="text-xs text-amber-300 mt-1">{ssl.error}</p>}
          <p className="text-xs text-slate-500 mt-2">A valid certificate only proves encryption and domain control. Phishing sites routinely use HTTPS.</p>
        </Section>
        <Section title="DNS & domain registration" icon={Network}>
          <KV k="A records" v={dns.a?.join(', ')} /><KV k="AAAA records" v={dns.aaaa?.join(', ')} /><KV k="MX records" v={dns.mx?.join(', ')} /><KV k="Name servers" v={dns.ns?.join(', ')} />
          <KV k="Registered" v={age.registered} /><KV k="Domain age" v={age.age_days != null ? `${age.age_days} days` : null} /><KV k="Registrar" v={age.registrar} />
        </Section>
        <Section title="Redirect analysis" icon={Route}>
          <KV k="Reachable" v={r.fetch?.reachable ? `yes (HTTP ${r.fetch.status_code})` : `no - ${r.fetch?.error || 'unknown'}`} />
          <KV k="Redirect hops" v={red.count} /><KV k="Final URL" v={red.final_url} mono />
          <KV k="Cross-domain targets" v={red.cross_domain?.length ? red.cross_domain.join(', ') : 'none'} />
        </Section>
      </div>
      <Section title="Suspicious URL & domain features" icon={Globe2}><SignalList signals={(r.signals || []).filter((s) => !['cred_form', 'form_external', 'form_http', 'hidden_iframe', 'js', 'ext_links', 'meta_refresh', 'title_brand', 'fav'].includes(s.id))} /></Section>
      <Section title="HTML analysis" icon={FileCode2}>
        {h ? <div className="grid md:grid-cols-2 gap-x-8">
          <div><KV k="Title" v={h.title} /><KV k="Meta description" v={h.meta_description} /><KV k="Password forms" v={h.credential_forms} /><KV k="Hidden iframes" v={h.hidden_iframes} /></div>
          <div><KV k="Suspicious JS patterns" v={h.suspicious_js?.join(', ') || 'none'} /><KV k="External link ratio" v={h.external_link_ratio} /><KV k="Empty links" v={h.empty_link_count} /><KV k="Top external domains" v={h.top_external_domains?.join(', ') || 'none'} /></div>
        </div> : <p className="text-sm text-slate-400">The page content could not be analysed, so HTML checks are <b>unknown</b> (not safe).</p>}
        {h && <div className="mt-3"><SignalList signals={(r.signals || []).filter((s) => ['cred_form', 'form_external', 'form_http', 'hidden_iframe', 'js', 'ext_links', 'meta_refresh', 'title_brand', 'fav'].includes(s.id))} /></div>}
        <p className="text-xs text-slate-500 mt-2">Static analysis only: scripts were never executed and no form was submitted.</p>
      </Section>
      <Why r={r} />
    </div>
  )
}
