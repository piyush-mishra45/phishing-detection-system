export const verdictStyle = {
  SAFE: { text: 'text-emerald-300', bg: 'bg-emerald-500/15', ring: 'ring-emerald-400/40', hex: '#34d399', label: 'SAFE' },
  LEGITIMATE: { text: 'text-emerald-300', bg: 'bg-emerald-500/15', ring: 'ring-emerald-400/40', hex: '#34d399', label: 'LEGITIMATE' },
  SUSPICIOUS: { text: 'text-amber-300', bg: 'bg-amber-500/15', ring: 'ring-amber-400/40', hex: '#fbbf24', label: 'SUSPICIOUS' },
  PHISHING: { text: 'text-red-300', bg: 'bg-red-500/15', ring: 'ring-red-400/40', hex: '#f87171', label: 'PHISHING' },
  UNKNOWN: { text: 'text-slate-300', bg: 'bg-slate-500/15', ring: 'ring-slate-400/40', hex: '#94a3b8', label: 'UNKNOWN' },
}
export const styleFor = (v) => verdictStyle[v] || verdictStyle.UNKNOWN

export const levelFor = (score) => (score <= 30 ? 'Low Risk' : score <= 60 ? 'Medium Risk' : score <= 80 ? 'High Risk' : 'Critical Risk')
export const levelHex = (score) => (score <= 30 ? '#34d399' : score <= 60 ? '#fbbf24' : score <= 80 ? '#fb923c' : '#f87171')
export const pct = (v) => (v == null ? 'n/a' : `${(v * 100).toFixed(1)}%`)
export const fmtDate = (iso) => (iso ? new Date(iso + (iso.endsWith('Z') ? '' : 'Z')).toLocaleString() : '')
