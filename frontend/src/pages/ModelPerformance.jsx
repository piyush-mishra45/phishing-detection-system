import { AlertTriangle } from 'lucide-react'
import { dataApi } from '../services/api'
import { useAsync } from '../hooks/useAsync'
import { ErrorBox, PageHeader, Section, Spinner } from '../components/ui'
import { MetricsBar } from '../charts/Charts'
import { fmtDate } from '../utils'

const n = (v) => (v == null ? 'n/a' : v.toFixed(3))
export default function ModelPerformance() {
  const { data, loading, error } = useAsync(() => dataApi.metrics(), [])
  if (loading) return <Spinner />
  if (error) return <ErrorBox>{error}</ErrorBox>
  const m = data.metrics
  const demo = m.some((x) => x.is_demo_data)
  const chart = m.map((x) => ({ name: x.model_name.replace(/^(Email|Website): /, '').replace(/DEPLOYED \((.*)\)/, '$1*'), accuracy: x.accuracy, precision: x.precision, recall: x.recall, f1: x.f1_score }))
  return (
    <>
      <PageHeader title="Model performance" subtitle="Held-out test-set metrics from the training scripts" />
      {demo && <div className="card border-amber-400/40 bg-amber-500/10 mb-4 flex gap-3 text-amber-100 text-sm"><AlertTriangle className="shrink-0 text-amber-300" />
        <div><b>These models were trained on synthetic demo data.</b> The near-perfect scores are meaningless. Download real datasets (see datasets/README.md) and re-run the training scripts.</div></div>}
      <p className="text-xs text-slate-500 mb-4">{data.warning}</p>
      {m.length === 0 ? <ErrorBox>No metrics found. Run backend/train_email_model.py and train_website_model.py, then restart the API.</ErrorBox> : <>
        <Section title="Comparison (* = deployed, calibrated)"><MetricsBar data={chart} /></Section>
        <div className="card mt-4 p-0 overflow-x-auto"><table className="w-full"><thead><tr>{['Model', 'Accuracy', 'Precision', 'Recall', 'F1', 'ROC-AUC', 'Confusion [[TN,FP],[FN,TP]]', 'Trained'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
          <tbody>{m.map((x) => (<tr key={x.model_name} className={x.model_name.includes('DEPLOYED') ? 'bg-cyan-400/5' : ''}><td className="td font-medium">{x.model_name}</td><td className="td">{n(x.accuracy)}</td><td className="td">{n(x.precision)}</td><td className="td">{n(x.recall)}</td><td className="td">{n(x.f1_score)}</td><td className="td">{n(x.roc_auc)}</td><td className="td font-mono text-xs">{JSON.stringify(x.confusion_matrix)}</td><td className="td text-xs text-slate-400">{fmtDate(x.trained_at)}<div>{x.dataset}</div></td></tr>))}</tbody></table></div></>}
    </>
  )
}
