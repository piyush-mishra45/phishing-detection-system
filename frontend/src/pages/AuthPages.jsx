import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ShieldCheck } from 'lucide-react'
import { useAuth } from '../hooks/useAuth'
import { errMsg } from '../services/api'
import { ErrorBox } from '../components/ui'

function Shell({ title, children, foot }) {
  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <div className="card w-full max-w-md">
        <Link to="/" className="flex items-center gap-2 text-white font-bold mb-5"><ShieldCheck className="text-cyan-300" />Phish<span className="text-cyan-300">Guard</span></Link>
        <h1 className="text-xl font-bold text-white mb-4">{title}</h1>{children}<div className="text-sm text-slate-400 mt-4">{foot}</div>
      </div>
    </div>
  )
}

export function Login() {
  const { login } = useAuth(); const nav = useNavigate()
  const [f, setF] = useState({ identifier: '', password: '' }); const [err, setErr] = useState(''); const [busy, setBusy] = useState(false)
  const submit = async (e) => { e.preventDefault(); setBusy(true); setErr(''); try { await login(f.identifier, f.password); nav('/dashboard') } catch (x) { setErr(errMsg(x)) } finally { setBusy(false) } }
  return (
    <Shell title="Welcome back" foot={<>No account? <Link className="text-cyan-300" to="/register">Register</Link></>}>
      <form onSubmit={submit} className="space-y-4">
        <div><label className="label" htmlFor="id">Username or email</label><input id="id" className="input" required autoComplete="username" value={f.identifier} onChange={(e) => setF({ ...f, identifier: e.target.value })} /></div>
        <div><label className="label" htmlFor="pw">Password</label><input id="pw" type="password" className="input" required autoComplete="current-password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></div>
        <ErrorBox>{err}</ErrorBox><button className="btn-primary w-full" disabled={busy}>{busy ? 'Signing in...' : 'Log in'}</button>
      </form>
    </Shell>
  )
}

export function Register() {
  const { register } = useAuth(); const nav = useNavigate()
  const [f, setF] = useState({ username: '', email: '', password: '' }); const [err, setErr] = useState(''); const [busy, setBusy] = useState(false)
  const submit = async (e) => { e.preventDefault(); setBusy(true); setErr(''); try { await register(f); nav('/dashboard') } catch (x) { setErr(errMsg(x)) } finally { setBusy(false) } }
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  return (
    <Shell title="Create your account" foot={<>Already registered? <Link className="text-cyan-300" to="/login">Log in</Link></>}>
      <form onSubmit={submit} className="space-y-4">
        <div><label className="label" htmlFor="u">Username</label><input id="u" className="input" required minLength={3} value={f.username} onChange={set('username')} /></div>
        <div><label className="label" htmlFor="e">Email</label><input id="e" type="email" className="input" required value={f.email} onChange={set('email')} /></div>
        <div><label className="label" htmlFor="p">Password</label><input id="p" type="password" className="input" required minLength={10} autoComplete="new-password" value={f.password} onChange={set('password')} /><p className="text-xs text-slate-500 mt-1">At least 10 characters with upper-case, lower-case and a digit.</p></div>
        <ErrorBox>{err}</ErrorBox><button className="btn-primary w-full" disabled={busy}>{busy ? 'Creating...' : 'Create account'}</button>
      </form>
    </Shell>
  )
}
