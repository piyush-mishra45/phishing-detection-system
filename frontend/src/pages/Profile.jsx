import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { authApi, errMsg, tokenStore } from '../services/api'
import { useAuth } from '../hooks/useAuth'
import { ErrorBox, PageHeader, Section } from '../components/ui'

export default function Profile() {
  const { user, setUser } = useAuth(); const nav = useNavigate()
  const [p, setP] = useState({ username: user.username, email: user.email }); const [pm, setPm] = useState({ err: '', ok: '' })
  const [pw, setPw] = useState({ current_password: '', new_password: '' }); const [pwm, setPwm] = useState({ err: '', ok: '' })
  const save = async (e) => { e.preventDefault(); setPm({ err: '', ok: '' }); try { setUser(await authApi.updateMe(p)); setPm({ err: '', ok: 'Profile updated.' }) } catch (x) { setPm({ err: errMsg(x), ok: '' }) } }
  const change = async (e) => { e.preventDefault(); setPwm({ err: '', ok: '' }); try { await authApi.changePassword(pw); tokenStore.clear(); setUser(null); nav('/login') } catch (x) { setPwm({ err: errMsg(x), ok: '' }) } }
  return (
    <>
      <PageHeader title="Profile" subtitle={`Role: ${user.role} - member since ${new Date(user.created_at).toLocaleDateString()}`} />
      <div className="grid lg:grid-cols-2 gap-4 max-w-4xl">
        <Section title="Account details"><form onSubmit={save} className="space-y-3">
          <div><label className="label">Username</label><input className="input" value={p.username} onChange={(e) => setP({ ...p, username: e.target.value })} /></div>
          <div><label className="label">Email</label><input type="email" className="input" value={p.email} onChange={(e) => setP({ ...p, email: e.target.value })} /></div>
          <ErrorBox>{pm.err}</ErrorBox>{pm.ok && <p className="text-sm text-emerald-300">{pm.ok}</p>}<button className="btn-primary">Save</button></form></Section>
        <Section title="Change password"><form onSubmit={change} className="space-y-3">
          <div><label className="label">Current password</label><input type="password" className="input" autoComplete="current-password" value={pw.current_password} onChange={(e) => setPw({ ...pw, current_password: e.target.value })} /></div>
          <div><label className="label">New password</label><input type="password" className="input" autoComplete="new-password" value={pw.new_password} onChange={(e) => setPw({ ...pw, new_password: e.target.value })} /></div>
          <ErrorBox>{pwm.err}</ErrorBox><button className="btn-primary">Change password</button></form></Section>
      </div>
    </>
  )
}
