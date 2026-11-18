import { useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { BarChart3, Cpu, History, LayoutDashboard, LogOut, Mail, Menu, ShieldCheck, Globe, User, UserCog, X } from 'lucide-react'
import { useAuth } from '../hooks/useAuth'

const links = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/scan/email', label: 'Email Scanner', icon: Mail },
  { to: '/scan/website', label: 'Website Scanner', icon: Globe },
  { to: '/history', label: 'Scan History', icon: History },
  { to: '/analytics', label: 'Analytics', icon: BarChart3 },
  { to: '/models', label: 'Model Performance', icon: Cpu },
  { to: '/profile', label: 'Profile', icon: User },
]

export default function Layout() {
  const { user, logout } = useAuth()
  const nav = useNavigate()
  const [open, setOpen] = useState(false)
  const items = user?.role === 'admin' ? [...links, { to: '/admin', label: 'Admin', icon: UserCog }] : links
  const bye = async () => { await logout(); nav('/') }

  const side = (
    <nav className="flex flex-col h-full p-4">
      <div className="flex items-center gap-2 px-2 mb-8"><ShieldCheck className="text-cyan-300" /><span className="text-lg font-bold text-white">Phish<span className="text-cyan-300">Guard</span></span></div>
      <div className="space-y-1 flex-1">
        {items.map(({ to, label, icon: Icon }) => (
          <NavLink key={to} to={to} onClick={() => setOpen(false)}
            className={({ isActive }) => `flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition ${isActive ? 'bg-gradient-to-r from-blue-500/25 to-cyan-400/10 text-cyan-200 ring-1 ring-cyan-400/30' : 'text-slate-400 hover:text-white hover:bg-white/5'}`}>
            <Icon size={18} />{label}
          </NavLink>
        ))}
      </div>
      <div className="border-t border-white/10 pt-3">
        <div className="px-2 text-sm text-white truncate">{user?.username}</div>
        <div className="px-2 text-xs text-slate-500 mb-2">{user?.role}</div>
        <button onClick={bye} className="btn-ghost w-full"><LogOut size={16} />Log out</button>
      </div>
    </nav>
  )
  return (
    <div className="min-h-screen lg:flex">
      <aside className="hidden lg:block w-64 shrink-0 bg-navy-900/80 border-r border-white/5 sticky top-0 h-screen">{side}</aside>
      <div className="lg:hidden flex items-center justify-between px-4 py-3 bg-navy-900/90 border-b border-white/5 sticky top-0 z-30">
        <span className="font-bold text-white flex items-center gap-2"><ShieldCheck className="text-cyan-300" size={20} />PhishGuard</span>
        <button aria-label="Toggle menu" onClick={() => setOpen(!open)}>{open ? <X /> : <Menu />}</button>
      </div>
      {open && <div className="lg:hidden fixed inset-0 z-20 pt-12 bg-navy-900">{side}</div>}
      <main className="flex-1 min-w-0 p-4 sm:p-6 lg:p-8 max-w-7xl"><Outlet /></main>
    </div>
  )
}
