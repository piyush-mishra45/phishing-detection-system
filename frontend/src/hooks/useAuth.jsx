import { createContext, useContext, useEffect, useState, useCallback } from 'react'
import { authApi, tokenStore } from '../services/api'

const Ctx = createContext(null)
export const useAuth = () => useContext(Ctx)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(!!tokenStore.get())

  useEffect(() => {
    if (!tokenStore.get()) return
    authApi.me().then(setUser).catch(() => tokenStore.clear()).finally(() => setLoading(false))
  }, [])

  const login = useCallback(async (identifier, password) => {
    const d = await authApi.login({ identifier, password })
    tokenStore.set(d.token); setUser(d.user); return d.user
  }, [])
  const register = useCallback(async (payload) => {
    const d = await authApi.register(payload)
    tokenStore.set(d.token); setUser(d.user); return d.user
  }, [])
  const logout = useCallback(async () => { await authApi.logout(); tokenStore.clear(); setUser(null) }, [])

  return <Ctx.Provider value={{ user, setUser, loading, login, register, logout }}>{children}</Ctx.Provider>
}
