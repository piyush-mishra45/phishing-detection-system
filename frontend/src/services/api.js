import axios from 'axios'

const TOKEN_KEY = 'phishguard_token'
// NOTE: a JWT in localStorage is readable by any XSS. The app renders all scan data as text (React escapes it),
// but for higher-assurance deployments move the token to an httpOnly, SameSite cookie.
export const tokenStore = {
  get: () => localStorage.getItem(TOKEN_KEY),
  set: (t) => localStorage.setItem(TOKEN_KEY, t),
  clear: () => localStorage.removeItem(TOKEN_KEY),
}

const api = axios.create({ baseURL: import.meta.env.VITE_API_URL || '', timeout: 60000 })

api.interceptors.request.use((cfg) => {
  const t = tokenStore.get()
  if (t) cfg.headers.Authorization = `Bearer ${t}`
  return cfg
})

api.interceptors.response.use(
  (r) => r,
  (err) => {
    const url = err.config?.url || ''
    if (err.response?.status === 401 && !url.includes('/auth/login') && !url.includes('/auth/register')) {
      tokenStore.clear()
      if (!location.pathname.startsWith('/login')) location.assign('/login')
    }
    return Promise.reject(err)
  }
)

export const errMsg = (e) => e.response?.data?.error || (e.code === 'ECONNABORTED' ? 'The request timed out' : e.message === 'Network Error' ? 'Cannot reach the server' : e.message)

export const authApi = {
  register: (d) => api.post('/api/auth/register', d).then((r) => r.data),
  login: (d) => api.post('/api/auth/login', d).then((r) => r.data),
  logout: () => api.post('/api/auth/logout').catch(() => {}),
  me: () => api.get('/api/auth/me').then((r) => r.data.user),
  updateMe: (d) => api.put('/api/auth/me', d).then((r) => r.data.user),
  changePassword: (d) => api.post('/api/auth/change-password', d).then((r) => r.data),
}
export const scanApi = {
  email: (payload) => api.post('/api/scan/email', payload).then((r) => r.data),
  website: (url) => api.post('/api/scan/website', { url }).then((r) => r.data),
}
export const dataApi = {
  stats: (scope) => api.get('/api/dashboard/stats', { params: scope ? { scope } : {} }).then((r) => r.data),
  history: (params) => api.get('/api/history', { params }).then((r) => r.data),
  detail: (id) => api.get(`/api/history/${id}`).then((r) => r.data),
  remove: (id) => api.delete(`/api/history/${id}`).then((r) => r.data),
  metrics: () => api.get('/api/model/metrics').then((r) => r.data),
  exportCsv: async (params) => {
    const r = await api.get('/api/reports/export', { params, responseType: 'blob' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(r.data)
    a.download = 'phishguard_report.csv'
    a.click()
    URL.revokeObjectURL(a.href)
  },
}
export const adminApi = {
  users: () => api.get('/api/admin/users').then((r) => r.data.users),
  stats: () => api.get('/api/admin/stats').then((r) => r.data),
  setRole: (id, role) => api.patch(`/api/admin/users/${id}/role`, { role }).then((r) => r.data),
  remove: (id) => api.delete(`/api/admin/users/${id}`).then((r) => r.data),
}
export default api
