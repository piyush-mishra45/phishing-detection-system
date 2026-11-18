import { Navigate, Outlet } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { Spinner } from './ui'

export default function ProtectedRoute({ admin = false }) {
  const { user, loading } = useAuth()
  if (loading) return <Spinner label="Checking session..." />
  if (!user) return <Navigate to="/login" replace />
  if (admin && user.role !== 'admin') return <Navigate to="/dashboard" replace />
  return <Outlet />
}
