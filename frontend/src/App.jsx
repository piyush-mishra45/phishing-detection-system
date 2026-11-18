import { Navigate, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import ProtectedRoute from './components/ProtectedRoute'
import Landing from './pages/Landing'
import { Login, Register } from './pages/AuthPages'
import Dashboard from './pages/Dashboard'
import EmailScanner from './pages/EmailScanner'
import WebsiteScanner from './pages/WebsiteScanner'
import ScanResults from './pages/ScanResults'
import History from './pages/History'
import Analytics from './pages/Analytics'
import ModelPerformance from './pages/ModelPerformance'
import Profile from './pages/Profile'
import AdminDashboard from './pages/AdminDashboard'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<Layout />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/scan/email" element={<EmailScanner />} />
          <Route path="/scan/website" element={<WebsiteScanner />} />
          <Route path="/results/:id" element={<ScanResults />} />
          <Route path="/history" element={<History />} />
          <Route path="/analytics" element={<Analytics />} />
          <Route path="/models" element={<ModelPerformance />} />
          <Route path="/profile" element={<Profile />} />
          <Route element={<ProtectedRoute admin />}><Route path="/admin" element={<AdminDashboard />} /></Route>
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
