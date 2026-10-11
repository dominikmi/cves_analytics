import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ShieldAlert } from 'lucide-react'
import { BrowserRouter, Link, Route, Routes, useLocation } from 'react-router-dom'
import { ProfileDetailPage } from './pages/ProfileDetailPage'
import { ProfilesPage } from './pages/ProfilesPage'

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 15_000, retry: 1 } },
})

function NavBar() {
  const { pathname } = useLocation()
  const onProfiles = pathname === '/'
  return (
    <nav className="flex items-center gap-4 border-b border-gray-200 bg-white px-6 py-3">
      <Link to="/" className="flex items-center gap-2 text-violet-700 font-bold tracking-tight">
        <ShieldAlert className="w-5 h-5" />
        CVEs Analytics
      </Link>
      <div className="ml-4 flex gap-1">
        <Link
          to="/"
          className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
            onProfiles
              ? 'bg-violet-50 text-violet-700'
              : 'text-gray-600 hover:bg-gray-100'
          }`}
        >
          Profiles
        </Link>
      </div>
      <div className="ml-auto">
        <a
          href="/docs"
          target="_blank"
          rel="noreferrer"
          className="text-xs text-gray-400 hover:text-gray-600 transition-colors"
        >
          API docs →
        </a>
      </div>
    </nav>
  )
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <div className="min-h-screen bg-gray-50 flex flex-col">
          <NavBar />
          <main className="flex-1">
            <Routes>
              <Route path="/" element={<ProfilesPage />} />
              <Route path="/profiles/:profileId" element={<ProfileDetailPage />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  )
}

export default App
