import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Moon, ShieldAlert, Sun } from 'lucide-react'
import { BrowserRouter, Link, Route, Routes, useLocation } from 'react-router-dom'
import { useTheme } from './hooks/useTheme'
import { ProfileDetailPage } from './pages/ProfileDetailPage'
import { ProfilesPage } from './pages/ProfilesPage'

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 15_000, retry: 1 } },
})

function NavBar() {
  const { pathname } = useLocation()
  const { theme, toggle } = useTheme()
  const onProfiles = pathname === '/'
  return (
    <nav className="flex items-center gap-4 border-b border-gray-200 bg-white px-6 py-3 dark:border-gray-700 dark:bg-gray-900">
      <Link to="/" className="flex items-center gap-2 text-violet-700 font-bold tracking-tight dark:text-violet-400">
        <ShieldAlert className="w-5 h-5" />
        CVEs Analytics
      </Link>
      <div className="ml-4 flex gap-1">
        <Link
          to="/"
          className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
            onProfiles
              ? 'bg-violet-50 text-violet-700 dark:bg-violet-950 dark:text-violet-300'
              : 'text-gray-600 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-800'
          }`}
        >
          Profiles
        </Link>
      </div>
      <div className="ml-auto flex items-center gap-3">
        <a
          href="/docs"
          target="_blank"
          rel="noreferrer"
          className="text-xs text-gray-400 hover:text-gray-600 transition-colors dark:hover:text-gray-300"
        >
          API docs →
        </a>
        <button
          onClick={toggle}
          title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          className="rounded-md p-1.5 text-gray-500 hover:bg-gray-100 transition-colors dark:text-gray-400 dark:hover:bg-gray-800"
        >
          {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>
      </div>
    </nav>
  )
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <div className="min-h-screen bg-gray-50 flex flex-col dark:bg-gray-950">
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
