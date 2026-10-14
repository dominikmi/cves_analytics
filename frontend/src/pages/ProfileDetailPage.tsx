import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowDown, ArrowLeft, ArrowUp, ArrowUpDown, CheckCircle2, Pencil, Play, RefreshCw, Server, Shield, Trash2, XCircle } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { deleteScan, generateScenario, getFindings, getImageStats, getProfile, getScanRun, getScenario, listScans, patchProfile, triggerScan } from '../api/client'
import type { ControlsSnapshot, FindingRow, FindingsSort, ProfileOut, ScanRunOut, SortOrder, SSEEvent } from '../api/types'
import { EnvironmentDiagram } from '../components/EnvironmentDiagram'
import { ScanReport } from '../components/ScanReport'
import { SeverityBadge } from '../components/SeverityBadge'
import { StatusPill } from '../components/StatusPill'

// ---------------------------------------------------------------------------
// Profile details panel
// ---------------------------------------------------------------------------
const CONTROL_LABELS: Record<string, string> = {
  network_segmentation: 'Network Segmentation',
  firewall: 'Firewall',
  waf: 'WAF',
  ids_ips: 'IDS / IPS',
  edr_xdr: 'EDR / XDR',
  antivirus: 'Antivirus',
  mfa: 'MFA',
  privileged_access_mgmt: 'PAM',
  siem: 'SIEM',
  soc_24x7: 'SOC 24×7',
  incident_response_plan: 'Incident Response Plan',
  security_training: 'Security Training',
  air_gapped: 'Air-Gapped',
}

function ProfileDetailsPanel({ profile }: { profile: ProfileOut }) {
  const qc = useQueryClient()
  const controls: ControlsSnapshot = profile.controls_snapshot ?? {}
  const boolControls = Object.entries(CONTROL_LABELS) as [keyof ControlsSnapshot, string][]
  const images = profile.image_inventory ?? []

  const [editingImages, setEditingImages] = useState(false)
  const [imagesRaw, setImagesRaw] = useState('')

  const saveMut = useMutation({
    mutationFn: (imgs: string[]) => patchProfile(profile.id, { image_inventory: imgs }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['profile', profile.id] })
      setEditingImages(false)
    },
  })

  function startEdit() {
    setImagesRaw(images.join('\n'))
    setEditingImages(true)
  }

  function saveEdit() {
    const imgs = imagesRaw.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean)
    saveMut.mutate(imgs)
  }

  return (
    <details open={images.length === 0} className="mb-6 rounded-xl border border-gray-200 bg-white shadow-sm dark:border-gray-700 dark:bg-gray-900">
      <summary className="flex cursor-pointer items-center gap-2 px-5 py-3 text-sm font-semibold text-gray-700 select-none hover:bg-gray-50 rounded-xl dark:text-gray-200 dark:hover:bg-gray-800">
        <Shield className="w-4 h-4 text-violet-500" />
        Profile Configuration
        <span className="ml-auto text-xs font-normal text-gray-400">{images.length === 0 ? 'click to collapse' : 'click to expand'}</span>
      </summary>

      <div className="px-5 pb-5 pt-3 space-y-5">
        {/* Environment attributes */}
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-gray-400 mb-2">Environment</p>
          <dl className="grid grid-cols-3 gap-x-6 gap-y-2 text-sm">
            {([
              ['Industry', profile.industry],
              ['Environment', profile.environment],
              ['Org Size', profile.org_size],
              ['Org Reach', profile.org_reach],
              ['Maturity', profile.security_maturity],
              ['Created', new Date(profile.created_at).toLocaleDateString()],
            ] as [string, string][]).map(([label, value]) => (
              <div key={label}>
                <dt className="text-xs text-gray-400">{label}</dt>
                <dd className="font-medium text-gray-800 capitalize dark:text-gray-200">{value}</dd>
              </div>
            ))}
          </dl>
        </div>

        {/* Image inventory */}
        <div>
          <div className="flex items-center gap-2 mb-2">
            <p className="text-xs font-semibold uppercase tracking-wide text-gray-400 flex items-center gap-1">
              <Server className="w-3 h-3" /> Container Images ({images.length})
            </p>
            {!editingImages && (
              <button
                onClick={startEdit}
                className="ml-auto flex items-center gap-1 rounded px-2 py-0.5 text-xs text-gray-400 hover:text-violet-600 hover:bg-violet-50 transition-colors dark:hover:bg-violet-950 dark:hover:text-violet-300"
              >
                <Pencil className="w-3 h-3" /> Edit
              </button>
            )}
          </div>

          {editingImages ? (
            <div className="space-y-2">
              <textarea
                autoFocus
                value={imagesRaw}
                onChange={(e) => setImagesRaw(e.target.value)}
                rows={4}
                className="w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-violet-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
                placeholder="nginx:latest&#10;redis:7&#10;postgres:15"
              />
              <div className="flex gap-2">
                <button
                  onClick={saveEdit}
                  disabled={saveMut.isPending}
                  className="rounded bg-violet-600 px-3 py-1 text-xs font-medium text-white hover:bg-violet-700 disabled:opacity-50 transition-colors"
                >
                  {saveMut.isPending ? 'Saving…' : 'Save'}
                </button>
                <button
                  onClick={() => setEditingImages(false)}
                  className="rounded border border-gray-300 px-3 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50 transition-colors dark:border-gray-600 dark:text-gray-300 dark:hover:bg-gray-800"
                >
                  Cancel
                </button>
              </div>
              {saveMut.isError && (
                <p className="text-xs text-red-600 dark:text-red-400">{String(saveMut.error)}</p>
              )}
            </div>
          ) : images.length === 0 ? (
            <p className="text-xs text-gray-400 italic">
              No images defined.
              <button onClick={startEdit} className="ml-1 text-violet-500 hover:underline dark:text-violet-400">Add now</button>
            </p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {images.map((img) => (
                <span key={img} className="rounded bg-gray-100 px-2 py-0.5 font-mono text-xs text-gray-700 border border-gray-200 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-700">
                  {img}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Security controls grid */}
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-gray-400 mb-2">Security Controls</p>
          <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-sm">
            {boolControls.map(([key, label]) => {
              const present = controls[key] === true
              return (
                <div key={key} className="flex items-center gap-2">
                  {present
                    ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                    : <XCircle className="w-3.5 h-3.5 text-gray-300 shrink-0 dark:text-gray-600" />}
                  <span className={present ? 'text-gray-800 dark:text-gray-200' : 'text-gray-400 dark:text-gray-500'}>{label}</span>
                </div>
              )
            })}
          </div>
          {controls.patch_management && (
            <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
              Patch cadence: <span className="font-medium text-gray-700 capitalize dark:text-gray-300">{controls.patch_management}</span>
            </p>
          )}
        </div>
      </div>
    </details>
  )
}

// ---------------------------------------------------------------------------
// Log stream panel
// ---------------------------------------------------------------------------
function LogStream({ jobId, onDone }: { jobId: string; onDone: () => void }) {
  const [lines, setLines] = useState<{ ts: string; level: string; msg: string }[]>([])
  const [progress, setProgress] = useState<{ current: number; total: number } | null>(null)
  const [done, setDone] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const es = new EventSource(`/api/stream/${jobId}`)

    es.onmessage = (e) => {
      const ev: SSEEvent = JSON.parse(e.data)
      if (ev.type === 'done' || ev.type === 'complete') {
        setDone(true)
        es.close()
        onDone()
      } else if (ev.type === 'error') {
        setLines((l) => [...l, { ts: new Date().toISOString(), level: 'ERROR', msg: ev.message }])
        setDone(true)
        es.close()
        onDone()
      } else if (ev.type === 'log') {
        setLines((l) => [...l, { ts: ev.ts, level: ev.level, msg: ev.message }])
      } else if (ev.type === 'progress') {
        if (ev.current != null && ev.total != null && ev.total > 0) {
          setProgress({ current: ev.current, total: ev.total })
        }
        const level = ev.image_phase === 'failed' ? 'WARNING' : 'INFO'
        setLines((l) => [...l, { ts: new Date().toISOString(), level, msg: ev.message }])
      }
    }

    es.onerror = () => {
      setLines((l) => [...l, { ts: new Date().toISOString(), level: 'ERROR', msg: 'SSE connection lost' }])
      setDone(true)
      es.close()
      onDone()
    }

    return () => es.close()
  }, [jobId, onDone])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [lines])

  const levelColor: Record<string, string> = {
    DEBUG: 'text-gray-400',
    INFO: 'text-green-400',
    WARNING: 'text-yellow-400',
    ERROR: 'text-red-400',
  }

  const pct = progress ? Math.round((progress.current / progress.total) * 100) : 0

  return (
    <div>
      {progress && !done && (
        <div className="mb-2">
          <div className="flex justify-between text-[11px] text-gray-500 mb-1 dark:text-gray-400">
            <span>Scanning images</span>
            <span className="tabular-nums">
              {progress.current} / {progress.total} ({pct}%)
            </span>
          </div>
          <div className="h-1.5 rounded-full bg-gray-200 overflow-hidden dark:bg-gray-800">
            <div
              className="h-full bg-violet-500 transition-all duration-500"
              style={{ width: `${pct}%` }}
            />
          </div>
        </div>
      )}
      <div className="rounded-lg border border-gray-800 bg-gray-950 p-3 font-mono text-xs h-64 overflow-y-auto">
      {lines.length === 0 && !done && (
        <span className="text-gray-500">Waiting for pipeline output…</span>
      )}
      {lines.map((l, i) => (
        <div key={i} className="flex gap-2 leading-5">
          <span className="text-gray-600 shrink-0">{l.ts.slice(11, 19)}</span>
          <span className={`shrink-0 w-14 ${levelColor[l.level] ?? 'text-gray-400'}`}>{l.level}</span>
          <span className="text-gray-200 break-all">{l.msg}</span>
        </div>
      ))}
      {done && (
        <div className="mt-1 text-green-500 font-bold">─── stream closed ───</div>
      )}
      <div ref={bottomRef} />
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Findings table
// ---------------------------------------------------------------------------
const SORTABLE_COLUMNS: { key: FindingsSort; label: string; right?: boolean }[] = [
  { key: 'cve', label: 'CVE' },
  { key: 'image', label: 'Image' },
  { key: 'service', label: 'Service' },
  { key: 'severity', label: 'Scanner' },
  { key: 'reassessed', label: 'Reassessed' },
  { key: 'cvss', label: 'CVSS', right: true },
  { key: 'epss', label: 'EPSS', right: true },
  { key: 'risk', label: 'Risk', right: true },
  { key: 'kev', label: 'KEV' },
]

function shortImageName(ref: string): string {
  // "registry.local:5000/org/img:tag" -> "org/img:tag" basename stays readable.
  const last = ref.split('/').pop() ?? ref
  return last
}

function FindingsTable({ profileId, runId }: { profileId: number; runId: number }) {
  const [page, setPage] = useState(0)
  const [severityFilter, setSeverityFilter] = useState('')
  const [imageFilter, setImageFilter] = useState<string | null>(null)
  const [sort, setSort] = useState<FindingsSort | null>(null)
  const [order, setOrder] = useState<SortOrder>('desc')
  const limit = 50

  const { data: imageStats = [] } = useQuery({
    queryKey: ['image-stats', profileId, runId],
    queryFn: () => getImageStats(profileId, runId),
  })

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['findings', profileId, runId, page, severityFilter, imageFilter, sort, order],
    queryFn: () =>
      getFindings(profileId, runId, {
        limit,
        offset: page * limit,
        severity: severityFilter || undefined,
        image: imageFilter ?? undefined,
        sort: sort ?? undefined,
        order,
      }),
  })

  function toggleSort(key: FindingsSort) {
    if (sort !== key) {
      setSort(key)
      setOrder('desc')
    } else if (order === 'desc') {
      setOrder('asc')
    } else {
      setSort(null)
    }
    setPage(0)
  }

  function sortIcon(key: FindingsSort) {
    if (sort !== key) return <ArrowUpDown className="w-3 h-3 opacity-40" />
    return order === 'desc'
      ? <ArrowDown className="w-3 h-3" />
      : <ArrowUp className="w-3 h-3" />
  }

  const totalPages = data ? Math.ceil(data.total / limit) : 0
  const tabTotal = imageStats.reduce((acc, s) => acc + s.total, 0)

  return (
    <div>
      {/* Per-image tabs */}
      {imageStats.length > 0 && (
        <div className="mb-3 flex flex-wrap gap-1">
          <button
            onClick={() => { setImageFilter(null); setPage(0) }}
            className={`rounded-t-md border-b-2 px-3 py-1.5 text-xs font-medium transition-colors ${
              imageFilter === null
                ? 'border-violet-500 text-violet-700 dark:text-violet-300'
                : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200'
            }`}
          >
            All <span className="ml-1 text-gray-400">({tabTotal})</span>
          </button>
          {imageStats.map((s) => (
            <button
              key={s.image}
              onClick={() => { setImageFilter(s.image); setPage(0) }}
              title={s.image}
              className={`rounded-t-md border-b-2 px-3 py-1.5 text-xs font-mono transition-colors ${
                imageFilter === s.image
                  ? 'border-violet-500 text-violet-700 dark:text-violet-300'
                  : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200'
              }`}
            >
              {shortImageName(s.image)}
              <span className="ml-1.5 font-sans text-gray-400">({s.total})</span>
              {s.critical > 0 && (
                <span className="ml-1 rounded bg-red-100 px-1 text-[10px] font-bold text-red-700 dark:bg-red-950 dark:text-red-300">
                  {s.critical}C
                </span>
              )}
            </button>
          ))}
        </div>
      )}

      <div className="flex items-center justify-between mb-3">
        <p className="text-sm text-gray-600 dark:text-gray-400">
          {data ? `${data.total} total findings` : 'Loading…'}
        </p>
        <div className="flex items-center gap-2">
          <select
            value={severityFilter}
            onChange={(e) => { setSeverityFilter(e.target.value); setPage(0) }}
            className="rounded border border-gray-300 px-2 py-1 text-xs dark:border-gray-600 dark:bg-gray-800 dark:text-gray-200"
          >
            <option value="">All severities</option>
            {['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Informational', 'Unknown'].map((s) => (
              <option key={s} value={s.toLowerCase()}>{s}</option>
            ))}
          </select>
          <button
            onClick={() => refetch()}
            className="p-1 text-gray-400 hover:text-violet-600 transition-colors dark:hover:text-violet-400"
            title="Refresh"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {isLoading && <p className="text-sm text-gray-500">Loading findings…</p>}

      {data && (
      <div className="overflow-x-auto rounded-lg border border-gray-200 dark:border-gray-700">
        <table className="w-full text-xs">
          <thead className="bg-gray-50 text-left text-gray-600 uppercase tracking-wide dark:bg-gray-800 dark:text-gray-400">
            <tr>
              {SORTABLE_COLUMNS.map((col) => (
                <th key={col.key} className={`px-3 py-2 ${col.right ? 'text-right' : ''}`}>
                  <button
                    onClick={() => toggleSort(col.key)}
                    className={`inline-flex items-center gap-1 uppercase tracking-wide hover:text-violet-600 dark:hover:text-violet-400 ${
                      sort === col.key ? 'text-violet-700 dark:text-violet-300' : ''
                    }`}
                  >
                    {col.label}
                    {sortIcon(col.key)}
                  </button>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100 bg-white dark:divide-gray-800 dark:bg-gray-900">
            {data.items.map((f: FindingRow) => (
              <tr key={f.id} className="hover:bg-gray-50 dark:hover:bg-gray-800">
                <td className="px-3 py-2 font-mono text-violet-700 dark:text-violet-300">{f.cve_id ?? '—'}</td>
                <td className="px-3 py-2 text-gray-700 max-w-[140px] truncate dark:text-gray-300" title={`${f.image_name ?? ''}:${f.image_tag ?? ''}`}>
                  {f.image_name ?? '—'}{f.image_tag ? `:${f.image_tag}` : ''}
                </td>
                <td className="px-3 py-2 text-gray-600 dark:text-gray-400">{f.service_name ?? '—'}</td>
                <td className="px-3 py-2">
                  <SeverityBadge value={f.severity} />
                </td>
                <td className="px-3 py-2">
                  <SeverityBadge value={f.severity_reassessed} />
                </td>
                <td className="px-3 py-2 text-right tabular-nums text-gray-700 dark:text-gray-300">
                  {f.cvss_score != null ? f.cvss_score.toFixed(1) : '—'}
                </td>
                <td className="px-3 py-2 text-right tabular-nums text-gray-700 dark:text-gray-300">
                  {f.epss_score != null ? (f.epss_score * 100).toFixed(1) + '%' : '—'}
                </td>
                <td className="px-3 py-2 text-right tabular-nums text-gray-700 dark:text-gray-300">
                  {f.bayesian_risk != null ? (f.bayesian_risk * 100).toFixed(1) + '%' : '—'}
                </td>
                <td className="px-3 py-2 text-center">
                  {f.is_kev ? (
                    <span className="text-red-600 font-bold text-[10px] dark:text-red-400">KEV</span>
                  ) : (
                    <span className="text-gray-300 dark:text-gray-600">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-3 text-xs text-gray-600 dark:text-gray-400">
          <span>Page {page + 1} of {totalPages}</span>
          <div className="flex gap-2">
            <button
              disabled={page === 0}
              onClick={() => setPage((p) => p - 1)}
              className="rounded border border-gray-300 px-2 py-1 disabled:opacity-40 hover:bg-gray-50 dark:border-gray-600 dark:hover:bg-gray-800"
            >
              Prev
            </button>
            <button
              disabled={page + 1 >= totalPages}
              onClick={() => setPage((p) => p + 1)}
              className="rounded border border-gray-300 px-2 py-1 disabled:opacity-40 hover:bg-gray-50 dark:border-gray-600 dark:hover:bg-gray-800"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Run card
// ---------------------------------------------------------------------------
function severityCount(run: ScanRunOut, severity: string): number {
  const counts = run.severity_counts ?? {}
  const key = Object.keys(counts).find(
    (k) => k.toLowerCase() === severity.toLowerCase(),
  )
  return key ? counts[key] : 0
}

function formatStartedAt(value: string | null): string {
  return value ? new Date(value).toLocaleString() : '—'
}

function RunCard({
  run,
  selected,
  onSelect,
  onDelete,
}: {
  run: ScanRunOut
  selected: boolean
  onSelect: () => void
  onDelete: () => void
}) {
  const deletable = run.status !== 'RUNNING' && run.status !== 'PENDING'
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => e.key === 'Enter' && onSelect()}
      className={`w-full text-left rounded-lg border px-4 py-3 transition-colors cursor-pointer ${
        selected
          ? 'border-violet-400 bg-violet-50 dark:bg-violet-950'
          : 'border-gray-200 bg-white hover:border-violet-200 dark:border-gray-700 dark:bg-gray-900 dark:hover:border-violet-700'
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <StatusPill status={run.status} />
        <span className="text-xs text-gray-500 tabular-nums flex-1 text-right dark:text-gray-400">
          {formatStartedAt(run.started_at)}
        </span>
        {deletable && (
          <button
            onClick={(e) => { e.stopPropagation(); onDelete() }}
            title="Delete scan"
            className="p-1 rounded text-gray-400 hover:text-red-600 hover:bg-red-50 transition-colors dark:hover:bg-red-950"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        )}
      </div>
      {run.status === 'DONE' && (
        <div className="mt-2 flex gap-4 text-xs">
          <span className="text-red-700 font-semibold dark:text-red-400">C: {severityCount(run, 'CRITICAL')}</span>
          <span className="text-orange-700 font-semibold dark:text-orange-400">H: {severityCount(run, 'HIGH')}</span>
          <span className="text-yellow-700 font-semibold dark:text-yellow-400">M: {severityCount(run, 'MEDIUM')}</span>
          <span className="text-blue-700 dark:text-blue-400">L: {severityCount(run, 'LOW')}</span>
          <span className="ml-auto text-gray-500 dark:text-gray-400">
            {Object.values(run.severity_counts ?? {}).reduce((total, count) => total + count, 0)} total
          </span>
        </div>
      )}
      {run.status === 'FAILED' && run.error_message && (
        <details className="mt-1">
          <summary className="text-xs text-red-600 cursor-pointer select-none dark:text-red-400">
            Error — click to expand
          </summary>
          <pre className="mt-1 text-xs text-red-700 whitespace-pre-wrap break-all bg-red-50 rounded p-2 dark:bg-red-950 dark:text-red-300">
            {run.error_message}
          </pre>
        </details>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------
export function ProfileDetailPage() {
  const { profileId } = useParams<{ profileId: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [activeJobId, setActiveJobId] = useState<string | null>(null)
  const [selectedRunId, setSelectedRunId] = useState<number | null>(null)

  const { data: profile, isLoading: loadingProfile } = useQuery({
    queryKey: ['profile', profileId],
    queryFn: () => getProfile(profileId!),
    enabled: !!profileId,
  })

  const { data: runs = [], refetch: refetchRuns } = useQuery({
    queryKey: ['scans', profileId],
    queryFn: () => listScans(profileId!),
    enabled: !!profileId,
    refetchInterval: activeJobId ? 5_000 : 30_000,
  })

  const { data: scenario, refetch: refetchScenario } = useQuery({
    queryKey: ['scenario', profileId],
    queryFn: () => getScenario(profileId!),
    enabled: !!profileId,
    retry: false,
  })

  const scenarioMut = useMutation({
    mutationFn: () => generateScenario(profileId!),
    onSuccess: () => refetchScenario(),
  })

  const deleteMut = useMutation({
    mutationFn: (runId: number) => deleteScan(profileId!, runId),
    onSuccess: (_data, runId) => {
      if (selectedRunId === runId) setSelectedRunId(null)
      qc.invalidateQueries({ queryKey: ['scans', profileId] })
      qc.invalidateQueries({ queryKey: ['profile', profileId] })
    },
  })

  const triggerMut = useMutation({
    mutationFn: () => triggerScan(profileId!),
    onSuccess: (data) => {
      setActiveJobId(data.job_id)
      setSelectedRunId(data.id)
      qc.invalidateQueries({ queryKey: ['scans', profileId] })
    },
  })

  // Poll selected run while it's running
  useQuery({
    queryKey: ['scan-run', profileId, selectedRunId],
    queryFn: () => getScanRun(profileId!, selectedRunId!),
    enabled: !!profileId && !!selectedRunId,
    refetchInterval: (query) => {
      const data = query.state.data
      const active = data?.status === 'RUNNING' || data?.status === 'PENDING'
      if (!active && data?.status) qc.invalidateQueries({ queryKey: ['profile', profileId] })
      return active ? 3_000 : false
    },
  })

  const selectedRun = runs.find((r) => r.id === selectedRunId) ?? runs[0] ?? null
  // Attach the log stream to whichever run is live — the just-triggered job,
  // or any RUNNING/PENDING run the user selects (e.g. after a page reload).
  const streamJobId =
    activeJobId ??
    (selectedRun && (selectedRun.status === 'RUNNING' || selectedRun.status === 'PENDING')
      ? selectedRun.job_id
      : null)

  // Stable identity — a fresh function every render would make the
  // LogStream effect tear down and reconnect its EventSource each poll.
  const handleStreamDone = useCallback(() => {
    setActiveJobId(null)
    refetchRuns()
    qc.invalidateQueries({ queryKey: ['scan-run', profileId, selectedRunId] })
    qc.invalidateQueries({ queryKey: ['profile', profileId] })
  }, [qc, profileId, selectedRunId, refetchRuns])

  if (loadingProfile) return <p className="p-8 text-sm text-gray-500 dark:text-gray-400">Loading…</p>
  if (!profile) return <p className="p-8 text-sm text-red-600 dark:text-red-400">Profile not found</p>

  return (
    <div className="p-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/')}
            className="p-1.5 text-gray-400 hover:text-gray-700 transition-colors dark:hover:text-gray-200"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">{profile.name}</h1>
            <p className="text-sm text-gray-500 mt-0.5 dark:text-gray-400">
              {profile.industry} · {profile.environment} · {profile.org_size} · {profile.org_reach} · maturity: {profile.security_maturity}
            </p>
          </div>
        </div>
        <button
          onClick={() => triggerMut.mutate()}
          disabled={triggerMut.isPending || !!activeJobId}
          className="flex items-center gap-2 rounded-lg bg-violet-600 px-4 py-2 text-sm font-medium text-white hover:bg-violet-700 disabled:opacity-50 transition-colors"
        >
          <Play className="w-4 h-4" />
          {activeJobId ? 'Running…' : 'Trigger Scan'}
        </button>
      </div>

      <ProfileDetailsPanel profile={profile} />

      {/* Environment diagram */}
      <div className="mb-6">
        {scenario ? (
          <EnvironmentDiagram scenario={scenario} />
        ) : (
          <button
            onClick={() => scenarioMut.mutate()}
            disabled={scenarioMut.isPending}
            className="rounded-lg border border-dashed border-gray-300 px-4 py-2 text-xs text-gray-500 hover:border-violet-400 hover:text-violet-600 transition-colors dark:border-gray-600 dark:text-gray-400 dark:hover:text-violet-400"
          >
            {scenarioMut.isPending ? 'Generating…' : 'Generate environment diagram'}
          </button>
        )}
      </div>

      <div className="grid grid-cols-[280px_1fr] gap-6">
        {/* Scan run list */}
        <div>
          <h2 className="text-xs font-semibold uppercase tracking-wide text-gray-500 mb-2 dark:text-gray-400">
            Scan Runs ({runs.length})
          </h2>
          {runs.length === 0 ? (
            <p className="text-sm text-gray-400 text-center py-8 dark:text-gray-500">No scans yet</p>
          ) : (
            <div className="space-y-2">
              {runs.map((r) => (
                <RunCard
                  key={r.id}
                  run={r}
                  selected={r.id === (selectedRun?.id ?? null)}
                  onSelect={() => setSelectedRunId(r.id)}
                  onDelete={() => deleteMut.mutate(r.id)}
                />
              ))}
            </div>
          )}
        </div>

        {/* Right panel */}
        <div className="space-y-4">
          {/* Live log stream */}
          {streamJobId && (
            <div>
              <h2 className="text-xs font-semibold uppercase tracking-wide text-gray-500 mb-2 dark:text-gray-400">
                Live Pipeline Output — {selectedRun?.status}
              </h2>
              <LogStream jobId={streamJobId} onDone={handleStreamDone} />
            </div>
          )}

          {/* Scan report + findings table */}
          {selectedRun && selectedRun.status === 'DONE' && (
            <>
              <ScanReport profileId={profile.id} runId={selectedRun.id} />
              <div>
                <h2 className="text-xs font-semibold uppercase tracking-wide text-gray-500 mb-2 dark:text-gray-400">
                  Findings — {formatStartedAt(selectedRun.started_at)}
                </h2>
                <FindingsTable profileId={profile.id} runId={selectedRun.id} />
              </div>
            </>
          )}

          {selectedRun && selectedRun.status === 'FAILED' && (
            <div className="rounded-lg border border-red-200 bg-red-50 p-4 dark:border-red-900 dark:bg-red-950">
              <p className="text-sm font-semibold text-red-700 dark:text-red-300">Scan failed</p>
              <p className="text-xs text-red-600 mt-1 dark:text-red-400">{selectedRun.error_message}</p>
            </div>
          )}

          {!streamJobId && !selectedRun && (
            <div className="rounded-xl border border-dashed border-gray-300 p-10 text-center text-sm text-gray-500 dark:border-gray-700 dark:text-gray-400">
              Trigger a scan to see findings here.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
