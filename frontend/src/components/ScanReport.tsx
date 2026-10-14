import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, Download, ShieldCheck, Skull, Timer } from 'lucide-react'
import { getScanReport } from '../api/client'
import type { ScanReport as ScanReportData } from '../api/types'
import { SeverityBadge } from './SeverityBadge'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'negligible', 'informational', 'unknown']

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  negligible: 'bg-gray-400',
  informational: 'bg-sky-400',
  unknown: 'bg-gray-300',
}

function fmtPct(value: number | null | undefined): string {
  return value == null ? '—' : `${(value * 100).toFixed(1)}%`
}

function fmtDuration(seconds: number | null): string {
  if (seconds == null) return '—'
  const m = Math.floor(seconds / 60)
  const s = Math.round(seconds % 60)
  return m > 0 ? `${m}m ${s}s` : `${s}s`
}

function StatCard({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-lg border border-gray-200 bg-white px-4 py-3 dark:border-gray-700 dark:bg-gray-900">
      <p className="text-[11px] font-semibold uppercase tracking-wide text-gray-400">{label}</p>
      <p className="mt-0.5 text-xl font-bold tabular-nums text-gray-900 dark:text-gray-100">{value}</p>
      {sub && <p className="text-[11px] text-gray-500 dark:text-gray-400">{sub}</p>}
    </div>
  )
}

function DistributionBar({ title, counts }: { title: string; counts: Record<string, number> }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0)
  if (total === 0) return null
  const ordered = Object.entries(counts)
    .map(([k, v]) => [k.toLowerCase(), v] as [string, number])
    .sort(
      (a, b) =>
        (SEVERITY_ORDER.indexOf(a[0]) === -1 ? 99 : SEVERITY_ORDER.indexOf(a[0])) -
        (SEVERITY_ORDER.indexOf(b[0]) === -1 ? 99 : SEVERITY_ORDER.indexOf(b[0])),
    )
  return (
    <div>
      <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-gray-400">{title}</p>
      <div className="flex h-3 w-full overflow-hidden rounded-full bg-gray-100 dark:bg-gray-800">
        {ordered.map(([key, count]) => (
          <div
            key={key}
            className={`${SEVERITY_COLORS[key] ?? 'bg-gray-300'} h-full`}
            style={{ width: `${(count / total) * 100}%` }}
            title={`${key}: ${count}`}
          />
        ))}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-gray-500 dark:text-gray-400">
        {ordered.map(([key, count]) => (
          <span key={key} className="inline-flex items-center gap-1">
            <span className={`h-2 w-2 rounded-full ${SEVERITY_COLORS[key] ?? 'bg-gray-300'}`} />
            <span className="capitalize">{key}</span>
            <span className="tabular-nums font-medium">{count}</span>
          </span>
        ))}
      </div>
    </div>
  )
}

const INTEL_LABELS: Record<string, string> = {
  kev: 'CISA KEV',
  public_exploit: 'Public exploit',
  exploitdb: 'Exploit-DB',
  metasploit: 'Metasploit',
  nuclei: 'Nuclei',
  poc_github: 'PoC on GitHub',
  epss_ge_50pct: 'EPSS ≥ 50%',
}

const LR_LABELS: Record<string, string> = {
  controls: 'Security controls',
  threat: 'Threat intel',
  cvss_vector: 'CVSS vector',
  exposure: 'Exposure',
  criticality: 'Asset criticality',
}

export function ScanReport({ profileId, runId }: { profileId: number; runId: number }) {
  const { data: report } = useQuery<ScanReportData>({
    queryKey: ['scan-report', profileId, runId],
    queryFn: () => getScanReport(profileId, runId),
  })
  if (!report) return null

  const reassessedCritical = report.severity.reassessed['CRITICAL'] ?? 0
  const reassessedHigh = report.severity.reassessed['HIGH'] ?? 0
  const silent = report.coverage.images_without_findings

  function downloadJson() {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `scan-report-profile${report!.profile_id}-run${report!.scan_run_id}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="rounded-xl border border-gray-200 bg-white shadow-sm dark:border-gray-700 dark:bg-gray-900">
      <div className="flex items-center justify-between border-b border-gray-100 px-5 py-3 dark:border-gray-800">
        <h2 className="text-sm font-semibold text-gray-800 dark:text-gray-100">Scan report</h2>
        <button
          onClick={downloadJson}
          className="flex items-center gap-1.5 rounded border border-gray-300 px-2.5 py-1 text-xs text-gray-600 hover:bg-gray-50 transition-colors dark:border-gray-600 dark:text-gray-300 dark:hover:bg-gray-800"
        >
          <Download className="h-3.5 w-3.5" /> Export JSON
        </button>
      </div>

      <div className="space-y-5 p-5">
        {/* KPI strip */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <StatCard label="Findings" value={String(report.totals.findings)} sub={`${report.totals.unique_cves} unique CVEs`} />
          <StatCard label="Reassessed C/H" value={`${reassessedCritical} / ${reassessedHigh}`} sub="critical / high after analysis" />
          <StatCard label="KEV-listed" value={String(report.threat_intel.kev ?? 0)} sub="known-exploited" />
          <StatCard
            label="Images"
            value={`${report.coverage.images_with_findings} / ${report.coverage.images_requested}`}
            sub={`with findings · ran ${fmtDuration(report.duration_seconds)}`}
          />
        </div>

        {/* Failed / silent images */}
        {silent.length > 0 && (
          <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 dark:border-amber-900 dark:bg-amber-950">
            <p className="flex items-center gap-1.5 text-xs font-semibold text-amber-800 dark:text-amber-300">
              <AlertTriangle className="h-3.5 w-3.5" />
              {silent.length} image(s) produced no findings (clean or failed to scan)
            </p>
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {silent.map((img) => (
                <code key={img} className="rounded bg-amber-100 px-1.5 py-0.5 text-[11px] text-amber-900 dark:bg-amber-900 dark:text-amber-200">{img}</code>
              ))}
            </div>
          </div>
        )}

        {/* Severity distributions */}
        <div className="grid gap-4 sm:grid-cols-2">
          <DistributionBar title="Scanner severity" counts={report.severity.scanner} />
          <DistributionBar title="Reassessed severity" counts={report.severity.reassessed} />
        </div>

        {/* Bayesian risk decomposition */}
        {report.risk.available && (
          <div>
            <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-gray-400">
              Bayesian risk — why scores look the way they do
            </p>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
              {(Object.entries(report.risk.avg_likelihood_ratios ?? {}) as [string, number | null][]).map(([key, val]) => (
                <div key={key} className="rounded-lg border border-gray-100 px-3 py-2 dark:border-gray-800">
                  <p className="text-[10px] text-gray-400">{LR_LABELS[key] ?? key}</p>
                  <p className="text-sm font-semibold tabular-nums text-gray-800 dark:text-gray-200">
                    {val == null ? '—' : `LR ${val}`}
                  </p>
                </div>
              ))}
            </div>
            <p className="mt-1.5 text-[11px] text-gray-400">
              LR &lt; 1 suppresses risk, LR &gt; 1 amplifies it. Avg posterior {fmtPct(report.risk.avg_posterior)}, max {fmtPct(report.risk.max_posterior)}.
            </p>
          </div>
        )}

        {/* Threat intel + kill chain */}
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-gray-400">
              <Skull className="mr-1 inline h-3 w-3" />Exploit intelligence
            </p>
            <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
              {Object.entries(report.threat_intel).map(([key, val]) => (
                <div key={key} className="flex justify-between text-gray-600 dark:text-gray-300">
                  <span>{INTEL_LABELS[key] ?? key}</span>
                  <span className="font-medium tabular-nums">{val ?? '—'}</span>
                </div>
              ))}
            </div>
          </div>
          <div>
            <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-gray-400">
              <ShieldCheck className="mr-1 inline h-3 w-3" />Kill chain
            </p>
            <div className="space-y-1 text-xs">
              {report.kill_chain.map((kc) => (
                <div key={kc.phase ?? 'unknown'} className="flex justify-between text-gray-600 dark:text-gray-300">
                  <span className="capitalize">{(kc.phase ?? 'unknown').replace('_', ' ')}</span>
                  <span className="tabular-nums">
                    {kc.count} · {fmtPct(kc.avg_probability)}
                  </span>
                </div>
              ))}
              {report.kill_chain.length === 0 && (
                <p className="text-gray-400">No kill-chain data.</p>
              )}
            </div>
          </div>
        </div>

        {/* Top risks */}
        {report.top_findings.length > 0 && (
          <div>
            <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-gray-400">
              <Timer className="mr-1 inline h-3 w-3" />Highest posterior risk
            </p>
            <div className="divide-y divide-gray-100 rounded-lg border border-gray-100 dark:divide-gray-800 dark:border-gray-800">
              {report.top_findings.map((f, i) => (
                <details key={`${f.cve_id}-${f.image}-${i}`} className="group px-3 py-2">
                  <summary className="flex cursor-pointer list-none items-center gap-3 text-xs select-none">
                    <span className="font-mono font-medium text-violet-700 dark:text-violet-300">{f.cve_id}</span>
                    <span className="truncate text-gray-500 dark:text-gray-400">{f.package}@{f.version} · {f.image}</span>
                    <SeverityBadge value={f.severity ?? null} />
                    <SeverityBadge value={f.risk_category ?? null} />
                    {f.is_kev && <span className="rounded bg-red-100 px-1 text-[10px] font-bold text-red-700 dark:bg-red-950 dark:text-red-300">KEV</span>}
                    <span className="ml-auto shrink-0 tabular-nums font-semibold text-gray-800 dark:text-gray-200">{fmtPct(f.posterior_probability)}</span>
                  </summary>
                  {f.explanation && (
                    <p className="mt-2 rounded bg-gray-50 p-2 font-mono text-[11px] leading-4 text-gray-600 dark:bg-gray-800 dark:text-gray-300">
                      {f.explanation}
                    </p>
                  )}
                </details>
              ))}
            </div>
          </div>
        )}

        {/* Top CWEs */}
        {report.top_cwes.length > 0 && (
          <div>
            <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-gray-400">Top weakness classes</p>
            <div className="flex flex-wrap gap-1.5">
              {report.top_cwes.map((c) => (
                <span key={c.cwe_id} className="rounded bg-gray-100 px-2 py-0.5 font-mono text-[11px] text-gray-600 dark:bg-gray-800 dark:text-gray-300">
                  {c.cwe_id} ({c.count})
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
