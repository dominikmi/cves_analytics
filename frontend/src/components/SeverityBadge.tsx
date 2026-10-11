import { clsx } from 'clsx'

const palette: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border border-red-200',
  high: 'bg-orange-100 text-orange-800 border border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border border-yellow-200',
  low: 'bg-blue-100 text-blue-800 border border-blue-200',
  negligible: 'bg-gray-100 text-gray-600 border border-gray-200',
  unknown: 'bg-gray-100 text-gray-500 border border-gray-200',
}

export function SeverityBadge({ value }: { value: string | null }) {
  const key = (value ?? 'unknown').toLowerCase()
  return (
    <span
      className={clsx(
        'inline-flex items-center rounded px-1.5 py-0.5 text-xs font-semibold uppercase tracking-wide',
        palette[key] ?? palette.unknown,
      )}
    >
      {value ?? '—'}
    </span>
  )
}
