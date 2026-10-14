import { clsx } from 'clsx'

const palette: Record<string, string> = {
  critical:
    'bg-red-100 text-red-800 border border-red-200 dark:bg-red-950 dark:text-red-300 dark:border-red-800',
  high: 'bg-orange-100 text-orange-800 border border-orange-200 dark:bg-orange-950 dark:text-orange-300 dark:border-orange-800',
  medium:
    'bg-yellow-100 text-yellow-800 border border-yellow-200 dark:bg-yellow-950 dark:text-yellow-300 dark:border-yellow-800',
  low: 'bg-blue-100 text-blue-800 border border-blue-200 dark:bg-blue-950 dark:text-blue-300 dark:border-blue-800',
  negligible:
    'bg-gray-100 text-gray-600 border border-gray-200 dark:bg-gray-800 dark:text-gray-400 dark:border-gray-700',
  informational:
    'bg-sky-100 text-sky-700 border border-sky-200 dark:bg-sky-950 dark:text-sky-300 dark:border-sky-800',
  unknown:
    'bg-gray-100 text-gray-500 border border-gray-200 dark:bg-gray-800 dark:text-gray-500 dark:border-gray-700',
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
