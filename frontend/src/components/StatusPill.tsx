import { clsx } from 'clsx'
import type { ScanStatus } from '../api/types'

const palette: Record<ScanStatus, string> = {
  PENDING: 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400',
  RUNNING: 'bg-blue-100 text-blue-700 animate-pulse dark:bg-blue-950 dark:text-blue-300',
  DONE: 'bg-green-100 text-green-700 dark:bg-green-950 dark:text-green-300',
  FAILED: 'bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300',
}

export function StatusPill({ status }: { status: ScanStatus }) {
  return (
    <span
      className={clsx(
        'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium',
        palette[status],
      )}
    >
      {status}
    </span>
  )
}
