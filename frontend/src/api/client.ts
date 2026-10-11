import type {
  FindingsPage,
  ProfileCreate,
  ProfileOut,
  ScanRunOut,
  ScanTriggered,
} from './types'

const BASE = '/api'
type ApiId = string | number

async function _json<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`${res.status} ${res.statusText}: ${text}`)
  }
  return res.json() as Promise<T>
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

export async function listProfiles(): Promise<ProfileOut[]> {
  return _json(await fetch(`${BASE}/profiles`))
}

export async function getProfile(id: ApiId): Promise<ProfileOut> {
  return _json(await fetch(`${BASE}/profiles/${id}`))
}

export async function createProfile(body: ProfileCreate): Promise<ProfileOut> {
  return _json(
    await fetch(`${BASE}/profiles`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  )
}

export async function patchProfile(
  id: ApiId,
  body: { image_inventory?: string[] },
): Promise<ProfileOut> {
  return _json(
    await fetch(`${BASE}/profiles/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  )
}

export async function deleteProfile(id: ApiId): Promise<void> {
  const res = await fetch(`${BASE}/profiles/${id}`, { method: 'DELETE' })
  if (!res.ok) throw new Error(`Delete failed: ${res.status}`)
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export async function listScans(profileId: ApiId): Promise<ScanRunOut[]> {
  return _json(await fetch(`${BASE}/profiles/${profileId}/scans`))
}

export async function getScanRun(
  profileId: ApiId,
  runId: ApiId,
): Promise<ScanRunOut> {
  return _json(await fetch(`${BASE}/profiles/${profileId}/scans/${runId}`))
}

export async function deleteScan(profileId: ApiId, runId: ApiId): Promise<void> {
  const res = await fetch(`${BASE}/profiles/${profileId}/scans/${runId}`, {
    method: 'DELETE',
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`${res.status} ${res.statusText}: ${text}`)
  }
}

export async function triggerScan(profileId: ApiId): Promise<ScanTriggered> {
  return _json(
    await fetch(`${BASE}/profiles/${profileId}/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    }),
  )
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export async function getFindings(
  profileId: ApiId,
  runId: ApiId,
  params?: { limit?: number; offset?: number; severity?: string },
): Promise<FindingsPage> {
  const qs = new URLSearchParams()
  if (params?.limit) qs.set('limit', String(params.limit))
  if (params?.offset) qs.set('offset', String(params.offset))
  if (params?.severity) qs.set('severity', params.severity)
  const url = `${BASE}/profiles/${profileId}/scans/${runId}/findings?${qs}`
  return _json(await fetch(url))
}
