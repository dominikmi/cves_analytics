import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { PlusCircle, Trash2, ChevronRight } from 'lucide-react'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { createProfile, deleteProfile, listProfiles } from '../api/client'
import type { Industry, OrgReach, OrgSize, Environment, ProfileCreate } from '../api/types'

const DEFAULT_FORM: ProfileCreate & { images_raw: string } = {
  name: '',
  org_size: 'mid',
  org_reach: 'regional',
  industry: 'financial-services',
  environment: 'prod',
  security_maturity: 0.4,
  images_raw: '',
}

const MATURITY_OPTIONS = [
  { value: 0.0, label: 'initial' },
  { value: 0.2, label: 'developing' },
  { value: 0.4, label: 'defined' },
  { value: 0.6, label: 'managed' },
  { value: 0.8, label: 'optimizing' },
]

export function ProfilesPage() {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState<typeof DEFAULT_FORM>(DEFAULT_FORM)

  const { data: profiles = [], isLoading } = useQuery({
    queryKey: ['profiles'],
    queryFn: listProfiles,
    refetchInterval: 10_000,
  })

  const createMut = useMutation({
    mutationFn: createProfile,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['profiles'] })
      setShowForm(false)
      setForm(DEFAULT_FORM)
    },
  })

  const deleteMut = useMutation({
    mutationFn: deleteProfile,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['profiles'] }),
  })

  function field<K extends keyof typeof DEFAULT_FORM>(key: K, value: (typeof DEFAULT_FORM)[K]) {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  function buildPayload(): ProfileCreate {
    const images = form.images_raw
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean)
    return {
      name: form.name,
      org_size: form.org_size,
      org_reach: form.org_reach,
      industry: form.industry,
      environment: form.environment,
      security_maturity: form.security_maturity,
      image_inventory: images,
    }
  }

  return (
    <div className="p-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Environment Profiles</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
            Each profile represents a persistent environment definition for temporal tracking.
          </p>
        </div>
        <button
          onClick={() => setShowForm((v) => !v)}
          className="flex items-center gap-2 rounded-lg bg-violet-600 px-4 py-2 text-sm font-medium text-white hover:bg-violet-700 transition-colors"
        >
          <PlusCircle className="w-4 h-4" />
          New Profile
        </button>
      </div>

      {/* Create form */}
      {showForm && (
        <div className="mb-6 rounded-xl border border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-900 p-5 shadow-sm">
          <h2 className="text-base font-semibold text-gray-800 dark:text-gray-200 mb-4">Create Profile</h2>
          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Name</label>
              <input
                type="text"
                value={form.name}
                onChange={(e) => field('name', e.target.value)}
                className="w-full rounded-md border border-gray-300 dark:border-gray-600 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-violet-500 dark:bg-gray-800 dark:text-gray-100"
                placeholder="e.g. prod-ecommerce-eu"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Org Size</label>
              <select
                value={form.org_size}
                onChange={(e) => field('org_size', e.target.value as OrgSize)}
                className="w-full rounded-md border border-gray-300 dark:border-gray-600 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-violet-500 dark:bg-gray-800 dark:text-gray-100"
              >
                {(['small', 'mid', 'large'] as OrgSize[]).map((v) => (
                  <option key={v} value={v}>{v}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Org Reach</label>
              <select
                value={form.org_reach}
                onChange={(e) => field('org_reach', e.target.value as OrgReach)}
                className="w-full rounded-md border border-gray-300 dark:border-gray-600 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-violet-500 dark:bg-gray-800 dark:text-gray-100"
              >
                {(['local', 'regional', 'global'] as OrgReach[]).map((v) => (
                  <option key={v} value={v}>{v}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Industry</label>
              <select
                value={form.industry}
                onChange={(e) => field('industry', e.target.value as Industry)}
                className="w-full rounded-md border border-gray-300 dark:border-gray-600 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-violet-500 dark:bg-gray-800 dark:text-gray-100"
              >
                {(['on-line-store', 'financial-services', 'consulting'] as Industry[]).map((v) => (
                  <option key={v} value={v}>{v}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Environment</label>
              <select
                value={form.environment}
                onChange={(e) => field('environment', e.target.value as Environment)}
                className="w-full rounded-md border border-gray-300 dark:border-gray-600 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-violet-500 dark:bg-gray-800 dark:text-gray-100"
              >
                {(['dev', 'test', 'qa', 'stage', 'prod'] as Environment[]).map((v) => (
                  <option key={v} value={v}>{v}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Security Maturity</label>
              <select
                value={form.security_maturity}
                onChange={(e) => field('security_maturity', Number(e.target.value))}
                className="w-full rounded-md border border-gray-300 dark:border-gray-600 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-violet-500 dark:bg-gray-800 dark:text-gray-100"
              >
                {MATURITY_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>{option.label}</option>
                ))}
              </select>
            </div>
          </div>
          {/* Image inventory */}
          <div className="col-span-2 mt-1">
            <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">
              Container Images <span className="font-normal text-gray-400">(one per line or comma-separated)</span>
            </label>
            <textarea
              value={form.images_raw}
              onChange={(e) => field('images_raw', e.target.value)}
              rows={3}
              className="w-full rounded-md border border-gray-300 dark:border-gray-600 px-3 py-1.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-violet-500 dark:bg-gray-800 dark:text-gray-100"
              placeholder="nginx:latest&#10;redis:7&#10;postgres:15"
            />
          </div>
          <div className="flex gap-2 mt-4">
            <button
              disabled={!form.name || createMut.isPending}
              onClick={() => createMut.mutate(buildPayload())}
              className="rounded-md bg-violet-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-violet-700 disabled:opacity-50 transition-colors"
            >
              {createMut.isPending ? 'Creating…' : 'Create'}
            </button>
            <button
              onClick={() => setShowForm(false)}
              className="rounded-md border border-gray-300 dark:border-gray-600 px-4 py-1.5 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
            >
              Cancel
            </button>
          </div>
          {createMut.isError && (
            <p className="mt-2 text-xs text-red-600 dark:text-red-400">{String(createMut.error)}</p>
          )}
        </div>
      )}

      {/* Profile list */}
      {isLoading ? (
        <p className="text-sm text-gray-500 dark:text-gray-400">Loading profiles…</p>
      ) : profiles.length === 0 ? (
        <div className="rounded-xl border border-dashed border-gray-300 p-10 text-center text-sm text-gray-500 dark:text-gray-400">
          No profiles yet. Create one to start scanning.
        </div>
      ) : (
        <div className="space-y-3">
          {profiles.map((p) => (
            <div
              key={p.id}
              className="flex items-center justify-between rounded-xl border border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-900 px-5 py-4 shadow-sm hover:border-violet-300 dark:hover:border-violet-700 transition-colors"
            >
              <button
                className="flex-1 text-left"
                onClick={() => navigate(`/profiles/${p.id}`)}
              >
                <div className="flex items-center gap-3">
                  <div>
                    <p className="font-semibold text-gray-900 dark:text-gray-100">{p.name}</p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                      {p.industry} · {p.environment} · {p.org_size} · {p.org_reach}
                    </p>
                  </div>
                  <div className="ml-auto flex items-center gap-4 mr-2">
                    <div className="text-center">
                      <p className="text-lg font-bold text-gray-800 dark:text-gray-200">{p.total_scans}</p>
                      <p className="text-xs text-gray-500 dark:text-gray-400">scans</p>
                    </div>
                  </div>
                </div>
              </button>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => navigate(`/profiles/${p.id}`)}
                  className="p-1.5 text-gray-400 dark:text-gray-500 hover:text-violet-600 dark:hover:text-violet-400 transition-colors"
                  title="View profile"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
                <button
                  onClick={() => {
                    if (confirm(`Delete profile "${p.name}"?`)) deleteMut.mutate(p.id)
                  }}
                  className="p-1.5 text-gray-400 dark:text-gray-500 hover:text-red-500 dark:hover:text-red-400 transition-colors"
                  title="Delete profile"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
