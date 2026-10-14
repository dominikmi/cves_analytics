import { Globe, AlertTriangle, Box } from 'lucide-react'
import type { Scenario, ScenarioService } from '../api/types'

// Preferred left-to-right zone flow: edge -> app -> data -> internal.
const ZONE_ORDER = ['dmz', 'app_tier', 'data_tier', 'internal', 'flat_network']

const ZONE_LABELS: Record<string, string> = {
  dmz: 'DMZ',
  app_tier: 'App Tier',
  data_tier: 'Data Tier',
  internal: 'Internal',
  flat_network: 'Flat Network',
}

function ServiceNode({ service }: { service: ScenarioService }) {
  const warnings =
    (service.misconfigurations?.length ?? 0) +
    (service.hardcoded_secrets?.length ?? 0)
  return (
    <div
      title={service.image ?? service.role}
      className="rounded-md border border-gray-200 bg-gray-50 px-2 py-1.5 dark:border-gray-700 dark:bg-gray-800"
    >
      <div className="flex items-center gap-1.5">
        <Box className="w-3 h-3 shrink-0 text-violet-500" />
        <span className="truncate text-xs font-medium text-gray-800 dark:text-gray-200">
          {service.name}
        </span>
        {warnings > 0 && (
          <AlertTriangle
            className="ml-auto w-3 h-3 shrink-0 text-amber-500"
            aria-label={`${warnings} issue(s)`}
          />
        )}
      </div>
      <p className="mt-0.5 truncate font-mono text-[10px] text-gray-400 dark:text-gray-500">
        {service.image ?? service.role}
      </p>
    </div>
  )
}

export function EnvironmentDiagram({ scenario }: { scenario: Scenario }) {
  const services = scenario.services ?? []
  const zones = [...(scenario.network_zones ?? [])].sort(
    (a, b) =>
      (ZONE_ORDER.indexOf(a) === -1 ? 99 : ZONE_ORDER.indexOf(a)) -
      (ZONE_ORDER.indexOf(b) === -1 ? 99 : ZONE_ORDER.indexOf(b)),
  )
  const byZone = new Map<string, ScenarioService[]>()
  for (const s of services) {
    const zone = s.zone ?? 'flat_network'
    byZone.set(zone, [...(byZone.get(zone) ?? []), s])
  }
  const unzoned = byZone.get('flat_network') ?? []
  const flatOnly = zones.length === 0 || zones.includes('flat_network')

  return (
    <div className="overflow-x-auto rounded-xl border border-gray-200 bg-white p-5 shadow-sm dark:border-gray-700 dark:bg-gray-900">
      <div className="mb-4 flex items-center justify-between">
        <p className="text-xs font-semibold uppercase tracking-wide text-gray-400 dark:text-gray-500">
          Environment — {scenario.metadata?.topology ?? 'unknown'} topology
        </p>
        <p className="text-xs text-gray-400 dark:text-gray-500">
          {services.length} services
        </p>
      </div>

      <div className="flex items-stretch gap-4">
        {/* Internet edge */}
        <div className="flex w-24 shrink-0 flex-col items-center justify-center gap-1 rounded-lg border-2 border-dashed border-gray-300 text-gray-400 dark:border-gray-600 dark:text-gray-500">
          <Globe className="w-6 h-6" />
          <span className="text-[10px] font-semibold uppercase">Internet</span>
        </div>
        <div className="self-center text-gray-300 dark:text-gray-600">→</div>

        {/* Zone lanes */}
        <div className="flex flex-1 gap-4">
          {flatOnly ? (
            <div className="flex-1 rounded-lg border border-gray-200 bg-gray-50/50 p-3 dark:border-gray-700 dark:bg-gray-800/50">
              <p className="mb-2 text-[10px] font-bold uppercase tracking-wider text-gray-400 dark:text-gray-500">
                {ZONE_LABELS.flat_network}
              </p>
              <div className="grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-4">
                {services.map((s) => (
                  <ServiceNode key={s.name} service={s} />
                ))}
              </div>
            </div>
          ) : (
            zones.map((zone) => (
              <div
                key={zone}
                className="min-w-[160px] flex-1 rounded-lg border border-gray-200 bg-gray-50/50 p-3 dark:border-gray-700 dark:bg-gray-800/50"
              >
                <p className="mb-2 text-[10px] font-bold uppercase tracking-wider text-gray-400 dark:text-gray-500">
                  {ZONE_LABELS[zone] ?? zone}
                </p>
                <div className="space-y-1.5">
                  {(byZone.get(zone) ?? []).map((s) => (
                    <ServiceNode key={s.name} service={s} />
                  ))}
                  {(byZone.get(zone) ?? []).length === 0 && (
                    <p className="text-[10px] italic text-gray-300 dark:text-gray-600">
                      no services
                    </p>
                  )}
                </div>
              </div>
            ))
          )}
          {!flatOnly && unzoned.length > 0 && (
            <div className="min-w-[160px] flex-1 rounded-lg border border-gray-200 p-3 dark:border-gray-700">
              <p className="mb-2 text-[10px] font-bold uppercase tracking-wider text-gray-400">
                Unzoned
              </p>
              <div className="space-y-1.5">
                {unzoned.map((s) => (
                  <ServiceNode key={s.name} service={s} />
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
