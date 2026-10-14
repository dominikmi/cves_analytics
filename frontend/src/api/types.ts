// ---------------------------------------------------------------------------
// API types — mirror the Pydantic schemas from src/api/schemas/
// ---------------------------------------------------------------------------

export type OrgSize = 'small' | 'mid' | 'large'
export type OrgReach = 'local' | 'regional' | 'global'
export type Industry = 'on-line-store' | 'financial-services' | 'consulting'
export type Environment = 'dev' | 'test' | 'qa' | 'stage' | 'prod'
export type ScanStatus = 'PENDING' | 'RUNNING' | 'DONE' | 'FAILED'

export interface ProfileCreate {
  name: string
  org_size: OrgSize
  org_reach: OrgReach
  industry: Industry
  environment: Environment
  security_maturity?: number
  image_inventory?: string[]
}

export interface ControlsSnapshot {
  network_segmentation?: boolean
  firewall?: boolean
  waf?: boolean
  ids_ips?: boolean
  edr_xdr?: boolean
  antivirus?: boolean
  mfa?: boolean
  privileged_access_mgmt?: boolean
  siem?: boolean
  soc_24x7?: boolean
  incident_response_plan?: boolean
  security_training?: boolean
  air_gapped?: boolean
  patch_management?: string
  [key: string]: boolean | string | undefined
}

export interface ProfileOut {
  id: number
  name: string
  org_size: string
  org_reach: string
  industry: string
  environment: string
  security_maturity: number
  controls_snapshot: ControlsSnapshot
  image_inventory: string[]
  created_at: string
  updated_at: string
  total_scans: number
}

export interface ScanRunOut {
  id: number
  profile_id: number
  status: ScanStatus
  job_id: string | null
  started_at: string | null
  completed_at: string | null
  epss_vintage: string | null
  cve_vintage: string | null
  severity_counts: Record<string, number> | null
  avg_bayesian_risk: number | null
  error_message: string | null
  report_path: string | null
}

export type ScanTriggered = ScanRunOut

export interface FindingRow {
  id: string
  profile_id: number
  scan_run_id: number
  cve_id: string | null
  image_name: string | null
  image_tag: string | null
  service_name: string | null
  severity: string | null
  severity_reassessed: string | null
  cvss_score: number | null
  cvss_vector: string | null
  cvss_version: string | null
  epss_score: number | null
  epss_percentile: number | null
  epss_vintage_date: string | null
  epss_snapshotted_at: string | null
  bayesian_risk: number | null
  bayesian_risk_low: number | null
  bayesian_risk_high: number | null
  is_kev: boolean | null
  cwe_id: string | null
  description: string | null
  status: string
  reassessment_reason: string | null
}

export interface FindingsPage {
  items: FindingRow[]
  total: number
  limit: number
  offset: number
  scan_run_id: number
}

export interface ImageStats {
  image: string
  total: number
  critical: number
  high: number
  medium: number
  low: number
  negligible: number
  avg_risk: number | null
  kev: number
}

export interface ScenarioService {
  name: string
  role: string
  image?: string
  zone?: string
  misconfigurations?: string[]
  hardcoded_secrets?: unknown[]
  [key: string]: unknown
}

export interface Scenario {
  scenario_id: string
  company_name?: string
  metadata?: {
    size?: string
    reach?: string
    industry?: string
    environment?: string
    topology?: string
  }
  network_zones?: string[]
  services?: ScenarioService[]
  [key: string]: unknown
}

export interface ScanReport {
  scan_run_id: number
  profile_id: number
  profile_name: string
  status: string
  started_at: string | null
  completed_at: string | null
  duration_seconds: number | null
  epss_vintage: string | null
  cve_vintage: string | null
  coverage: {
    images_requested: number
    images_with_findings: number
    images_without_findings: string[]
  }
  totals: { findings: number; unique_cves: number }
  severity: {
    scanner: Record<string, number>
    reassessed: Record<string, number>
  }
  risk: {
    available: boolean
    avg_posterior?: number | null
    max_posterior?: number | null
    avg_likelihood_ratios?: Record<string, number | null>
  }
  threat_intel: Record<string, number | null>
  kill_chain: { phase: string | null; count: number; avg_probability: number | null }[]
  top_findings: TopFinding[]
  top_cwes: { cwe_id: string; count: number }[]
  per_image: ImageStats[]
}

export interface TopFinding {
  cve_id?: string
  image?: string
  package?: string
  version?: string
  severity?: string
  risk_category?: string
  posterior_probability?: number
  epss_score?: number
  is_kev?: boolean
  explanation?: string
}

export type FindingsSort =
  | 'cve'
  | 'image'
  | 'service'
  | 'severity'
  | 'reassessed'
  | 'cvss'
  | 'epss'
  | 'risk'
  | 'kev'
export type SortOrder = 'asc' | 'desc'

export type SSEEvent =
  | { type: 'log'; level: string; message: string; ts: string }
  | {
      type: 'progress'
      message: string
      stage?: string
      current?: number
      total?: number
      image?: string
      image_phase?: string
    }
  | { type: 'done'; status?: string }
  | { type: 'complete' }
  | { type: 'error'; message: string }
