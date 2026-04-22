// Shape of content/live/snapshot.json. Authoritative — keep aligned
// with scripts/build-snapshot.mjs output.

export type PolicyStatus =
  | 'compliant'
  | 'warning'
  | 'violation'
  | 'cve-violation'
  | 'malware'
  | 'typosquat'
  | 'insufficient'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown'

export type Ecosystem = 'npm' | 'pypi'

export type ReportRow = {
  package: string
  ecosystem: Ecosystem | string
  installed: string | null
  latest: string | null
  latest_published_at?: string
  kind?: string
  status: PolicyStatus
  message: string
  cve_ids: string[]
  workspace: string
}

export type CveMatch = {
  package: string
  ecosystem: string
  installed: string
  advisory_id: string
  severity: Severity
  fix_version?: string | null
  affected_range?: string | null
}

export type MalwareFinding = {
  package: string
  ecosystem: string
  installed: string
  source: string
  advisory_ref?: string
  summary?: string
}

export type TyposquatFinding = {
  package: string
  ecosystem: string
  evidence: {
    reason: string
    resembles: string
    distance: number
    score: number
  }
  summary: string
}

export type GraphNode = {
  id: string
  ecosystem: string
  name: string
  version: string
  is_root: boolean
  cve_severity: Severity | null
  has_malware: boolean
  has_typosquat: boolean
  compliance: PolicyStatus | null
  is_unresolved: boolean
}

export type GraphEdge = {
  source: string
  target: string
  kind: string
  unresolved: boolean
}

export type Snapshot = {
  scanned_at: string
  packguard_version: string
  target: {
    name: string
    ecosystems: string[]
    package_manager: string
  }
  summary: {
    total_packages: number
    by_status: Record<PolicyStatus, number>
    cve_by_severity: Record<Severity, number>
    malware_confirmed: number
    typosquat_suspects: number
  }
  report: { rows: ReportRow[] }
  audit: {
    cve: {
      matches: CveMatch[]
      summary: Record<Severity, number>
    }
    malware: MalwareFinding[]
    typosquat: TyposquatFinding[]
  }
  graph: {
    nodes: GraphNode[]
    edges: GraphEdge[]
    total_nodes: number
    total_edges: number
    oversize_warning: boolean
  }
}
