export type UserRole = "admin" | "analyst" | "viewer";

export interface Finding {
  id: number;
  cve_id: string;
  asset_id: number;
  asset_name: string;
  exposure: string;
  criticality: number;
  cvss_score: number;
  epss: number;
  in_kev: boolean;
  priority_tier: string;
  score: number;
  status: string;
  date_found: string | null;
  explanation: ScoringExplanation;
}

export interface ScoringExplanation {
  summary: string;
  inputs: {
    in_kev: boolean;
    internet_facing: boolean;
    criticality: number;
    epss_percentile: number | null;
    cvss_score: number | null;
  };
  rationale: string[];
}

export interface Asset {
  id: number;
  name: string;
  exposure: string;
  criticality: number;
}

export interface AuditEntry {
  id: number;
  user: string;
  action: string;
  details: string;
  timestamp: string | null;
}

export interface UserItem {
  id: number;
  username: string;
  role: UserRole;
}

export interface FindingsPage {
  items: Finding[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
  counts: Record<string, number>;
}

export interface DashboardActivityDay {
  date: string;
  ingested_count: number;
  resolved_count: number;
}

export interface DashboardAnalytics {
  total_findings: number;
  resolved_findings: number;
  mitigation_pct: number | null;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  open_critical_count: number;
  open_high_count: number;
  open_medium_count: number;
  open_low_count: number;
  mean_time_to_triage_hours: number | null;
  sla_compliance_pct: number | null;
  weekly_activity: DashboardActivityDay[];
  ingestion_has_history: boolean;
}

export interface ScanResult {
  finding_id: number;
  action: "created" | "updated";
  priority_tier: string;
  score: number;
  explanation: ScoringExplanation;
}

export interface ImportPreview {
  summary: {
    total: number;
    ok: number;
    error: number;
    duplicate: number;
  };
  rows: Array<{
    line: number;
    asset_name: string;
    cve_id: string;
    date_found: string;
    status: string;
    reason: string;
    asset_id: number | null;
  }>;
}

export interface ImportCommit {
  imported: number;
  skipped: number;
  problems_csv: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: "bearer";
  role: UserRole;
  username: string;
}

export interface IntelResponse {
  cve_id: string;
  epss: number | null;
  cvss: number | null;
  available: boolean;
  errors: string[];
}

export interface StatusUpdate {
  message: string;
  id: number;
  status: string;
}
