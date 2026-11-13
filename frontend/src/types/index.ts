export type UserRole = "admin" | "analyst" | "viewer";
export type PriorityMode = "ml_asset" | "deterministic";

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
  final_priority: string;
  priority_source: string;
  rule_priority_tier: string;
  score: number;
  status: string;
  date_found: string | null;
  explanation: ScoringExplanation;
  ml_likelihood: number | null;
  ml_risk: number | null;
  ml_priority: string | null;
  ml_top_reasons: string[] | null;
  ml_model_version: string | null;
  ml_recommended_action: string | null;
  ml_unavailable_reason: string | null;
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
  type: string;
  ip_or_domain: string;
  owner: string;
  environment: string;
  exposure: string;
  criticality: number;
  needs_review: boolean;
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
  total_assets: number;
  open_vulnerabilities: number;
  fixed_this_month: number;
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
  reopened: boolean;
  priority_tier: string;
  final_priority: string;
  priority_source: string;
  rule_priority_tier: string;
  score: number;
  explanation: ScoringExplanation;
  ml_likelihood: number | null;
  ml_risk: number | null;
  ml_priority: string | null;
  ml_top_reasons: string[] | null;
  ml_model_version: string | null;
  ml_recommended_action: string | null;
  ml_unavailable_reason: string | null;
}

export interface ModelResultRow {
  name: string;
  dataset: string;
  pr_auc: number | null;
  pr_auc_stddev: number | null;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  roc_auc: number | null;
  precision_at_k: Record<string, number>;
  recall_at_k: Record<string, number>;
  note: string | null;
}

export interface ModelResults {
  models: ModelResultRow[];
  conclusion: string;
  source_files: string[];
}

export interface ImportPreview {
  detected_format: string;
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
    cvss_score: number | null;
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

export interface CurrentUser {
  id: number;
  username: string;
  role: UserRole;
  priority_mode: PriorityMode;
}

export interface IntelResponse {
  cve_id: string;
  epss: number | null;
  cvss: number | null;
  available: boolean;
  errors: string[];
  description: string | null;
  cvss_vector: string | null;
  cwe: string | null;
  published_date: string | null;
}

export interface StatusUpdate {
  message: string;
  id: number;
  status: string;
}
