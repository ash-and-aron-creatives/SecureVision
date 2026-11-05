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
  date_found: string;
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

export interface ScanResult {
  finding_id: number;
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
  token_type: string;
  role: UserRole;
  username: string;
}

export interface StatusUpdate {
  message: string;
  id: number;
  status: string;
}
