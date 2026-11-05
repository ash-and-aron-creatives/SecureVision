from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


class ResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class UserResponse(ResponseSchema):
    id: int
    username: str
    role: str


class TokenResponse(ResponseSchema):
    access_token: str
    token_type: Literal["bearer"]
    role: Literal["admin", "analyst", "viewer"]
    username: str


class IntelResponse(ResponseSchema):
    cve_id: str
    epss: float | None
    cvss: float | None
    available: bool
    errors: list[str]


class DeletedUserResponse(ResponseSchema):
    deleted: int
    username: str


class AssetResponse(ResponseSchema):
    id: int
    name: str
    exposure: str
    criticality: int


class ScoringInputsResponse(ResponseSchema):
    in_kev: bool
    internet_facing: bool
    criticality: int
    epss_percentile: float | None
    cvss_score: float | None


class ScoringExplanationResponse(ResponseSchema):
    summary: str
    inputs: ScoringInputsResponse
    rationale: list[str]


class FindingResponse(ResponseSchema):
    id: int
    cve_id: str
    asset_id: int
    asset_name: str
    exposure: str
    criticality: int
    cvss_score: float
    epss: float
    in_kev: bool
    priority_tier: str
    score: int
    status: str
    date_found: str | None
    explanation: ScoringExplanationResponse


class FindingsPageResponse(ResponseSchema):
    items: list[FindingResponse]
    total: int
    page: int
    page_size: int
    pages: int
    counts: dict[str, int]


class DashboardActivityDayResponse(ResponseSchema):
    date: date
    ingested_count: int
    resolved_count: int


class DashboardAnalyticsResponse(ResponseSchema):
    total_findings: int
    resolved_findings: int
    mitigation_pct: float | None
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    open_critical_count: int
    open_high_count: int
    open_medium_count: int
    open_low_count: int
    mean_time_to_triage_hours: float | None
    sla_compliance_pct: float | None
    weekly_activity: list[DashboardActivityDayResponse]
    ingestion_has_history: bool


class AssetSummaryResponse(ResponseSchema):
    id: int | None
    name: str
    exposure: str
    criticality: int


class ScoreHistoryResponse(ResponseSchema):
    id: int
    provider_id: int
    priority_tier: str
    score: int
    likelihood: float
    explanation: ScoringExplanationResponse
    provenance: Any


class AuditEntryResponse(ResponseSchema):
    id: int
    user: str
    action: str
    details: str
    timestamp: datetime | None


class FindingDetailResponse(ResponseSchema):
    id: int
    cve_id: str
    status: str
    date_found: str | None
    cvss_score: float
    in_kev: bool
    asset: AssetSummaryResponse
    priority_tier: str
    score: int
    likelihood: float
    explanation: ScoringExplanationResponse
    provenance: Any
    score_history: list[ScoreHistoryResponse]
    audit_trail: list[AuditEntryResponse]


class ScanResultResponse(ResponseSchema):
    finding_id: int
    priority_tier: str
    score: int
    explanation: ScoringExplanationResponse


class StatusUpdateResponse(ResponseSchema):
    message: str
    id: int
    status: str


class ImportSummaryResponse(ResponseSchema):
    total: int
    ok: int
    error: int
    duplicate: int


class ImportRowResponse(ResponseSchema):
    line: int
    asset_name: str
    cve_id: str
    date_found: str
    status: str
    reason: str
    asset_id: int | None


class ImportPreviewResponse(ResponseSchema):
    summary: ImportSummaryResponse
    rows: list[ImportRowResponse]


class ImportCommitResponse(ResponseSchema):
    imported: int
    skipped: int
    problems_csv: str
