from datetime import date, datetime
from typing import Any, Literal

import ipaddress
import re
from pydantic import BaseModel, ConfigDict, Field, field_validator
from backend.rules_config import (
    ASSET_DEFAULT_ENVIRONMENT,
    ASSET_DEFAULT_EXPOSURE,
    ASSET_DEFAULT_TYPE,
    ASSET_ENVIRONMENTS,
    ASSET_EXPOSURES,
    ASSET_IP_OR_DOMAIN_MAX_LENGTH,
    ASSET_NAME_MAX_LENGTH,
    ASSET_OWNER_MAX_LENGTH,
    ASSET_TYPES,
)


class ResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class UserResponse(ResponseSchema):
    id: int
    username: str
    role: str
    is_active: bool


class CurrentUserResponse(UserResponse):
    priority_mode: Literal["ml_asset", "deterministic"]
    ml_warmup_state: Literal["starting", "ready", "failed"]


class AssetRequest(BaseModel):
    name: str = Field(min_length=1, max_length=ASSET_NAME_MAX_LENGTH)
    type: str = ASSET_DEFAULT_TYPE
    ip_or_domain: str = Field(default="", max_length=ASSET_IP_OR_DOMAIN_MAX_LENGTH)
    owner: str = Field(default="", max_length=ASSET_OWNER_MAX_LENGTH)
    environment: str = ASSET_DEFAULT_ENVIRONMENT
    exposure: str = ASSET_DEFAULT_EXPOSURE
    criticality: int = Field(default=3, ge=1, le=5)

    @field_validator("name", "ip_or_domain", "owner", "environment", "type", "exposure")
    @classmethod
    def clean_text(cls, value: str) -> str:
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Text fields cannot contain control characters.")
        return value.strip()

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not value:
            raise ValueError("name is required.")
        return value

    @field_validator("type")
    @classmethod
    def validate_type(cls, value: str) -> str:
        if value not in ASSET_TYPES:
            raise ValueError(f"type must be one of: {', '.join(ASSET_TYPES)}.")
        return value

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, value: str) -> str:
        if value not in ASSET_ENVIRONMENTS:
            raise ValueError(f"environment must be one of: {', '.join(ASSET_ENVIRONMENTS)}.")
        return value

    @field_validator("exposure")
    @classmethod
    def validate_exposure(cls, value: str) -> str:
        exposure = ASSET_EXPOSURES.get(value.casefold())
        if exposure is None:
            raise ValueError("exposure must be Internet or Internal.")
        return exposure

    @field_validator("ip_or_domain")
    @classmethod
    def validate_ip_or_domain(cls, value: str) -> str:
        if not value:
            return value
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            pass
        if len(value) > ASSET_IP_OR_DOMAIN_MAX_LENGTH or not re.fullmatch(
            r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*",
            value,
        ):
            raise ValueError("ip_or_domain must be a valid IP address or hostname.")
        return value


class TokenResponse(ResponseSchema):
    access_token: str
    token_type: Literal["bearer"]
    role: Literal["admin", "analyst", "viewer"]
    username: str


class IntelResponse(ResponseSchema):
    cve_id: str
    epss: float | None
    epss_percentile: float | None = None
    cvss: float | None
    available: bool
    errors: list[str]
    description: str | None = None
    cvss_vector: str | None = None
    cwe: str | None = None
    published_date: str | None = None


class MLFieldsResponse(ResponseSchema):
    ml_likelihood: float | None = None
    ml_risk: float | None = None
    ml_priority: str | None = None
    ml_top_reasons: list[str] | None = None
    ml_model_version: str | None = None
    ml_recommended_action: str | None = None
    ml_unavailable_reason: str | None = None


class DeletedUserResponse(ResponseSchema):
    deleted: int
    username: str


class AssetResponse(ResponseSchema):
    id: int
    name: str
    type: str
    ip_or_domain: str
    owner: str
    environment: str
    exposure: str
    criticality: int
    needs_review: bool


class CVEResponse(ResponseSchema):
    cve_id: str
    source: str
    published_date: str | None = None
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwe: str | None = None
    kev_date_added: str | None = None
    epss: float | None = None
    percentile: float | None = None
    in_kev: bool | None = None


class DeletedAssetResponse(ResponseSchema):
    deleted: int
    name: str


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


class FindingResponse(MLFieldsResponse):
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
    final_priority: str
    recommended_action: str
    priority_source: str
    rule_priority_tier: str
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
    total_assets: int
    open_vulnerabilities: int
    fixed_this_month: int
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


class ModelResultRowResponse(ResponseSchema):
    name: str
    dataset: str
    pr_auc: float | None
    pr_auc_stddev: float | None
    precision: float | None
    recall: float | None
    f1: float | None
    roc_auc: float | None
    precision_at_k: dict[str, float]
    recall_at_k: dict[str, float]
    note: str | None


class ModelResultsResponse(ResponseSchema):
    models: list[ModelResultRowResponse]
    conclusion: str
    source_files: list[str]


class AssetSummaryResponse(ResponseSchema):
    id: int | None
    name: str
    type: str
    ip_or_domain: str
    owner: str
    environment: str
    exposure: str
    criticality: int


class ScoreHistoryResponse(MLFieldsResponse):
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


class FindingDetailResponse(MLFieldsResponse):
    id: int
    cve_id: str
    status: str
    date_found: str | None
    cvss_score: float
    in_kev: bool
    asset: AssetSummaryResponse
    priority_tier: str
    final_priority: str
    recommended_action: str
    priority_source: str
    rule_priority_tier: str
    score: int
    likelihood: float
    explanation: ScoringExplanationResponse
    provenance: Any
    score_history: list[ScoreHistoryResponse]
    audit_trail: list[AuditEntryResponse]


class ScanResultResponse(MLFieldsResponse):
    finding_id: int
    action: Literal["created", "updated"]
    reopened: bool
    priority_tier: str
    final_priority: str
    recommended_action: str
    priority_source: str
    rule_priority_tier: str
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
    cvss_score: float | None


class ImportPreviewResponse(ResponseSchema):
    detected_format: str
    summary: ImportSummaryResponse
    rows: list[ImportRowResponse]


class ImportCommitResponse(ResponseSchema):
    imported: int
    skipped: int
    problems_csv: str
