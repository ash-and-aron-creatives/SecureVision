from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import case, func, or_
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, aliased
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool
import hashlib
import csv
import io
import json
import logging
import os
import re
import threading
import time
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone

from backend import models, auth
from backend.database import get_db
from backend.ml_inference import (
    get_warmup_state,
    mark_warmup_failed,
    predict_exploit_likelihood,
    warm_up_model,
)
from backend.cve_dataset import lookup_catalog, lookup_cve_intel, search_catalog
from backend.rules_config import (
    CVE_SEARCH_MAX_RESULTS,
    LOGIN_USERNAME_MAX_LENGTH,
    PRIORITY_MODE,
    recommended_action_for_priority,
)
from backend.scoring_engine import TIER_SCORES, calculate_priority, resolve_final_priority
from backend.threat_intel import fetch_cve_data
from backend.csv_import import MAX_BYTES, ImportFileError, detect_format, parse_and_validate, problems_to_csv
from backend.model_results import read_model_results
from backend.reports import router as reports_router
from backend.users import router as users_router
from backend.schemas import (
    AssetResponse,
    AssetRequest,
    AuditEntryResponse,
    CVEResponse,
    CurrentUserResponse,
    DeletedAssetResponse,
    DashboardAnalyticsResponse,
    FindingDetailResponse,
    FindingsPageResponse,
    IntelResponse,
    ImportCommitResponse,
    ImportPreviewResponse,
    ModelResultsResponse,
    ScanResultResponse,
    StatusUpdateResponse,
    TokenResponse,
    UserResponse,
)

_LOGGER = logging.getLogger(__name__)


def start_ml_warmup() -> None:
    try:
        worker = threading.Thread(
            target=warm_up_model,
            name="ml-model-warmup",
            daemon=True,
        )
        worker.start()
    except Exception:
        mark_warmup_failed()
        _LOGGER.exception("Could not start the ML warm-up thread.")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    start_ml_warmup()
    yield


app = FastAPI(title="SecureVision Backend API", lifespan=lifespan)
cors_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "").split(",")
    if origin.strip()
]
if "*" in cors_origins:
    raise RuntimeError("CORS_ORIGINS must contain explicit origins, not '*'.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "X-Content-SHA256", "X-Row-Count"],
)
app.include_router(reports_router)
app.include_router(users_router)

TIER_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
VALID_STATUSES = {"Open", "In Progress", "Resolved"}
CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
STATUS_CHANGE_PATTERN = re.compile(
    r"^finding_id=(\d+)\b.* status changed from (Open|In Progress|Resolved) "
    r"to (Open|In Progress|Resolved)$"
)
IMPORT_COUNT_PATTERN = re.compile(r"\bimported=(\d+)\s+skipped=\d+(?:\s+finding_ids=[\d,]+)?$")
IMPORT_FINDING_IDS_PATTERN = re.compile(r"\bfinding_ids=([\d,]+)$")
_DUMMY_PASSWORD_HASH = auth.get_password_hash("securevision-invalid-login-placeholder")


def _stored_score(score: models.FindingScore | None, tier: str) -> int:
    if score and isinstance(score.provenance, dict) and "score" in score.provenance:
        return int(score.provenance["score"])
    return TIER_SCORES.get(tier, 0)


def _stored_explanation(
    score: models.FindingScore | None,
    finding: models.Finding,
    asset: models.Asset | None,
) -> dict:
    if score and isinstance(score.provenance, dict):
        explanation = score.provenance.get("scoring_explanation")
        if explanation:
            return explanation

    return {
        "summary": score.explanation if score and score.explanation else "No scoring explanation recorded.",
        "inputs": {
            "in_kev": bool(finding.in_kev),
            "internet_facing": bool(asset and (asset.exposure or "").lower() == "internet"),
            "criticality": int(asset.criticality) if asset and asset.criticality is not None else 1,
            "epss_percentile": float(score.likelihood) if score and score.likelihood is not None else None,
            "cvss_score": float(finding.cvss_score) if finding.cvss_score is not None else None,
        },
        "rationale": [],
    }


def _ml_score_fields(score: models.FindingScore | None) -> dict:
    return {
        "ml_likelihood": score.ml_likelihood if score else None,
        "ml_risk": score.ml_risk if score else None,
        "ml_priority": score.ml_priority if score else None,
        "ml_top_reasons": score.ml_top_reasons if score else None,
        "ml_model_version": score.ml_model_version if score else None,
        "ml_recommended_action": score.ml_recommended_action if score else None,
        "ml_unavailable_reason": score.ml_unavailable_reason if score else None,
    }


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _asset_identifier_map(assets: list[models.Asset]) -> dict[str, int]:
    identifiers = {}
    for asset in assets:
        for value in (asset.name, asset.ip_or_domain):
            normalized = (value or "").strip().casefold()
            if normalized:
                identifiers.setdefault(normalized, asset.id)
    return identifiers


class ScanRequest(BaseModel):
    asset_id: int
    cve_id: str
    cvss_score: float | None = None
    in_kev: bool = False
    epss_percentile: float | None = None

class StatusUpdateRequest(BaseModel):
    status: str

@app.post("/token", response_model=TokenResponse)
def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    client_ip = request.client.host if request.client else "unknown"
    user = (
        db.query(models.User)
        .filter(models.User.username == form_data.username)
        .first()
        if len(form_data.username) <= LOGIN_USERNAME_MAX_LENGTH
        else None
    )
    stored_hash = user.hashed_password if user else _DUMMY_PASSWORD_HASH
    rate_limited = not auth.login_attempt_allowed(form_data.username, client_ip)
    password_valid = not rate_limited and auth.verify_password(form_data.password, stored_hash)
    if rate_limited or not user or not user.is_active or not password_valid:
        db.add(models.AuditLog(
            user_id=None,
            action="LOGIN_FAILED",
            details=json.dumps({"username_attempted": form_data.username[:120]}),
        ))
        try:
            db.commit()
        except Exception:
            db.rollback()
            raise
        if rate_limited:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Try again in 15 minutes.",
            )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect credentials")

    try:
        access_token = auth.create_access_token(data={"sub": user.username})
        db.add(models.AuditLog(
            user_id=user.id,
            action="LOGIN_SUCCESS",
            details=json.dumps({"username": user.username}),
        ))
        db.commit()
    except Exception:
        db.rollback()
        raise
    auth.clear_login_failures(form_data.username, client_ip)
    return {"access_token": access_token, "token_type": "bearer", "role": user.role, "username": user.username}

@app.get("/me", response_model=CurrentUserResponse)
def get_me(current_user: models.User = Depends(auth.get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role,
        "is_active": current_user.is_active,
        "priority_mode": PRIORITY_MODE,
        "ml_warmup_state": get_warmup_state(),
    }

@app.post("/assets", response_model=AssetResponse)
def create_asset(
    body: AssetRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Only administrators or analysts can manage assets.")
    asset = models.Asset(
        name=body.name,
        type=body.type,
        ip_or_domain=body.ip_or_domain,
        owner=body.owner,
        environment=body.environment,
        exposure=body.exposure,
        criticality=body.criticality,
    )
    try:
        db.add(asset)
        db.flush()
        db.add(models.AuditLog(
            user_id=current_user.id,
            action="ASSET_CREATED",
            details=json.dumps({"asset_id": asset.id, "name": asset.name}),
        ))
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="An asset with this name already exists, ignoring letter case.",
        ) from exc
    except Exception:
        db.rollback()
        raise
    return asset

@app.put("/assets/{asset_id}", response_model=AssetResponse)
def update_asset(
    asset_id: int,
    body: AssetRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Only administrators or analysts can manage assets.")
    asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    previous = {
        "name": asset.name,
        "type": asset.type,
        "ip_or_domain": asset.ip_or_domain,
        "owner": asset.owner,
        "environment": asset.environment,
        "exposure": asset.exposure,
        "criticality": asset.criticality,
    }
    try:
        for field in previous:
            setattr(asset, field, getattr(body, field))
        db.add(models.AuditLog(
            user_id=current_user.id,
            action="ASSET_UPDATED",
            details=json.dumps({"asset_id": asset.id, "before": previous, "after": body.model_dump()}),
        ))
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="An asset with this name already exists, ignoring letter case.",
        ) from exc
    except Exception:
        db.rollback()
        raise
    return asset

@app.delete("/assets/{asset_id}", response_model=DeletedAssetResponse)
def delete_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Only administrators or analysts can manage assets.")
    asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    if db.query(models.Finding.id).filter(models.Finding.asset_id == asset.id).first():
        raise HTTPException(
            status_code=409,
            detail="This asset has findings and cannot be deleted. Resolve or move its findings first.",
        )
    name = asset.name
    try:
        db.delete(asset)
        db.add(models.AuditLog(
            user_id=current_user.id,
            action="ASSET_DELETED",
            details=json.dumps({"asset_id": asset_id, "name": name}),
        ))
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {"deleted": asset_id, "name": name}

@app.get("/assets", response_model=list[AssetResponse])
def get_assets(db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    return db.query(models.Asset).order_by(models.Asset.id.asc()).all()

def _cve_from_intel(info: dict) -> dict:
    return {
        "cve_id": info.get("cve_id"),
        "published_date": info.get("published_date"),
        "description": info.get("description"),
        "cvss_score": info.get("cvss"),
        "cvss_vector": info.get("cvss_vector"),
        "cwe": info.get("cwe"),
        "kev_date_added": info.get("kev_date_added"),
        "epss": info.get("epss"),
        "percentile": info.get("epss_percentile", info.get("percentile")),
        "in_kev": info.get("in_kev"),
    }


def _lookup_cached_cve(db: Session, cve_id: str) -> dict | None:
    cached = db.query(models.CVECache).filter_by(cve_id=cve_id).first()
    return cached.data if cached is not None else None


def _store_cached_cve(db: Session, cve_id: str, record: dict) -> None:
    try:
        db.add(models.CVECache(cve_id=cve_id, data=record))
        db.commit()
    except Exception:
        db.rollback()
        raise


@app.get("/cves/{cve_id}", response_model=CVEResponse)
async def get_cve(
    cve_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    cve_clean = cve_id.strip().upper()
    if not CVE_ID_PATTERN.fullmatch(cve_clean):
        raise HTTPException(status_code=422, detail="cve_id must look like CVE-2021-44228.")
    record = await run_in_threadpool(lookup_catalog, db, cve_clean)
    if record is not None:
        return {**record, "source": "catalog"}

    cached = await run_in_threadpool(_lookup_cached_cve, db, cve_clean)
    if cached is not None:
        return {**cached, "source": "postgres_cache"}
    intel = await fetch_cve_data(cve_clean)
    if not intel.get("available"):
        raise HTTPException(
            status_code=503,
            detail={
                "message": (
                    "The CVE catalog and PostgreSQL cache missed, and the live provider "
                    "did not return this CVE."
                ),
                "errors": intel.get("errors", []),
            },
        )
    record = _cve_from_intel(intel)
    await run_in_threadpool(_store_cached_cve, db, cve_clean, record)
    return {**record, "source": "live_provider"}


@app.get("/cves", response_model=list[CVEResponse])
def search_cve_records(
    response: Response,
    search: str = Query(..., min_length=1, max_length=200),
    limit: int = Query(default=CVE_SEARCH_MAX_RESULTS, ge=1, le=CVE_SEARCH_MAX_RESULTS),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    query = search.strip()
    if not query:
        raise HTTPException(status_code=422, detail="search cannot be empty.")
    catalog_records = search_catalog(db, query, limit)
    if catalog_records:
        response.headers["X-CVE-Lookup-Source"] = "catalog"
        results = tuple({**record, "source": "catalog"} for record in catalog_records)
    else:
        response.headers["X-CVE-Lookup-Source"] = "postgres_cache"
        needle = query.casefold()
        cached_records = (
            db.query(models.CVECache)
            .order_by(models.CVECache.cve_id.asc())
            .all()
        )
        results = tuple(
            {**record.data, "source": "postgres_cache"}
            for record in cached_records
            if needle in record.cve_id.casefold()
            or needle in json.dumps(record.data, ensure_ascii=False).casefold()
        )[:limit]
    return results

@app.get("/intel/{cve_id}", response_model=IntelResponse)
async def get_intel(
    cve_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    cve_clean = cve_id.strip().upper()
    if not CVE_ID_PATTERN.fullmatch(cve_clean):
        raise HTTPException(status_code=422, detail="cve_id must look like CVE-2021-44228.")
    return await lookup_cve_intel(db, cve_clean, fetch_cve_data)


@app.get("/model/results", response_model=ModelResultsResponse)
def get_model_results(current_user: models.User = Depends(auth.get_current_user)):
    return read_model_results()


@app.post("/scan", response_model=ScanResultResponse)
async def scan_vulnerability(req: ScanRequest, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    if current_user.role == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot run scans.")
    asset = db.query(models.Asset).filter(models.Asset.id == req.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    cve_clean = req.cve_id.strip().upper()
    if not CVE_ID_PATTERN.fullmatch(cve_clean):
        raise HTTPException(status_code=422, detail="cve_id must look like CVE-2021-44228.")
    intel = await lookup_cve_intel(db, cve_clean, fetch_cve_data)
    cvss_score = req.cvss_score
    epss_percentile = req.epss_percentile
    in_kev = bool(req.in_kev or intel.get("in_kev"))
    if cvss_score is None or epss_percentile is None:
        if cvss_score is None:
            cvss_score = intel.get("cvss")
        if epss_percentile is None:
            epss_percentile = intel.get("epss_percentile")
        if cvss_score is None or epss_percentile is None:
            raise HTTPException(
                status_code=503,
                detail={
                    "message": "Threat intelligence is unavailable; scan was not scored.",
                    "errors": intel.get("errors", []),
                },
            )
    internet_facing = (asset.exposure.lower() == "internet")
    scoring = calculate_priority(in_kev, internet_facing, asset.criticality, epss_percentile, cvss_score)
    inference_started = time.perf_counter()
    ml_assessment = await run_in_threadpool(
        predict_exploit_likelihood,
        cvss_score=cvss_score,
        cvss_vector=intel.get("cvss_vector"),
        cwe=intel.get("cwe"),
        description=intel.get("description"),
        exposure=asset.exposure,
        criticality=asset.criticality,
    )
    _LOGGER.debug(
        "scan.ml_inference cve_id=%s elapsed_ms=%.3f",
        cve_clean,
        (time.perf_counter() - inference_started) * 1000,
    )
    rule_tier = scoring["tier"]
    final_tier, priority_source = resolve_final_priority(
        rule_tier, ml_assessment["priority"], in_kev
    )

    persistence_started = time.perf_counter()
    finding = (
        db.query(models.Finding)
        .filter(
            models.Finding.asset_id == asset.id,
            models.Finding.cve_id == cve_clean,
        )
        .first()
    )
    action = "created" if finding is None else "updated"
    reopened = False
    try:
        if finding is None and db.bind.dialect.name == "postgresql":
            inserted_id = db.execute(
                postgresql_insert(models.Finding)
                .values(
                    asset_id=asset.id,
                    cve_id=cve_clean,
                    cvss_score=cvss_score,
                    in_kev=in_kev,
                    final_priority=final_tier,
                    priority_source=priority_source,
                    status="Open",
                )
                .on_conflict_do_nothing(index_elements=["asset_id", "cve_id"])
                .returning(models.Finding.id)
            ).scalar_one_or_none()
            if inserted_id is not None:
                finding = db.get(models.Finding, inserted_id)
            else:
                finding = (
                    db.query(models.Finding)
                    .filter(
                        models.Finding.asset_id == asset.id,
                        models.Finding.cve_id == cve_clean,
                    )
                    .first()
                )
                if finding is None:
                    raise RuntimeError("Concurrent finding insert completed without a visible row.")
                action = "updated"
                reopened = (finding.status or "").casefold() == "resolved"
                finding.cvss_score = cvss_score
                finding.in_kev = in_kev
                if reopened:
                    finding.status = "Open"
        elif finding is None:
            finding = models.Finding(
                asset_id=asset.id,
                cve_id=cve_clean,
                cvss_score=cvss_score,
                in_kev=in_kev,
                status="Open",
            )
            db.add(finding)
            db.flush()
        else:
            action = "updated"
            reopened = (finding.status or "").casefold() == "resolved"
            finding.cvss_score = cvss_score
            finding.in_kev = in_kev
            if reopened:
                finding.status = "Open"
        finding.final_priority = final_tier
        finding.priority_source = priority_source
        db.flush()
        score = models.FindingScore(
            finding_id=finding.id,
            provider_id=1,
            likelihood=epss_percentile,
            priority_tier=rule_tier,
            provenance={
                "source": "Manual Scan",
                "in_kev": in_kev,
                "cvss": cvss_score,
                "epss": epss_percentile,
                "score": scoring["score"],
                "final_priority": final_tier,
                "priority_source": priority_source,
                "scoring_explanation": scoring["explanation"],
            },
            explanation=scoring["explanation"]["summary"],
            ml_likelihood=ml_assessment["likelihood"],
            ml_risk=ml_assessment["risk"],
            ml_priority=ml_assessment["priority"],
            ml_top_reasons=ml_assessment["top_reasons"],
            ml_model_version=ml_assessment["model_version"],
            ml_recommended_action=ml_assessment["recommended_action"],
            ml_unavailable_reason=ml_assessment["unavailable_reason"],
        )
        db.add(score)
        db.add(models.AuditLog(
            user_id=current_user.id,
            action="SCAN_RUN",
            details=f"finding_id={finding.id} Finding {action}: scanned {cve_clean} on {asset.name} -> {final_tier}",
        ))
        db.commit()
        _LOGGER.debug(
            "scan.persistence cve_id=%s action=%s elapsed_ms=%.3f",
            cve_clean,
            action,
            (time.perf_counter() - persistence_started) * 1000,
        )
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="This finding was created concurrently. Retry the scan.",
        ) from exc
    except Exception:
        db.rollback()
        raise
    return {
        "finding_id": finding.id,
        "action": action,
        "reopened": reopened,
        "priority_tier": final_tier,
        "final_priority": final_tier,
        "recommended_action": recommended_action_for_priority(final_tier),
        "priority_source": priority_source,
        "rule_priority_tier": rule_tier,
        "score": TIER_SCORES[final_tier],
        "explanation": scoring["explanation"],
        **_ml_score_fields(score),
    }

@app.put("/findings/{finding_id}/status", response_model=StatusUpdateResponse)
def update_status(finding_id: int, req: StatusUpdateRequest, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    if current_user.role == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot change finding status.")
    if req.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail="Status must be Open, In Progress, or Resolved.")
    finding = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    old_status = finding.status
    try:
        finding.status = req.status
        db.add(models.AuditLog(
            user_id=current_user.id,
            action="STATUS_UPDATE",
            details=f"finding_id={finding.id} {finding.cve_id} status changed from {old_status} to {req.status}",
        ))
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {"message": "Success", "id": finding.id, "status": finding.status}

@app.get("/findings", response_model=FindingsPageResponse)
def get_findings(
    priority: str | None = Query(default=None),
    status: str | None = Query(default=None),
    asset_id: int | None = Query(default=None),
    q: str | None = Query(default=None),
    sort: str = Query(default="priority"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    latest_score_ids = (
        db.query(
            models.FindingScore.finding_id.label("finding_id"),
            func.max(models.FindingScore.id).label("score_id"),
        )
        .group_by(models.FindingScore.finding_id)
        .subquery()
    )
    LatestScore = aliased(models.FindingScore)
    tier = func.coalesce(
        func.nullif(models.Finding.final_priority, ""),
        func.coalesce(func.nullif(LatestScore.priority_tier, ""), "Low"),
    )
    status_value = func.coalesce(models.Finding.status, "Open")
    cvss_value = func.coalesce(models.Finding.cvss_score, 0)
    likelihood_value = func.coalesce(LatestScore.likelihood, 0)
    query = (
        db.query(models.Finding, LatestScore, models.Asset)
        .outerjoin(models.Asset, models.Finding.asset_id == models.Asset.id)
        .outerjoin(latest_score_ids, latest_score_ids.c.finding_id == models.Finding.id)
        .outerjoin(LatestScore, LatestScore.id == latest_score_ids.c.score_id)
    )
    open_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for count_tier, count in (
        query.with_entities(tier, func.count(models.Finding.id))
        .filter(models.Finding.status == "Open")
        .group_by(tier)
        .all()
    ):
        if count_tier in open_counts:
            open_counts[count_tier] = count

    filtered_query = query
    if priority:
        filtered_query = filtered_query.filter(func.lower(tier) == priority.strip().lower())
    if status:
        filtered_query = filtered_query.filter(func.lower(status_value) == status.strip().lower())
    if asset_id is not None:
        filtered_query = filtered_query.filter(models.Finding.asset_id == asset_id)
    if q:
        needle = q.strip().lower()
        escaped_needle = needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped_needle}%"
        explanation_summary = LatestScore.provenance["scoring_explanation"]["summary"].as_string()
        explanation_text = func.coalesce(explanation_summary, LatestScore.explanation, "")
        filtered_query = filtered_query.filter(
            or_(
                func.coalesce(models.Finding.cve_id, "UNKNOWN").ilike(pattern, escape="\\"),
                func.coalesce(models.Asset.name, "Unknown").ilike(pattern, escape="\\"),
                explanation_text.ilike(pattern, escape="\\"),
            )
        )

    if sort == "cvss":
        ordered_query = filtered_query.order_by(cvss_value.desc(), models.Finding.id.desc())
    elif sort == "epss":
        ordered_query = filtered_query.order_by(likelihood_value.desc(), models.Finding.id.desc())
    elif sort == "newest":
        ordered_query = filtered_query.order_by(models.Finding.id.desc())
    else:
        tier_rank = case(
            (tier == "Critical", 4),
            (tier == "High", 3),
            (tier == "Medium", 2),
            (tier == "Low", 1),
            else_=0,
        )
        ordered_query = filtered_query.order_by(
            tier_rank.desc(),
            cvss_value.desc(),
            likelihood_value.desc(),
            models.Finding.id.desc(),
        )

    total = filtered_query.order_by(None).with_entities(func.count(models.Finding.id)).scalar() or 0
    pages = max(1, (total + page_size - 1) // page_size)
    rows = ordered_query.offset((page - 1) * page_size).limit(page_size).all()
    items = []
    for finding, latest, asset in rows:
        final_tier = finding.final_priority or (latest.priority_tier if latest and latest.priority_tier else "Low")
        rule_tier = latest.priority_tier if latest and latest.priority_tier else "Low"
        items.append({
            "id": int(finding.id),
            "cve_id": str(finding.cve_id or "UNKNOWN"),
            "asset_id": int(finding.asset_id) if finding.asset_id is not None else 0,
            "asset_name": asset.name if asset else "Unknown",
            "exposure": asset.exposure if asset else "Internal",
            "criticality": int(asset.criticality) if (asset and asset.criticality is not None) else 1,
            "cvss_score": float(finding.cvss_score) if finding.cvss_score is not None else 0.0,
            "epss": float(latest.likelihood) if latest and latest.likelihood is not None else 0.0,
            "in_kev": bool(finding.in_kev),
            "priority_tier": final_tier,
            "final_priority": final_tier,
            "recommended_action": recommended_action_for_priority(final_tier),
            "priority_source": finding.priority_source or "rules",
            "rule_priority_tier": rule_tier,
            "score": TIER_SCORES.get(final_tier, 0),
            "status": str(finding.status or "Open"),
            "date_found": str(finding.date_found) if finding.date_found else None,
            "explanation": _stored_explanation(latest, finding, asset),
            **_ml_score_fields(latest),
        })

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
        "counts": open_counts,
    }


@app.get("/dashboard/analytics", response_model=DashboardAnalyticsResponse)
def get_dashboard_analytics(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    findings = db.query(models.Finding).all()
    latest_scores: dict[int, models.FindingScore] = {}
    for score in db.query(models.FindingScore).order_by(models.FindingScore.id.asc()).all():
        latest_scores[score.finding_id] = score

    now = datetime.now(timezone.utc)
    today = now.date()
    month_start = today.replace(day=1)
    first_day = today - timedelta(days=6)
    weekly_counts = {
        first_day + timedelta(days=offset): {"ingested_count": 0, "resolved_count": 0}
        for offset in range(7)
    }

    triage_at: dict[int, datetime] = {}
    resolved_at: dict[int, datetime] = {}
    created_at: dict[int, datetime] = {}
    ingestion_has_history = False

    for log in db.query(models.AuditLog).order_by(models.AuditLog.id.asc()).all():
        event_time = _as_utc(log.timestamp)
        if log.action == "STATUS_UPDATE":
            match = STATUS_CHANGE_PATTERN.match(log.details or "")
            if match and event_time:
                finding_id = int(match.group(1))
                old_status, new_status = match.group(2), match.group(3)
                if old_status == "Open" and new_status in ("In Progress", "Resolved"):
                    triage_at.setdefault(finding_id, event_time)
                if new_status == "Resolved":
                    resolved_at[finding_id] = event_time
                    if first_day <= event_time.date() <= today:
                        weekly_counts[event_time.date()]["resolved_count"] += 1
        elif log.action == "SCAN_RUN":
            ingestion_has_history = True
            finding_match = re.match(r"^finding_id=(\d+)\b", log.details or "")
            if finding_match and event_time:
                created_at[int(finding_match.group(1))] = event_time
            if event_time and first_day <= event_time.date() <= today:
                weekly_counts[event_time.date()]["ingested_count"] += 1
        elif log.action == "IMPORT":
            imported_match = IMPORT_COUNT_PATTERN.search(log.details or "")
            imported = int(imported_match.group(1)) if imported_match else 0
            imported_ids_match = IMPORT_FINDING_IDS_PATTERN.search(log.details or "")
            if imported_ids_match and event_time:
                for finding_id in imported_ids_match.group(1).split(","):
                    created_at[int(finding_id)] = event_time
            if imported > 0:
                ingestion_has_history = True
                if event_time and first_day <= event_time.date() <= today:
                    weekly_counts[event_time.date()]["ingested_count"] += imported

    tier_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    open_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    resolved_findings = 0
    triage_durations: list[float] = []
    sla_eligible = 0
    sla_met = 0
    sla_hours = {"Critical": 24, "High": 72, "Medium": 14 * 24, "Low": 30 * 24}

    for finding in findings:
        score = latest_scores.get(finding.id)
        rule_tier = score.priority_tier if score and score.priority_tier else "Low"
        tier = finding.final_priority or rule_tier
        if tier not in tier_counts:
            tier = "Low"
        tier_counts[tier] += 1
        if finding.status == "Open":
            open_counts[tier] += 1
        if finding.status == "Resolved":
            resolved_findings += 1

        finding_created = created_at.get(finding.id)
        if finding_created is None:
            continue

        first_triage = triage_at.get(finding.id)
        if first_triage and first_triage >= finding_created:
            triage_durations.append((first_triage - finding_created).total_seconds() / 3600)

        resolution = resolved_at.get(finding.id)
        if finding.status == "Resolved" and resolution and resolution >= finding_created:
            sla_eligible += 1
            if (resolution - finding_created).total_seconds() <= sla_hours[tier] * 3600:
                sla_met += 1

    total_findings = len(findings)
    return {
        "total_assets": db.query(func.count(models.Asset.id)).scalar() or 0,
        "open_vulnerabilities": sum(1 for finding in findings if finding.status == "Open"),
        "fixed_this_month": sum(
            1
            for finding in findings
            if finding.status == "Resolved"
            and (resolution := resolved_at.get(finding.id)) is not None
            and month_start <= resolution.date() <= today
        ),
        "total_findings": total_findings,
        "resolved_findings": resolved_findings,
        "mitigation_pct": round(resolved_findings * 100 / total_findings, 1) if total_findings else None,
        "critical_count": tier_counts["Critical"],
        "high_count": tier_counts["High"],
        "medium_count": tier_counts["Medium"],
        "low_count": tier_counts["Low"],
        "open_critical_count": open_counts["Critical"],
        "open_high_count": open_counts["High"],
        "open_medium_count": open_counts["Medium"],
        "open_low_count": open_counts["Low"],
        "mean_time_to_triage_hours": round(sum(triage_durations) / len(triage_durations), 1)
        if triage_durations else None,
        "sla_compliance_pct": round(sla_met * 100 / sla_eligible, 1) if sla_eligible else None,
        "weekly_activity": [
            {"date": day, **counts} for day, counts in weekly_counts.items()
        ],
        "ingestion_has_history": ingestion_has_history,
    }


@app.get("/findings/{finding_id}", response_model=FindingDetailResponse)
def get_finding_detail(finding_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    f = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")

    scores = (
        db.query(models.FindingScore)
        .filter(models.FindingScore.finding_id == f.id)
        .order_by(models.FindingScore.id.desc())
        .all()
    )
    latest = scores[0] if scores else None

    related_logs = []
    if current_user.role == "admin":
        related_logs = _audit_entries_for_finding(db, f.id)

    final_tier = f.final_priority or (latest.priority_tier if latest else "Unknown")
    return {
        "id": f.id,
        "cve_id": f.cve_id,
        "status": f.status,
        "date_found": f.date_found,
        "cvss_score": float(f.cvss_score or 0.0),
        "in_kev": bool(f.in_kev),
        "asset": {
            "id": f.asset.id if f.asset else None,
            "name": f.asset.name if f.asset else "Unknown",
            "type": f.asset.type if f.asset else "Other",
            "ip_or_domain": f.asset.ip_or_domain if f.asset else "",
            "owner": f.asset.owner if f.asset else "",
            "environment": f.asset.environment if f.asset else "Unknown",
            "exposure": f.asset.exposure if f.asset else "Internal",
            "criticality": f.asset.criticality if f.asset else 1,
        },
        "priority_tier": final_tier,
        "final_priority": final_tier,
        "recommended_action": recommended_action_for_priority(final_tier),
        "priority_source": f.priority_source or "rules",
        "rule_priority_tier": latest.priority_tier if latest else "Unknown",
        "score": TIER_SCORES.get(final_tier, 0),
        "likelihood": float(latest.likelihood or 0.0) if latest else 0.0,
        "explanation": _stored_explanation(latest, f, f.asset),
        **_ml_score_fields(latest),
        "provenance": latest.provenance if latest else {},
        "score_history": [
            {
                "id": s.id,
                "provider_id": s.provider_id,
                "priority_tier": s.priority_tier,
                "score": _stored_score(s, s.priority_tier),
                "likelihood": float(s.likelihood or 0.0),
                "explanation": _stored_explanation(s, f, f.asset),
                **_ml_score_fields(s),
                "provenance": s.provenance,
            }
            for s in scores
        ],
        "audit_trail": [
            {
                "id": l.id,
                "user": l.user.username if l.user else "system",
                "action": l.action,
                "details": l.details,
                "timestamp": l.timestamp,
            }
            for l in related_logs
        ],
    }


def _audit_entries_for_finding(db: Session, finding_id: int, limit: int = 20) -> list[models.AuditLog]:
    finding_id = int(finding_id)
    finding_pattern = re.compile(rf"(^|\s)finding_id={finding_id}(\s|$)")
    import_pattern = re.compile(rf"finding_ids=(\d+,)*{finding_id}(,|$)")
    related_pattern = finding_pattern.pattern
    import_query_pattern = import_pattern.pattern

    related_logs = (
        db.query(models.AuditLog)
        .filter(models.AuditLog.details.op("~")(related_pattern))
        .order_by(models.AuditLog.id.desc())
        .limit(limit)
        .all()
    )
    import_log = (
        db.query(models.AuditLog)
        .filter(
            models.AuditLog.action == "IMPORT",
            models.AuditLog.details.op("~")(import_query_pattern),
        )
        .order_by(models.AuditLog.id.desc())
        .limit(1)
        .all()
    )
    matched_logs = {
        log.id: log
        for log in related_logs + import_log
        if finding_pattern.search(log.details or "") or import_pattern.search(log.details or "")
    }
    return sorted(matched_logs.values(), key=lambda log: log.id, reverse=True)[:limit]


@app.get("/audit", response_model=list[AuditEntryResponse])
def get_audit_logs(db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only administrators can view the audit log.")
    logs = db.query(models.AuditLog).order_by(models.AuditLog.id.desc()).limit(100).all()
    return [
        {
            "id": l.id,
            "user": l.user.username if l.user else "system",
            "action": l.action,
            "details": l.details,
            "timestamp": l.timestamp,
        }
        for l in logs
    ]

@app.post("/imports/preview", response_model=ImportPreviewResponse)
async def preview_csv(
    file: UploadFile = File(...),
    create_missing_assets: bool = Form(False),
    date_order: str = Form("dmy"),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    if current_user.role == "viewer":
        raise HTTPException(403, "Viewers cannot import findings.")
    if date_order not in {"dmy", "mdy"}:
        raise HTTPException(422, "date_order must be 'dmy' or 'mdy'.")
    data = await file.read(MAX_BYTES + 1)
    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(400, "Upload a .csv file.")
    assets = _asset_identifier_map(db.query(models.Asset).order_by(models.Asset.id.asc()).all())
    pairs = {(a, c) for a, c in db.query(models.Finding.asset_id, models.Finding.cve_id).all()}
    try:
        rows, summary = parse_and_validate(
            data,
            assets,
            pairs,
            allow_missing_assets=create_missing_assets,
            date_order=date_order,
        )
    except ImportFileError as exc:
        raise HTTPException(400, str(exc))
    reader = csv.reader(io.StringIO(data.decode("utf-8-sig"), newline=""))
    ambiguous_date_rows = summary.pop("ambiguous_date_rows", 0)
    return {
        "detected_format": detect_format(next(reader, [])),
        "summary": summary,
        "rows": [r.as_dict() for r in rows],
        "ambiguous_date_rows": ambiguous_date_rows,
    }

@app.post("/imports/commit", response_model=ImportCommitResponse)
async def commit_csv(
    file: UploadFile = File(...),
    create_missing_assets: bool = Form(False),
    date_order: str = Form("dmy"),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    if current_user.role == "viewer":
        raise HTTPException(403, "Viewers cannot import findings.")
    if date_order not in {"dmy", "mdy"}:
        raise HTTPException(422, "date_order must be 'dmy' or 'mdy'.")
    data = await file.read(MAX_BYTES + 1)
    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(400, "Upload a .csv file.")
    all_assets = db.query(models.Asset).all()
    assets = _asset_identifier_map(all_assets)
    pairs = {(a, c) for a, c in db.query(models.Finding.asset_id, models.Finding.cve_id).all()}
    try:
        rows, summary = parse_and_validate(
            data,
            assets,
            pairs,
            allow_missing_assets=create_missing_assets,
            date_order=date_order,
        )
    except ImportFileError as exc:
        raise HTTPException(400, str(exc))

    ok = [r for r in rows if r.status == "ok"]
    cves = sorted({r.cve_id for r in ok})

    intel = {}
    for cve in cves:
        intel[cve] = await lookup_cve_intel(db, cve, fetch_cve_data)

    asset_by_id = {a.id: a for a in all_assets}
    new_assets: dict[str, models.Asset] = {}
    imported = 0
    imported_finding_ids = []

    try:
        for r in ok:
            info = intel.get(r.cve_id)
            if not info or info.get("epss_percentile") is None:
                errors = "; ".join(info.get("errors", [])) if info else "Threat intelligence lookup failed."
                r.status, r.reason = "error", errors
                continue

            cvss_val = r.cvss_score if r.cvss_score is not None else info.get("cvss")
            if cvss_val is None:
                errors = "; ".join(info.get("errors", [])) or "CVSS score is unavailable."
                r.status, r.reason = "error", errors
                continue

            asset = asset_by_id.get(r.asset_id) if r.asset_id is not None else None
            if asset is None:
                asset_key = r.asset_name.casefold()
                asset = new_assets.get(asset_key)
                if asset is None:
                    asset = models.Asset(
                        name=r.asset_name,
                        exposure="Internal",
                        criticality=3,
                        needs_review=True,
                    )
                    db.add(asset)
                    db.flush()
                    asset_by_id[asset.id] = asset
                    new_assets[asset_key] = asset
            r.asset_id = asset.id
            internet_facing = (asset.exposure.lower() == "internet")
            in_kev = bool(info.get("in_kev", False))
            epss_val = info.get("epss_percentile")
            scoring = calculate_priority(in_kev, internet_facing, asset.criticality, epss_val, cvss_val)
            ml_assessment = predict_exploit_likelihood(
                cvss_score=cvss_val,
                cvss_vector=info.get("cvss_vector"),
                cwe=info.get("cwe"),
                description=info.get("description"),
                exposure=asset.exposure,
                criticality=asset.criticality,
            )
            rule_tier = scoring["tier"]
            final_tier, priority_source = resolve_final_priority(
                rule_tier, ml_assessment["priority"], in_kev
            )

            finding = models.Finding(
                asset_id=r.asset_id,
                cve_id=r.cve_id,
                status="Open",
                date_found=r.date_found,
                cvss_score=cvss_val,
                in_kev=in_kev,
                final_priority=final_tier,
                priority_source=priority_source,
            )
            db.add(finding)
            db.flush()

            score = models.FindingScore(
                finding_id=finding.id,
                provider_id=1,
                likelihood=epss_val,
                priority_tier=rule_tier,
                provenance={
                    "source": "CSV Import",
                    "filename": file.filename,
                    "in_kev": in_kev,
                    "score": scoring["score"],
                    "final_priority": final_tier,
                    "priority_source": priority_source,
                    "scoring_explanation": scoring["explanation"],
                },
                explanation=scoring["explanation"]["summary"],
                ml_likelihood=ml_assessment["likelihood"],
                ml_risk=ml_assessment["risk"],
                ml_priority=ml_assessment["priority"],
                ml_top_reasons=ml_assessment["top_reasons"],
                ml_model_version=ml_assessment["model_version"],
                ml_recommended_action=ml_assessment["recommended_action"],
                ml_unavailable_reason=ml_assessment["unavailable_reason"],
            )
            db.add(score)
            imported_finding_ids.append(finding.id)
            imported += 1

        skipped = len(rows) - imported
        digest = hashlib.sha256(data).hexdigest()
        db.add(models.AuditLog(
            user_id=current_user.id,
            action="IMPORT",
            details=(
                f"file={file.filename} sha256={digest} "
                f"created_assets={','.join(asset.name for asset in new_assets.values())} "
                f"imported={imported} skipped={skipped} "
                f"finding_ids={','.join(str(finding_id) for finding_id in imported_finding_ids)}"
                if imported_finding_ids else
                f"file={file.filename} sha256={digest} "
                f"created_assets={','.join(asset.name for asset in new_assets.values())} "
                f"imported={imported} skipped={skipped}"
            ),
        ))
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="The import conflicted with records created concurrently. Refresh the preview and retry.",
        ) from exc
    except Exception:
        db.rollback()
        raise

    return {
        "imported": imported,
        "skipped": skipped,
        "problems_csv": problems_to_csv(rows),
        "ambiguous_date_rows": summary.get("ambiguous_date_rows", 0),
    }