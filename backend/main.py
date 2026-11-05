from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Query
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel
import hashlib
import os
import re

from backend import models, auth
from backend.database import engine, get_db
from backend.scoring_engine import TIER_SCORES, calculate_priority
from backend.threat_intel import fetch_cve_data
from backend.csv_import import MAX_BYTES, ImportFileError, parse_and_validate, problems_to_csv
from backend.reports import router as reports_router
from backend.users import router as users_router
from backend.schemas import (
    AssetResponse,
    AuditEntryResponse,
    FindingDetailResponse,
    FindingsPageResponse,
    IntelResponse,
    ImportCommitResponse,
    ImportPreviewResponse,
    ScanResultResponse,
    StatusUpdateResponse,
    TokenResponse,
)

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="SecureVision Backend API")
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


class AssetCreateRequest(BaseModel):
    name: str
    exposure: str
    criticality: int

class ScanRequest(BaseModel):
    asset_id: int
    cve_id: str
    cvss_score: float | None = None
    in_kev: bool = False
    epss_percentile: float | None = None

class StatusUpdateRequest(BaseModel):
    status: str

@app.post("/token", response_model=TokenResponse)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect credentials")
    access_token = auth.create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer", "role": user.role, "username": user.username}

@app.post("/assets", response_model=AssetResponse)
def create_asset(
    name: str | None = None,
    exposure: str | None = None,
    criticality: int | None = None,
    body: AssetCreateRequest | None = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Only administrators or analysts can manage assets.")
    final_name = (body.name if body else name or "").strip()
    final_exposure = (body.exposure if body else exposure or "Internal").strip()
    final_crit = int(body.criticality if body else (criticality or 3))
    if not final_name:
        raise HTTPException(status_code=400, detail="Asset name is required.")
    if final_crit < 1 or final_crit > 5:
        raise HTTPException(status_code=400, detail="Criticality must be between 1 and 5.")

    asset = models.Asset(name=final_name, exposure=final_exposure, criticality=final_crit)
    try:
        db.add(asset)
        db.flush()
        db.add(models.AuditLog(
            user_id=current_user.id,
            action="ASSET_CREATED",
            details=f"Added asset: {final_name} ({final_exposure}, criticality={final_crit})",
        ))
        db.commit()
    except Exception:
        db.rollback()
        raise
    return asset

@app.get("/assets", response_model=list[AssetResponse])
def get_assets(db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    return db.query(models.Asset).order_by(models.Asset.id.asc()).all()

@app.get("/intel/{cve_id}", response_model=IntelResponse)
async def get_intel(cve_id: str, current_user: models.User = Depends(auth.get_current_user)):
    cve_clean = cve_id.strip().upper()
    if not CVE_ID_PATTERN.fullmatch(cve_clean):
        raise HTTPException(status_code=422, detail="cve_id must look like CVE-2021-44228.")
    return await fetch_cve_data(cve_clean)

@app.post("/scan", response_model=ScanResultResponse)
async def scan_vulnerability(req: ScanRequest, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    if current_user.role == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot run scans.")
    asset = db.query(models.Asset).filter(models.Asset.id == req.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    cve_clean = req.cve_id.strip().upper()
    if not CVE_ID_PATTERN.fullmatch(cve_clean):
        raise HTTPException(status_code=400, detail="cve_id must look like CVE-2021-44228.")
    cvss_score = req.cvss_score
    epss_percentile = req.epss_percentile
    if cvss_score is None or epss_percentile is None:
        intel = await fetch_cve_data(cve_clean)
        if cvss_score is None:
            cvss_score = intel["cvss"]
        if epss_percentile is None:
            epss_percentile = intel["epss"]
        if cvss_score is None or epss_percentile is None:
            raise HTTPException(
                status_code=503,
                detail={
                    "message": "Threat intelligence is unavailable; scan was not scored.",
                    "errors": intel["errors"],
                },
            )
    internet_facing = (asset.exposure.lower() == "internet")
    scoring = calculate_priority(req.in_kev, internet_facing, asset.criticality, epss_percentile, cvss_score)
    tier = scoring["tier"]

    finding = models.Finding(
        asset_id=asset.id,
        cve_id=cve_clean,
        cvss_score=cvss_score,
        in_kev=req.in_kev,
        status="Open",
    )
    try:
        db.add(finding)
        db.flush()
        score = models.FindingScore(
            finding_id=finding.id,
            provider_id=1,
            likelihood=epss_percentile,
            priority_tier=tier,
            provenance={
                "source": "Manual Scan",
                "in_kev": req.in_kev,
                "cvss": cvss_score,
                "epss": epss_percentile,
                "score": scoring["score"],
                "scoring_explanation": scoring["explanation"],
            },
            explanation=scoring["explanation"]["summary"],
        )
        db.add(score)
        db.add(models.AuditLog(
            user_id=current_user.id,
            action="SCAN_RUN",
            details=f"finding_id={finding.id} Scanned {cve_clean} on {asset.name} -> {tier}",
        ))
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {
        "finding_id": finding.id,
        "priority_tier": tier,
        "score": scoring["score"],
        "explanation": scoring["explanation"],
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
    findings = db.query(models.Finding).all()
    all_rows = []
    open_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for f in findings:
        latest = (
            db.query(models.FindingScore)
            .filter(models.FindingScore.finding_id == f.id)
            .order_by(models.FindingScore.id.desc())
            .first()
        )
        tier = (latest.priority_tier if latest and latest.priority_tier else "Low")
        likelihood = float(latest.likelihood) if (latest and latest.likelihood is not None) else 0.0
        explanation = _stored_explanation(latest, f, f.asset)
        cvss_val = float(f.cvss_score) if f.cvss_score is not None else 0.0

        if f.status == "Open" and tier in open_counts:
            open_counts[tier] += 1

        all_rows.append({
            "id": int(f.id),
            "cve_id": str(f.cve_id or "UNKNOWN"),
            "asset_id": int(f.asset_id) if f.asset_id is not None else 0,
            "asset_name": f.asset.name if f.asset else "Unknown",
            "exposure": f.asset.exposure if f.asset else "Internal",
            "criticality": int(f.asset.criticality) if (f.asset and f.asset.criticality is not None) else 1,
            "cvss_score": cvss_val,
            "epss": likelihood,
            "in_kev": bool(f.in_kev),
            "priority_tier": tier,
            "score": _stored_score(latest, tier),
            "status": str(f.status or "Open"),
            "date_found": str(f.date_found or "2026-10-01"),
            "explanation": explanation,
        })

    filtered = all_rows
    if priority:
        filtered = [r for r in filtered if r["priority_tier"].lower() == priority.strip().lower()]
    if status:
        filtered = [r for r in filtered if r["status"].lower() == status.strip().lower()]
    if asset_id is not None:
        filtered = [r for r in filtered if r["asset_id"] == asset_id]
    if q:
        needle = q.strip().lower()
        filtered = [r for r in filtered if needle in r["cve_id"].lower() or needle in r["asset_name"].lower()]

    if sort == "cvss":
        filtered.sort(key=lambda r: (r["cvss_score"], r["id"]), reverse=True)
    elif sort == "epss":
        filtered.sort(key=lambda r: (r["epss"], r["id"]), reverse=True)
    elif sort == "newest":
        filtered.sort(key=lambda r: r["id"], reverse=True)
    else:
        filtered.sort(key=lambda r: (TIER_RANK.get(r["priority_tier"], 0), r["cvss_score"], r["epss"], r["id"]), reverse=True)

    total = len(filtered)
    pages = max(1, (total + page_size - 1) // page_size)
    start = (page - 1) * page_size
    items = filtered[start : start + page_size]

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
        "counts": open_counts,
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
        related_logs = (
            db.query(models.AuditLog)
            .filter(models.AuditLog.details.contains(f"finding_id={f.id}"))
            .order_by(models.AuditLog.id.desc())
            .limit(20)
            .all()
        )

    return {
        "id": f.id,
        "cve_id": f.cve_id,
        "status": f.status,
        "date_found": f.date_found or "2026-10-01",
        "cvss_score": float(f.cvss_score or 0.0),
        "in_kev": bool(f.in_kev),
        "asset": {
            "id": f.asset.id if f.asset else None,
            "name": f.asset.name if f.asset else "Unknown",
            "exposure": f.asset.exposure if f.asset else "Internal",
            "criticality": f.asset.criticality if f.asset else 1,
        },
        "priority_tier": latest.priority_tier if latest else "Unknown",
        "score": _stored_score(latest, latest.priority_tier if latest else "Unknown"),
        "likelihood": float(latest.likelihood or 0.0) if latest else 0.0,
        "explanation": _stored_explanation(latest, f, f.asset),
        "provenance": latest.provenance if latest else {},
        "score_history": [
            {
                "id": s.id,
                "provider_id": s.provider_id,
                "priority_tier": s.priority_tier,
                "score": _stored_score(s, s.priority_tier),
                "likelihood": float(s.likelihood or 0.0),
                "explanation": _stored_explanation(s, f, f.asset),
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
async def preview_csv(file: UploadFile = File(...), db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    if current_user.role == "viewer":
        raise HTTPException(403, "Viewers cannot import findings.")
    data = await file.read(MAX_BYTES + 1)
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(400, "Upload a .csv file.")
    assets = {a.name: a.id for a in db.query(models.Asset).all()}
    pairs = {(a, c) for a, c in db.query(models.Finding.asset_id, models.Finding.cve_id).all()}
    try:
        rows, summary = parse_and_validate(data, assets, pairs)
    except ImportFileError as exc:
        raise HTTPException(400, str(exc))
    return {"summary": summary, "rows": [r.as_dict() for r in rows]}

@app.post("/imports/commit", response_model=ImportCommitResponse)
async def commit_csv(file: UploadFile = File(...), db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    if current_user.role == "viewer":
        raise HTTPException(403, "Viewers cannot import findings.")
    data = await file.read(MAX_BYTES + 1)
    assets = {a.name: a.id for a in db.query(models.Asset).all()}
    pairs = {(a, c) for a, c in db.query(models.Finding.asset_id, models.Finding.cve_id).all()}
    try:
        rows, _ = parse_and_validate(data, assets, pairs)
    except ImportFileError as exc:
        raise HTTPException(400, str(exc))

    ok = [r for r in rows if r.status == "ok"]
    cves = sorted({r.cve_id for r in ok})

    intel = {}
    for cve in cves:
        intel[cve] = await fetch_cve_data(cve)

    asset_by_id = {a.id: a for a in db.query(models.Asset).all()}
    imported = 0

    try:
        for r in ok:
            info = intel.get(r.cve_id)
            if not info or not info["available"] or info["epss"] is None or info["cvss"] is None:
                errors = "; ".join(info["errors"]) if info else "Threat intelligence lookup failed."
                r.status, r.reason = "error", errors
                continue

            asset = asset_by_id[r.asset_id]
            internet_facing = (asset.exposure.lower() == "internet")
            in_kev = bool(info.get("in_kev", False))
            cvss_val = info["cvss"]
            epss_val = info["epss"]
            scoring = calculate_priority(in_kev, internet_facing, asset.criticality, epss_val, cvss_val)
            tier = scoring["tier"]

            finding = models.Finding(
                asset_id=r.asset_id,
                cve_id=r.cve_id,
                status="Open",
                date_found=r.date_found,
                cvss_score=cvss_val,
                in_kev=in_kev,
            )
            db.add(finding)
            db.flush()

            score = models.FindingScore(
                finding_id=finding.id,
                provider_id=1,
                likelihood=epss_val,
                priority_tier=tier,
                provenance={
                    "source": "CSV Import",
                    "filename": file.filename,
                    "in_kev": in_kev,
                    "score": scoring["score"],
                    "scoring_explanation": scoring["explanation"],
                },
                explanation=scoring["explanation"]["summary"],
            )
            db.add(score)
            imported += 1

        skipped = len(rows) - imported
        digest = hashlib.sha256(data).hexdigest()
        db.add(models.AuditLog(
            user_id=current_user.id,
            action="IMPORT",
            details=f"file={file.filename} sha256={digest} imported={imported} skipped={skipped}",
        ))
        db.commit()
    except Exception:
        db.rollback()
        raise

    return {"imported": imported, "skipped": skipped, "problems_csv": problems_to_csv(rows)}