import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response, StreamingResponse
from fpdf import FPDF
from sqlalchemy import case, func, or_
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.auth import get_current_user
from backend.models import Asset, AuditLog, Finding, FindingScore, User

router = APIRouter(prefix="/reports", tags=["reports"])

TIERS = ["Critical", "High", "Medium", "Low"]
_tier_rank = case({t: i for i, t in enumerate(TIERS)}, value=FindingScore.priority_tier, else_=99)

SORTS = {
    "priority": [_tier_rank.asc(), Finding.cvss_score.desc()],
    "cvss": [Finding.cvss_score.desc()],
    "epss": [FindingScore.likelihood.desc()],
    "newest": [Finding.id.desc()],
    "date": [Finding.date_found.desc()],
    "asset": [Asset.name.asc()],
}

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _safe_cell(v):
    """Neutralise CSV/Excel formula injection on string cells."""
    if isinstance(v, str) and v.startswith(_FORMULA_PREFIXES):
        return "'" + v
    return v


def _filtered_query(db: Session, priority, status, asset_id, q, sort):
    qry = (
        db.query(Finding, Asset, FindingScore)
        .join(Asset, Finding.asset_id == Asset.id)
        .outerjoin(FindingScore, FindingScore.finding_id == Finding.id)
    )
    if priority:
        qry = qry.filter(func.lower(FindingScore.priority_tier) == priority.strip().lower())
    if status:
        qry = qry.filter(func.lower(Finding.status) == status.strip().lower())
    if asset_id is not None:
        qry = qry.filter(Finding.asset_id == asset_id)
    if q:
        like = f"%{q.strip()}%"
        qry = qry.filter(or_(Finding.cve_id.ilike(like), Asset.name.ilike(like)))
    order = SORTS.get(sort or "priority", SORTS["priority"])
    return qry.order_by(*order, Finding.id.asc())


def _log_export(db: Session, user: User, fmt: str, filters: dict, rows: int, data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    db.add(
        AuditLog(
            user_id=user.id,
            action="EXPORT",
            details=json.dumps({"format": fmt, "filters": filters, "rows": rows, "sha256": digest}),
        )
    )
    db.commit()
    return digest


@router.get("/findings.csv")
def export_findings_csv(
    priority: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    asset_id: Optional[int] = Query(None),
    q: Optional[str] = Query(None),
    sort: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    buf = io.StringIO(newline="")
    w = csv.writer(buf)
    w.writerow([
        "finding_id", "cve_id", "asset", "exposure", "criticality", "cvss_score",
        "in_kev", "status", "priority_tier", "likelihood", "date_found",
    ])
    count = 0
    for f, a, s in _filtered_query(db, priority, status, asset_id, q, sort).yield_per(500):
        date_str = f.date_found.isoformat() if hasattr(f.date_found, "isoformat") else (f.date_found or "")
        w.writerow([
            _safe_cell(v)
            for v in (
                f.id,
                f.cve_id,
                a.name,
                a.exposure,
                a.criticality,
                f.cvss_score,
                f.in_kev,
                f.status,
                s.priority_tier if s else "",
                s.likelihood if s else "",
                date_str,
            )
        ])
        count += 1

    data = buf.getvalue().encode("utf-8")
    filters = {"priority": priority, "status": status, "asset_id": asset_id, "q": q, "sort": sort}
    digest = _log_export(db, user, "csv", filters, count, data)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return StreamingResponse(
        iter([data]),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="securevision-findings-{stamp}.csv"',
            "X-Content-SHA256": digest,
            "X-Row-Count": str(count),
            "Access-Control-Expose-Headers": "Content-Disposition, X-Content-SHA256, X-Row-Count",
        },
    )


def _t(s) -> str:
    """fpdf2 core fonts are latin-1 only."""
    return str(s if s is not None else "").encode("latin-1", "replace").decode("latin-1")


def _table(pdf: FPDF, headers, widths, rows):
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(230, 233, 240)
    for h, wd in zip(headers, widths):
        pdf.cell(wd, 7, _t(h), border=1, fill=True)
    pdf.ln()
    pdf.set_font("Helvetica", "", 9)
    for r in rows:
        for v, wd in zip(r, widths):
            pdf.cell(wd, 6, _t(v)[: int(wd / 1.9)], border=1)
        pdf.ln()


@router.get("/executive.pdf")
def export_executive_pdf(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    now = datetime.now(timezone.utc)
    tier_counts = dict(
        db.query(FindingScore.priority_tier, func.count(func.distinct(FindingScore.finding_id)))
        .group_by(FindingScore.priority_tier)
        .all()
    )
    total_findings = db.query(func.count(Finding.id)).scalar() or 0

    top = (
        db.query(Finding, Asset)
        .join(Asset, Finding.asset_id == Asset.id)
        .join(FindingScore, FindingScore.finding_id == Finding.id)
        .filter(func.lower(FindingScore.priority_tier) == "critical")
        .order_by(Finding.in_kev.desc(), Finding.cvss_score.desc(), Finding.id.asc())
        .limit(10)
        .all()
    )

    crit_sum = func.sum(case((func.lower(FindingScore.priority_tier) == "critical", 1), else_=0))
    assets = (
        db.query(
            Asset.name,
            Asset.exposure,
            Asset.criticality,
            func.count(func.distinct(Finding.id)),
            crit_sum,
        )
        .outerjoin(Finding, Finding.asset_id == Asset.id)
        .outerjoin(FindingScore, FindingScore.finding_id == Finding.id)
        .group_by(Asset.id)
        .order_by(crit_sum.desc(), func.count(func.distinct(Finding.id)).desc())
        .limit(15)
        .all()
    )

    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, "SecureVision - Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Generated: {now.strftime('%Y-%m-%d %H:%M UTC')}  |  By: {_t(user.username)}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Total findings: {total_findings}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Findings by priority tier", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "B", 11)
    for t in TIERS:
        pdf.cell(47, 14, f"{t}: {tier_counts.get(t, 0)}", border=1, align="C")
    pdf.ln(20)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Top critical findings", new_x="LMARGIN", new_y="NEXT")
    _table(
        pdf,
        ["CVE", "Asset", "CVSS", "KEV", "Status"],
        [38, 62, 20, 20, 50],
        [(f.cve_id, a.name, f.cvss_score, "Yes" if f.in_kev else "No", f.status) for f, a in top]
        or [("No critical findings", "", "", "", "")],
    )
    pdf.ln(6)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Asset summary (top 15 by critical findings)", new_x="LMARGIN", new_y="NEXT")
    _table(
        pdf,
        ["Asset", "Exposure", "Criticality", "Findings", "Critical"],
        [62, 34, 34, 30, 30],
        [(n, e, c, tot or 0, crit or 0) for n, e, c, tot, crit in assets]
        or [("No assets", "", "", "", "")],
    )

    data = bytes(pdf.output())
    _log_export(db, user, "pdf", {}, len(top), data)
    stamp = now.strftime("%Y%m%d-%H%M%S")
    return Response(
        content=data,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="securevision-executive-{stamp}.pdf"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )