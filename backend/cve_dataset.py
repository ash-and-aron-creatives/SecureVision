from sqlalchemy import or_
from sqlalchemy.orm import Session

from backend.models import CVECatalog


def _record(row: CVECatalog) -> dict:
    return {
        "cve_id": row.cve_id,
        "published_date": row.published_date,
        "description": row.description,
        "cvss_score": row.cvss_score,
        "cvss_vector": row.cvss_vector,
        "cwe": row.cwe,
        "kev_date_added": row.kev_date_added,
        "epss": row.epss,
        "percentile": row.percentile,
        "in_kev": row.in_kev,
    }


def lookup_catalog(db: Session, cve_id: str) -> dict | None:
    row = db.query(CVECatalog).filter_by(cve_id=cve_id).first()
    return _record(row) if row is not None else None


def search_catalog(db: Session, query: str, limit: int) -> tuple[dict, ...]:
    needle = f"%{query}%"
    rows = (
        db.query(CVECatalog)
        .filter(
            or_(
                CVECatalog.cve_id.ilike(needle),
                CVECatalog.description.ilike(needle),
            )
        )
        .order_by(CVECatalog.cve_id.asc())
        .limit(limit)
        .all()
    )
    return tuple(_record(row) for row in rows)
