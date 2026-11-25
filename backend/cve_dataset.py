from collections.abc import Awaitable, Callable

from sqlalchemy import or_
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from backend.models import CVECatalog


_CATALOG_FIELDS = {
    "published_date": "published_date",
    "description": "description",
    "cvss": "cvss_score",
    "cvss_vector": "cvss_vector",
    "cwe": "cwe",
    "kev_date_added": "kev_date_added",
    "epss": "epss",
    "epss_percentile": "percentile",
    "in_kev": "in_kev",
}
_REQUIRED_CATALOG_FIELDS = {"cvss", "epss_percentile", "description"}


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


def _is_missing(value) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


async def lookup_cve_intel(
    db: Session,
    cve_id: str,
    live_lookup: Callable[[str], Awaitable[dict]],
) -> dict:
    catalog = await run_in_threadpool(lookup_catalog, db, cve_id)
    missing_fields = (
        set(_CATALOG_FIELDS)
        if catalog is None
        else {
            field
            for field, catalog_field in _CATALOG_FIELDS.items()
            if field in _REQUIRED_CATALOG_FIELDS
            and _is_missing(catalog.get(catalog_field))
        }
    )
    live = await live_lookup(cve_id) if missing_fields else {}

    merged = dict(live)
    for field, catalog_field in _CATALOG_FIELDS.items():
        if catalog is not None and field not in missing_fields:
            merged[field] = catalog[catalog_field]
    if "epss_percentile" not in merged and "percentile" in merged:
        merged["epss_percentile"] = merged["percentile"]

    errors = list(live.get("errors", []))
    for field, message in (
        ("epss", "EPSS score is unavailable."),
        ("epss_percentile", "EPSS percentile is unavailable."),
        ("cvss", "NVD CVSS score is unavailable."),
    ):
        if _is_missing(merged.get(field)) and not errors and message not in errors:
            errors.append(message)

    merged.update(
        cve_id=cve_id,
        available=(
            not _is_missing(merged.get("epss"))
            and not _is_missing(merged.get("epss_percentile"))
            and not _is_missing(merged.get("cvss"))
        ),
        errors=errors,
        source="catalog" if catalog is not None and not missing_fields else "live",
        in_kev=bool(catalog.get("in_kev")) if catalog is not None else False,
    )
    return merged


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
