import csv
from functools import lru_cache
from pathlib import Path

from backend.rules_config import CVE_DATASET_PATH, CVE_SEARCH_MAX_RESULTS


def dataset_available() -> bool:
    return CVE_DATASET_PATH.is_file()


def _record(row: dict[str, str]) -> dict:
    return {
        "cve_id": row["cve_id"].strip().upper(),
        "published_date": row.get("published_date") or None,
        "description": row.get("description") or None,
        "cvss_score": _float_or_none(row.get("cvss_score")),
        "cvss_vector": row.get("cvss_vector") or None,
        "cwe": row.get("cwe") or None,
        "kev_date_added": row.get("kev_date_added") or None,
        "epss": _float_or_none(row.get("epss")),
        "percentile": _float_or_none(row.get("percentile")),
        "in_kev": row.get("in_kev", "").strip() in {"1", "true", "True"},
    }


def _float_or_none(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


@lru_cache(maxsize=512)
def lookup_cve(cve_id: str, dataset_path: str) -> dict | None:
    path = Path(dataset_path)
    with path.open("r", encoding="utf-8-sig", newline="") as dataset:
        for row in csv.DictReader(dataset):
            if (row.get("cve_id") or "").strip().upper() == cve_id:
                return _record(row)
    return None


@lru_cache(maxsize=64)
def search_cves(query: str, dataset_path: str) -> tuple[dict, ...]:
    path = Path(dataset_path)
    needle = query.casefold()
    matches = []
    with path.open("r", encoding="utf-8-sig", newline="") as dataset:
        for row in csv.DictReader(dataset):
            if needle in (row.get("cve_id") or "").casefold() or needle in (
                row.get("description") or ""
            ).casefold():
                matches.append(_record(row))
                if len(matches) >= CVE_SEARCH_MAX_RESULTS:
                    break
    return tuple(matches)
