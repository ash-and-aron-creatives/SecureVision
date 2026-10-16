from __future__ import annotations
import csv
import datetime as dt
import io
import re
from dataclasses import dataclass, asdict

MAX_BYTES = 5 * 1024 * 1024
MAX_ROWS = 5000
REQUIRED = ("asset_name", "cve_id", "date_found")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

class ImportFileError(ValueError): pass

@dataclass
class RowResult:
    line: int
    asset_name: str
    cve_id: str
    date_found: str
    status: str
    reason: str = ""
    asset_id: int | None = None

    def as_dict(self) -> dict: return asdict(self)

def safe_cell(value) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text

def parse_and_validate(data: bytes, assets_by_name: dict[str, int], existing_pairs: set[tuple[int, str]], today: dt.date | None = None) -> tuple[list[RowResult], dict]:
    today = today or dt.date.today()
    if len(data) > MAX_BYTES: raise ImportFileError("The file is larger than 5 MB.")
    try: text = data.decode("utf-8-sig")
    except UnicodeDecodeError: raise ImportFileError("The file must be UTF-8 text (save it as CSV UTF-8).")

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames: raise ImportFileError("The file is empty.")
    header = [h.strip().lower() for h in reader.fieldnames]
    missing = [c for c in REQUIRED if c not in header]
    if missing: raise ImportFileError("Missing required column(s): " + ", ".join(missing))
    reader.fieldnames = header

    lookup = {name.casefold(): aid for name, aid in assets_by_name.items()}
    seen: set[tuple[int, str]] = set()
    results: list[RowResult] = []

    for index, row in enumerate(reader, start=2):
        if index - 1 > MAX_ROWS: raise ImportFileError("The file has more than 5,000 rows.")
        asset_name = (row.get("asset_name") or "").strip()
        cve_id = (row.get("cve_id") or "").strip().upper()
        date_raw = (row.get("date_found") or "").strip()
        res = RowResult(index, asset_name, cve_id, date_raw, "ok")

        asset_id = lookup.get(asset_name.casefold()) if asset_name else None
        if not asset_name: res.status, res.reason = "error", "asset_name is empty."
        elif asset_id is None: res.status, res.reason = "error", "Unknown asset. Create it first."
        elif not CVE_RE.match(cve_id): res.status, res.reason = "error", "cve_id must look like CVE-2021-44228."
        else:
            try: found = dt.date.fromisoformat(date_raw)
            except ValueError: res.status, res.reason = "error", "date_found must be YYYY-MM-DD."
            else:
                if found > today: res.status, res.reason = "error", "date_found cannot be in the future."
        if res.status == "ok":
            res.asset_id = asset_id
            pair = (asset_id, cve_id)
            if pair in seen: res.status, res.reason = "duplicate", "Repeated in this file."
            elif pair in existing_pairs: res.status, res.reason = "duplicate", "This finding already exists."
            else: seen.add(pair)
        results.append(res)

    summary = {"total": len(results)}
    for key in ("ok", "error", "duplicate"): summary[key] = sum(1 for r in results if r.status == key)
    return results, summary

def problems_to_csv(results: list[RowResult]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["line", "asset_name", "cve_id", "date_found", "status", "reason"])
    for r in results:
        if r.status != "ok":
            writer.writerow([r.line, safe_cell(r.asset_name), safe_cell(r.cve_id), safe_cell(r.date_found), r.status, r.reason])
    return out.getvalue()
