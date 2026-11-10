from __future__ import annotations

import csv
import datetime as dt
import io
import re
from dataclasses import asdict, dataclass
from backend.rules_config import ASSET_NAME_MAX_LENGTH

MAX_BYTES = 5 * 1024 * 1024
MAX_ROWS = 5000
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

HEADER_ALIASES = {
    "asset_name": ("assetname", "hostname", "host", "dns", "fqdn", "ip", "hostip", "ipaddress", "assetip"),
    "cve_id": ("cve", "cveid", "cves", "cveids", "vulnerabilityid"),
    "date_found": (
        "datefound", "firstdetected", "firstdetection", "datefirstdetected",
        "firstdiscovered", "firstseen", "firstfound", "lastseen", "lastfound",
        "lastobserved", "detectiondate", "creationtime",
        "date", "discovered",
    ),
    "cvss_score": ("cvss", "cvssscore", "cvssv2", "cvssv3", "cvssbase", "cvssbasescore", "basecvss"),
}
ASSET_ALIASES = HEADER_ALIASES["asset_name"]


class ImportFileError(ValueError):
    pass


@dataclass
class RowResult:
    line: int
    asset_name: str
    cve_id: str
    date_found: str
    status: str
    reason: str = ""
    asset_id: int | None = None
    cvss_score: float | None = None

    def as_dict(self) -> dict:
        return asdict(self)


def safe_cell(value) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def _normalise_header(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.strip().lstrip("\ufeff").casefold())


def detect_format(headers: list[str]) -> str:
    names = {_normalise_header(header) for header in headers}
    if "nvtname" in names or ({"oid", "threat"} <= names and "cve" in names):
        return "OpenVAS/Greenbone"
    if "qid" in names or ("firstdetected" in names and "dns" in names):
        return "Qualys"
    if "pluginid" in names or ("pluginname" in names and ("hostip" in names or "risk" in names)):
        return "Nessus"
    return "Generic"


def _date_value(value: str) -> dt.date:
    value = value.strip()
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        pass

    for date_format in ("%d/%m/%Y", "%m/%d/%Y"):
        try:
            return dt.datetime.strptime(value, date_format).date()
        except ValueError:
            continue
    raise ValueError("invalid date")


def parse_and_validate(
    data: bytes,
    assets_by_name: dict[str, int],
    existing_pairs: set[tuple[int, str]],
    today: dt.date | None = None,
    allow_missing_assets: bool = False,
) -> tuple[list[RowResult], dict]:
    today = today or dt.date.today()
    if len(data) > MAX_BYTES:
        raise ImportFileError("The file is larger than 5 MB.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ImportFileError("The file must be UTF-8 text (save it as CSV UTF-8).") from exc

    reader = csv.reader(io.StringIO(text, newline=""))
    try:
        original_headers = next(reader)
    except StopIteration:
        raise ImportFileError("The file is empty.")
    if not original_headers:
        raise ImportFileError("The file is empty.")

    headers = [_normalise_header(header) for header in original_headers]
    column_indexes: dict[str, list[int]] = {}
    for canonical, aliases in HEADER_ALIASES.items():
        column_indexes[canonical] = [
            index
            for index, header in enumerate(headers)
            if header in aliases
            or (
                canonical == "cvss_score"
                and header.startswith("cvss")
                and ("score" in header or "base" in header or header in ("cvssv31", "cvssv30"))
            )
        ]

    missing = [name for name in ("asset_name", "cve_id", "date_found") if not column_indexes[name]]
    if missing:
        display_names = {"asset_name": "asset_name/hostname/IP", "cve_id": "CVE", "date_found": "date_found"}
        raise ImportFileError("Missing required column(s): " + ", ".join(display_names[name] for name in missing))

    lookup = {name.strip().casefold(): asset_id for name, asset_id in assets_by_name.items()}
    existing = {(asset_id, cve_id.upper()) for asset_id, cve_id in existing_pairs}
    seen: set[tuple[str, str]] = set()
    results: list[RowResult] = []
    row_count = 0

    for source_row in reader:
        if not source_row:
            continue
        row_count += 1
        if row_count > MAX_ROWS:
            raise ImportFileError("The file has more than 5,000 rows.")
        line = reader.line_num

        def values(field: str) -> list[str]:
            return [
                source_row[index].strip() if index < len(source_row) and source_row[index] else ""
                for index in column_indexes[field]
            ]

        asset_candidates = [
            source_row[index].strip()
            for alias in ASSET_ALIASES
            for index, header in enumerate(headers)
            if header == alias and index < len(source_row) and source_row[index].strip()
        ]
        asset_name = next(iter(asset_candidates), "")
        asset_id = next(
            (lookup[candidate.casefold()] for candidate in asset_candidates if candidate.casefold() in lookup),
            None,
        )
        raw_cves = values("cve_id")
        cve_text = " ".join(value for value in raw_cves if value)
        matches = [match.group(0).upper() for match in CVE_RE.finditer(cve_text)]
        if not matches:
            matches = [cve_text.upper()] if cve_text else [""]
        date_raw = next((value for value in values("date_found") if value), "")
        cvss_raw = next((value for value in values("cvss_score") if value), "")

        cvss_score = None
        cvss_error = ""
        if cvss_raw:
            try:
                cvss_score = float(cvss_raw)
                if not 0 <= cvss_score <= 10:
                    raise ValueError
            except ValueError:
                cvss_error = "cvss_score must be a number between 0 and 10."
                cvss_score = None

        parsed_date: dt.date | None = None
        date_error = ""
        try:
            parsed_date = _date_value(date_raw)
            if parsed_date > today:
                date_error = "date_found cannot be in the future."
        except ValueError:
            date_error = "date_found must be YYYY-MM-DD, DD/MM/YYYY, MM/DD/YYYY, or an ISO datetime."

        for cve_id in matches:
            errors: list[str] = []
            if not asset_name:
                errors.append("asset_name is empty.")
            elif len(asset_name) > ASSET_NAME_MAX_LENGTH:
                errors.append(f"asset_name must be at most {ASSET_NAME_MAX_LENGTH} characters.")
            elif any(ord(char) < 32 or ord(char) == 127 for char in asset_name):
                errors.append("asset_name cannot contain control characters.")
            elif asset_id is None and not allow_missing_assets:
                errors.append("Unknown asset. Create it first.")

            if not cve_id:
                errors.append("No CVE found in this row.")
            elif not CVE_RE.fullmatch(cve_id):
                errors.append("cve_id must look like CVE-2021-44228.")
            if date_error:
                errors.append(date_error)
            if cvss_error:
                errors.append(cvss_error)

            row_asset_id = asset_id
            if errors:
                status = "error"
            else:
                status = "ok"
                if row_asset_id is not None:
                    row_key = f"id:{row_asset_id}"
                else:
                    row_key = f"name:{asset_name.casefold()}"
                pair_key = (row_key, cve_id)
                if pair_key in seen:
                    status, errors = "duplicate", ["Repeated in this file."]
                elif row_asset_id is not None and (row_asset_id, cve_id) in existing:
                    status, errors = "duplicate", ["This finding already exists."]
                else:
                    seen.add(pair_key)

            results.append(RowResult(
                line=line,
                asset_name=asset_name,
                cve_id=cve_id,
                date_found=parsed_date.isoformat() if parsed_date else date_raw,
                status=status,
                reason=" ".join(errors),
                asset_id=row_asset_id,
                cvss_score=cvss_score,
            ))

    summary = {"total": len(results)}
    for key in ("ok", "error", "duplicate"):
        summary[key] = sum(1 for result in results if result.status == key)
    return results, summary


def problems_to_csv(results: list[RowResult]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["line", "asset_name", "cve_id", "date_found", "status", "reason"])
    for result in results:
        if result.status != "ok":
            writer.writerow([
                result.line,
                safe_cell(result.asset_name),
                safe_cell(result.cve_id),
                safe_cell(result.date_found),
                result.status,
                safe_cell(result.reason),
            ])
    return out.getvalue()
