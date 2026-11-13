import argparse
import csv
from pathlib import Path

from sqlalchemy import MetaData, Table, create_engine
from sqlalchemy.dialects.postgresql import insert


CATALOG_COLUMNS = (
    "cve_id",
    "published_date",
    "description",
    "cvss_score",
    "cvss_vector",
    "cwe",
    "kev_date_added",
    "epss",
    "percentile",
    "in_kev",
)
FLOAT_COLUMNS = ("cvss_score", "epss", "percentile")


def _float_or_none(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _record(row: dict[str, str]) -> dict:
    cve_id = (row.get("cve_id") or "").strip().upper()
    if not cve_id:
        raise ValueError("CSV contains a row without cve_id.")
    record = {
        column: (row.get(column) or "").strip() or None
        for column in CATALOG_COLUMNS
        if column not in FLOAT_COLUMNS and column != "in_kev"
    }
    for column in FLOAT_COLUMNS:
        record[column] = _float_or_none(row.get(column))
    record["cve_id"] = cve_id
    record["in_kev"] = (row.get("in_kev") or "").strip().casefold() in {
        "1",
        "true",
    }
    return record


def _upsert_batch(connection, table: Table, records: list[dict]) -> None:
    unique_records = {record["cve_id"]: record for record in records}
    statement = insert(table).values(list(unique_records.values()))
    updates = {
        column: getattr(statement.excluded, column)
        for column in CATALOG_COLUMNS
        if column != "cve_id"
    }
    connection.execute(
        statement.on_conflict_do_update(
            index_elements=[table.c.cve_id],
            set_=updates,
        )
    )


def load_csv(owner_url: str, csv_path: Path, batch_size: int = 1000) -> int:
    if batch_size < 1:
        raise ValueError("batch_size must be greater than zero.")
    engine = create_engine(owner_url)
    try:
        table = Table("cve_catalog", MetaData(), autoload_with=engine)
        input_rows = 0
        batch = []
        with Path(csv_path).open("r", encoding="utf-8-sig", newline="") as source:
            reader = csv.DictReader(source)
            missing_columns = set(CATALOG_COLUMNS).difference(reader.fieldnames or ())
            if missing_columns:
                raise ValueError(
                    "CSV is missing required columns: "
                    + ", ".join(sorted(missing_columns))
                )
            with engine.begin() as connection:
                for row in reader:
                    batch.append(_record(row))
                    input_rows += 1
                    if len(batch) >= batch_size:
                        _upsert_batch(connection, table, batch)
                        batch.clear()
                if batch:
                    _upsert_batch(connection, table, batch)
        return input_rows
    finally:
        engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Manually stream a prepared CVE CSV into the PostgreSQL catalog."
    )
    parser.add_argument("owner_url", help="Owner-role PostgreSQL URL")
    parser.add_argument("csv_path", type=Path, help="Prepared CVE CSV path")
    parser.add_argument("--batch-size", type=int, default=1000)
    args = parser.parse_args()
    processed = load_csv(args.owner_url, args.csv_path, args.batch_size)
    print(f"Processed {processed} CSV rows into cve_catalog.")


if __name__ == "__main__":
    main()
