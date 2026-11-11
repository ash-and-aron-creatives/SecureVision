"""Manually copy supported SecureVision records from SQLite to PostgreSQL."""

import argparse
from datetime import datetime, timezone

from sqlalchemy import DateTime, MetaData, Table, create_engine, inspect, text
from sqlalchemy.engine import URL, make_url

from backend.rules_config import (
    ASSET_DEFAULT_ENVIRONMENT,
    ASSET_DEFAULT_IP_OR_DOMAIN,
    ASSET_DEFAULT_NEEDS_REVIEW,
    ASSET_DEFAULT_OWNER,
    ASSET_DEFAULT_TYPE,
)


TABLES = ("users", "assets", "findings", "finding_scores", "audit_logs")
BATCH_SIZE = 1000
ASSET_COPY_DEFAULTS = {
    "type": ASSET_DEFAULT_TYPE,
    "ip_or_domain": ASSET_DEFAULT_IP_OR_DOMAIN,
    "owner": ASSET_DEFAULT_OWNER,
    "environment": ASSET_DEFAULT_ENVIRONMENT,
    "needs_review": ASSET_DEFAULT_NEEDS_REVIEW,
}


def _read_only_sqlite_url(source_url: URL) -> URL:
    query = dict(source_url.query)
    query.update({"mode": "ro", "uri": "true"})
    return source_url.set(query=query)


def copy_data(source_url: str, target_url: str) -> dict[str, int]:
    source_parsed = make_url(source_url)
    target_parsed = make_url(target_url)
    if source_parsed.get_backend_name() != "sqlite":
        raise ValueError("The source URL must use SQLite.")
    if target_parsed.get_backend_name() != "postgresql":
        raise ValueError("The target URL must use PostgreSQL.")

    source_engine = create_engine(_read_only_sqlite_url(source_parsed))
    target_engine = create_engine(target_parsed)
    copied_counts = {}
    try:
        source_inspector = inspect(source_engine)
        target_inspector = inspect(target_engine)
        missing_source = set(TABLES) - set(source_inspector.get_table_names())
        missing_target = set(TABLES) - set(target_inspector.get_table_names())
        if missing_source:
            raise RuntimeError(f"Source is missing tables: {sorted(missing_source)}")
        if missing_target:
            raise RuntimeError(
                f"Target schema is not migrated; missing tables: {sorted(missing_target)}"
            )

        with target_engine.begin() as target_connection:
            target_tables = {
                table_name: Table(
                    table_name,
                    MetaData(),
                    autoload_with=target_connection,
                )
                for table_name in TABLES
            }
            source_tables = {
                table_name: Table(
                    table_name,
                    MetaData(),
                    autoload_with=source_engine,
                )
                for table_name in TABLES
            }
            for table_name in TABLES:
                existing_count = target_connection.execute(
                    text(f"SELECT COUNT(*) FROM {table_name}")
                ).scalar_one()
                if existing_count:
                    raise RuntimeError(
                        f"Target table {table_name} is not empty; refusing to merge."
                    )

            for table_name in TABLES:
                source_columns = {
                    column["name"]
                    for column in source_inspector.get_columns(table_name)
                }
                target_columns = {
                    column["name"]
                    for column in target_inspector.get_columns(table_name)
                }
                shared_columns = source_columns & target_columns
                missing_asset_values = (
                    {
                        column: value
                        for column, value in ASSET_COPY_DEFAULTS.items()
                        if column in target_columns and column not in source_columns
                    }
                    if table_name == "assets"
                    else {}
                )
                with source_engine.connect() as source_connection:
                    rows = source_connection.execution_options(
                        stream_results=True
                    ).execute(source_tables[table_name].select()).mappings()
                    batch = []
                    source_count = 0
                    for row in rows:
                        values = {
                            column: row[column]
                            for column in shared_columns
                        }
                        for column, value in values.items():
                            target_type = target_tables[table_name].c[column].type
                            if (
                                isinstance(target_type, DateTime)
                                and target_type.timezone
                                and isinstance(value, datetime)
                                and value.tzinfo is None
                            ):
                                values[column] = value.replace(tzinfo=timezone.utc)
                        batch.append({**values, **missing_asset_values})
                        source_count += 1
                        if len(batch) == BATCH_SIZE:
                            target_connection.execute(target_tables[table_name].insert(), batch)
                            batch.clear()
                    if batch:
                        target_connection.execute(target_tables[table_name].insert(), batch)
                copied_counts[table_name] = source_count

                if "id" in target_columns:
                    target_connection.execute(
                        text(
                            "SELECT setval("
                            f"pg_get_serial_sequence('{table_name}', 'id'), "
                            f"COALESCE(MAX(id), 1), COUNT(*) > 0) FROM {table_name}"
                        )
                    )

            for table_name, expected_count in copied_counts.items():
                actual_count = target_connection.execute(
                    text(f"SELECT COUNT(*) FROM {table_name}")
                ).scalar_one()
                if actual_count != expected_count:
                    raise RuntimeError(
                        f"Row-count verification failed for {table_name}: "
                        f"source={expected_count}, target={actual_count}."
                    )
        return copied_counts
    finally:
        source_engine.dispose()
        target_engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Manually copy users, assets, findings, score history, and audit rows "
            "from a read-only SQLite source into an empty migrated PostgreSQL target."
        )
    )
    parser.add_argument("source_url", help="SQLite SQLAlchemy URL (opened read-only)")
    parser.add_argument("target_url", help="PostgreSQL SQLAlchemy URL")
    args = parser.parse_args()

    counts = copy_data(args.source_url, args.target_url)
    for table_name, count in counts.items():
        print(f"{table_name}: copied and verified {count} row(s)")


if __name__ == "__main__":
    main()
