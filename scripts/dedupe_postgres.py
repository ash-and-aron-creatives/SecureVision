#!/usr/bin/env python3
"""Manually merge duplicate PostgreSQL finding score history before migration 0003."""

import argparse

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


def _duplicate_groups(connection):
    rows = connection.execute(
        text(
            """
            SELECT asset_id, cve_id, array_agg(id ORDER BY id) AS finding_ids,
                   sum((SELECT count(*) FROM finding_scores s WHERE s.finding_id = f.id))
                       AS score_count
            FROM findings f
            WHERE asset_id IS NOT NULL AND cve_id IS NOT NULL
            GROUP BY asset_id, cve_id
            HAVING count(*) > 1
            ORDER BY asset_id, cve_id
            """
        )
    ).mappings()
    return list(rows)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Show duplicate finding groups and the score-history merge plan. "
            "No data is changed unless --apply is explicitly supplied."
        )
    )
    parser.add_argument("database_url", help="PostgreSQL URL for the owner/migrator role")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Print changes only (default)")
    mode.add_argument("--apply", action="store_true", help="Move score history and delete duplicates")
    args = parser.parse_args()

    if make_url(args.database_url).get_backend_name() != "postgresql":
        parser.error("database_url must use PostgreSQL.")

    engine = create_engine(args.database_url)
    try:
        with engine.begin() as connection:
            if args.apply:
                connection.execute(text("LOCK TABLE findings IN ACCESS EXCLUSIVE MODE"))
                connection.execute(text("LOCK TABLE finding_scores IN ACCESS EXCLUSIVE MODE"))

            groups = _duplicate_groups(connection)
            if not groups:
                print("No duplicate findings found.")
                return 0

            for group in groups:
                ids = list(group["finding_ids"])
                keep_id, duplicate_ids = ids[0], ids[1:]
                print(
                    f"asset_id={group['asset_id']} cve_id={group['cve_id']} "
                    f"keep finding_id={keep_id}; merge score history from {duplicate_ids}; "
                    f"total score rows={group['score_count']}"
                )
                if args.apply:
                    for duplicate_id in duplicate_ids:
                        connection.execute(
                            text(
                                "UPDATE finding_scores SET finding_id = :keep_id "
                                "WHERE finding_id = :duplicate_id"
                            ),
                            {"keep_id": keep_id, "duplicate_id": duplicate_id},
                        )
                        connection.execute(
                            text("DELETE FROM findings WHERE id = :duplicate_id"),
                            {"duplicate_id": duplicate_id},
                        )

            if args.apply:
                print(f"Applied duplicate finding merges for {len(groups)} group(s).")
            else:
                print(
                    f"DRY RUN: no changes made for {len(groups)} group(s). "
                    "Pass --apply to write."
                )
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
