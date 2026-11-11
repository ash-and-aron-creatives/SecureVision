import argparse
from collections import defaultdict

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend import models


def dedupe_findings(database_url: str) -> int:
    engine = create_engine(database_url)
    merged = 0
    try:
        with Session(engine) as db, db.begin():
            groups: dict[tuple[int, str], list[models.Finding]] = defaultdict(list)
            for finding in db.query(models.Finding).order_by(models.Finding.id.asc()).all():
                groups[(finding.asset_id, finding.cve_id.strip().upper())].append(finding)

            for findings in groups.values():
                if len(findings) < 2:
                    continue
                keeper = findings[0]
                for duplicate in findings[1:]:
                    db.query(models.FindingScore).filter(
                        models.FindingScore.finding_id == duplicate.id
                    ).update(
                        {models.FindingScore.finding_id: keeper.id},
                        synchronize_session=False,
                    )
                    db.delete(duplicate)
                    merged += 1
        return merged
    finally:
        engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Merge duplicate findings by asset and CVE.")
    parser.add_argument("database_url", help="SQLAlchemy URL of the database to update")
    args = parser.parse_args()
    print(f"Merged {dedupe_findings(args.database_url)} duplicate finding(s).")


if __name__ == "__main__":
    main()
