import os

from backend import models
from backend.auth import get_initial_admin_password, get_password_hash
from backend.database import SessionLocal
from backend.rules_config import (
    SYNTHETIC_DEMO_MODE_ENV,
    SYNTHETIC_DEMO_ASSETS,
    SYNTHETIC_DEMO_FINDINGS,
    SYNTHETIC_DEMO_SEED_ACTION,
)
from backend.scoring_engine import calculate_priority


def seed_synthetic_demo() -> None:
    if os.getenv(SYNTHETIC_DEMO_MODE_ENV, "").casefold() != "true":
        raise RuntimeError(
            f"Synthetic demo seeding requires {SYNTHETIC_DEMO_MODE_ENV}=true."
        )

    with SessionLocal() as db:
        admin = db.query(models.User).filter_by(username="admin").first()
        if admin is None:
            admin = models.User(
                username="admin",
                hashed_password=get_password_hash(get_initial_admin_password()),
                role="admin",
            )
            db.add(admin)
            db.flush()
            db.add(models.AuditLog(
                user_id=admin.id,
                action="ADMIN_BOOTSTRAPPED",
                details="Initial administrator account created from deployment configuration.",
            ))
            db.commit()
            print("Synthetic demo database initialized; administrator created.")
        else:
            print("Synthetic demo database initialized; administrator already exists.")

        if db.query(models.AuditLog).filter_by(
            action=SYNTHETIC_DEMO_SEED_ACTION
        ).first():
            print("Synthetic demo records already present; leaving them unchanged.")
            return

        if db.query(models.Asset).count() or db.query(models.Finding).count():
            print("Existing records found; synthetic demo seeding skipped.")
            return

        assets = {
            entry["name"]: models.Asset(**entry)
            for entry in SYNTHETIC_DEMO_ASSETS
        }
        db.add_all(assets.values())
        db.flush()

        for entry in SYNTHETIC_DEMO_FINDINGS:
            asset = assets[entry["asset_name"]]
            scoring = calculate_priority(
                entry["in_kev"],
                asset.exposure.casefold() == "internet",
                asset.criticality,
                entry["epss_percentile"],
                entry["cvss_score"],
            )
            finding = models.Finding(
                asset_id=asset.id,
                cve_id=entry["cve_id"],
                cvss_score=entry["cvss_score"],
                in_kev=entry["in_kev"],
                status=entry["status"],
                date_found=entry["date_found"],
            )
            db.add(finding)
            db.flush()
            db.add(models.FindingScore(
                finding_id=finding.id,
                provider_id=1,
                likelihood=entry["epss_percentile"],
                priority_tier=scoring["tier"],
                provenance={
                    "source": "Synthetic demo seed; not an observed vulnerability",
                    "in_kev": entry["in_kev"],
                    "cvss": entry["cvss_score"],
                    "epss": entry["epss_percentile"],
                    "score": scoring["score"],
                    "scoring_explanation": scoring["explanation"],
                },
                explanation=scoring["explanation"]["summary"],
                ml_unavailable_reason=(
                    "Synthetic demo seed has no NVD enrichment; ML advisory was not evaluated."
                ),
            ))

        db.add(models.AuditLog(
            user_id=admin.id,
            action=SYNTHETIC_DEMO_SEED_ACTION,
            details="Created clearly labeled synthetic demo assets and findings.",
        ))
        db.commit()
        print(
            f"Seeded {len(SYNTHETIC_DEMO_ASSETS)} synthetic assets and "
            f"{len(SYNTHETIC_DEMO_FINDINGS)} synthetic findings."
        )


if __name__ == "__main__":
    seed_synthetic_demo()
