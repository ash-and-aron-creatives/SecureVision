raise SystemExit(
    "Legacy SQLite-era seeding is disabled. Use backend.demo_seed.seed_synthetic_demo "
    "with SECUREVISION_DEMO_MODE=true."
)

from backend.database import SessionLocal
from backend.models import Asset, Finding, FindingScore
from backend.scoring_engine import calculate_priority
import random

db = SessionLocal()

# 1. Wipe old test data (Leaves User/Admin table perfectly intact)
print("Cleaning old test data...")
db.query(FindingScore).delete()
db.query(Finding).delete()
db.query(Asset).delete()
db.commit()

# 2. Create Realistic Enterprise Assets
asset_data = [
    ("Corporate Public Website", "Internet", 4),
    ("Customer Payment Gateway", "Internet", 5),
    ("Internal HR Database", "Internal", 4),
    ("CEO Executive Laptop", "Internal", 5),
    ("Guest Wi-Fi Router", "Internet", 1),
    ("Marketing Team File Share", "Internal", 2),
    ("Main Active Directory Server", "Internal", 5),
    ("Legacy Email Server", "Internet", 4),
    ("Developer Workstation", "Internal", 3),
    ("Warehouse IoT Controller", "Internal", 3),
]

assets = []
for name, exposure, crit in asset_data:
    a = Asset(name=name, exposure=exposure, criticality=crit)
    db.add(a)
    assets.append(a)
db.commit()
for a in assets: db.refresh(a)

# 3. Famous and Generic Vulnerability Templates (CVE, Base CVSS, EPSS, KEV status)
cve_templates = [
    ("CVE-2021-44228", 10.0, 0.99, True),   # Log4j
    ("CVE-2021-26855", 9.8, 0.97, True),    # ProxyLogon
    ("CVE-2017-0144", 8.1, 0.95, True),     # EternalBlue
    ("CVE-2020-1472", 10.0, 0.90, True),    # Zerologon
    ("CVE-2026-0001", 5.3, 0.01, False),    # Generic Medium
    ("CVE-2026-0002", 3.1, 0.00, False),    # Generic Low
    ("CVE-2026-0003", 7.5, 0.20, False),    # Generic High
    ("CVE-2026-0004", 6.5, 0.05, False),    # Generic Medium
]

# 4. Generate 50 unique findings across the network
print("Running AI Scoring Engine on 50 simulated network vulnerabilities...")
for i in range(50):
    asset = random.choice(assets)
    cve_id, cvss, epss, kev = random.choice(cve_templates)
    
    # Slight randomization to make charts look natural
    f_cve = f"{cve_id}-{random.randint(10,99)}" if not kev else cve_id 
    f_cvss = round(min(10.0, cvss + random.uniform(-0.5, 0.5)), 1)
    f_epss = max(0.0, min(1.0, epss + random.uniform(-0.05, 0.05)))
    
    internet_facing = (asset.exposure.lower() == 'internet')
    scoring = calculate_priority(kev, internet_facing, asset.criticality, f_epss, f_cvss)
    tier = scoring["tier"]
    
    finding = Finding(asset_id=asset.id, cve_id=f_cve, cvss_score=f_cvss, in_kev=kev, status='Open')
    db.add(finding)
    db.commit()
    db.refresh(finding)
    
    score = FindingScore(
        finding_id=finding.id, provider_id=1, likelihood=f_epss, priority_tier=tier,
        provenance={
            "source": "Seeding Script",
            "score": scoring["score"],
            "scoring_explanation": scoring["explanation"],
        },
        explanation=scoring["explanation"]["summary"],
    )
    db.add(score)

db.commit()
db.close()
print("[+] Success! Database seeded with 10 Assets and 50 Vulnerabilities.")
