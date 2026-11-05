from backend.auth import get_initial_admin_password, get_password_hash
from backend.database import SessionLocal
from backend.models import AuditLog, User

db = SessionLocal()
try:
    admin = db.query(User).filter(User.username == 'admin').first()
    if admin is None:
        raise RuntimeError("Admin user does not exist; run init_db.py first.")
    admin.hashed_password = get_password_hash(get_initial_admin_password())
    db.add(
        AuditLog(
            user_id=admin.id,
            action='ADMIN_PASSWORD_ROTATED',
            details='Administrator password rotated through the maintenance script.',
        )
    )
    db.commit()
    print("Admin password updated.")
finally:
    db.close()
