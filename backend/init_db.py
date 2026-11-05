from backend.database import Base, SessionLocal, engine
from backend.models import AuditLog, User
from backend.auth import get_initial_admin_password, get_password_hash

def seed_database():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        admin_user = db.query(User).filter(User.username == "admin").first()
        if admin_user is None:
            admin_user = User(
                username="admin",
                hashed_password=get_password_hash(get_initial_admin_password()),
                role="admin",
            )
            db.add(admin_user)
            db.flush()
            db.add(
                AuditLog(
                    action="ADMIN_BOOTSTRAPPED",
                    details="Initial administrator account created from deployment configuration.",
                )
            )
            db.commit()
            print("Database initialized. Initial admin created.")
        else:
            print("Database initialized. Admin already exists; use update_admin.py to rotate its password.")
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
