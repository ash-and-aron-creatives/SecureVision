from backend.database import SessionLocal, init_db
from backend.models import User, LikelihoodProvider
from backend.auth import get_password_hash
import sys

def seed_database():
    try:
        init_db()
        db = SessionLocal()
        admin_user = User(username="admin", hashed_password=get_password_hash("password123"), role="admin")
        db.add(admin_user)
        provider = LikelihoodProvider(name="EPSS+KEV", version="1.0", is_default=True)
        db.add(provider)
        db.commit()
        db.close()
        print("Database Initialized Successfully. Admin created.")
    except Exception as e:
        print(f"DATABASE INIT ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    seed_database()
