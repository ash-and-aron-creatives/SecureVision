from backend.database import SessionLocal
from backend.models import User
from backend.auth import get_password_hash

db = SessionLocal()
admin = db.query(User).filter(User.username == 'admin').first()
if admin:
    admin.hashed_password = get_password_hash('password123')
    db.commit()
    print("\n[+] Admin password upgraded to 600,000 iterations.")
db.close()
