raise SystemExit(
    "This legacy entry point is disabled. Use the administrator user-management API "
    "PATCH /users/{user_id} to change the role."
)

from backend.database import SessionLocal
from backend.models import User
db = SessionLocal()
admin = db.query(User).filter(User.username == 'admin').first()
if admin:
    admin.role = 'admin'
    db.commit()
db.close()
