from backend.database import engine, SessionLocal
from backend import models # MUST import models so Base knows about them
from backend.auth import get_initial_admin_password, get_password_hash

print('Creating database tables...')
models.Base.metadata.create_all(bind=engine)

db = SessionLocal()
try:
    admin = db.query(models.User).filter(models.User.username == 'admin').first()
    if admin is None:
        password = get_initial_admin_password()
        admin = models.User(username='admin', hashed_password=get_password_hash(password), role='admin')
        db.add(admin)
        db.flush()
        db.add(models.AuditLog(
            action='ADMIN_BOOTSTRAPPED',
            details='Initial administrator account created from deployment configuration.',
        ))
        db.commit()
        print('Initial admin user created.')
    else:
        print('Admin user already exists; use update_admin.py to rotate its password.')
finally:
    db.close()
print('Database initialization complete.')
