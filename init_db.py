from backend.database import engine, SessionLocal
from backend import models # MUST import models so Base knows about them
from backend.auth import get_password_hash

print('Creating database tables...')
models.Base.metadata.create_all(bind=engine)

print('Adding default admin user...')
db = SessionLocal()
db.add(models.User(username='admin', hashed_password=get_password_hash('password123'), role='admin'))
db.commit()
db.close()
print('Database initialization complete.')
