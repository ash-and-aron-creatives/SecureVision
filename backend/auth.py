import os
import hashlib
import hmac
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from backend.database import get_db
from backend import models
from backend.rules_config import (
    LOGIN_ATTEMPT_WINDOW_SECONDS,
    LOGIN_MAX_FAILED_ATTEMPTS,
    LOGIN_RATE_LIMIT_MAX_KEYS,
    LOGIN_USERNAME_MAX_LENGTH,
)
from sqlalchemy.orm import Session

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
MIN_SECRET_KEY_LENGTH = 32
MIN_PASSWORD_LENGTH = 8

# OWASP RECOMMENDED: 600,000 iterations for PBKDF2 HMAC SHA-256
ITERATIONS = 600000
_login_failures: dict[tuple[str, str], deque[float]] = {}
_login_failures_lock = threading.Lock()


def _prune_login_failures(now: float) -> None:
    expired_keys = []
    for key, failures in _login_failures.items():
        while failures and now - failures[0] >= LOGIN_ATTEMPT_WINDOW_SECONDS:
            failures.popleft()
        if not failures:
            expired_keys.append(key)
    for key in expired_keys:
        del _login_failures[key]


def login_attempt_allowed(username: str, client_ip: str) -> bool:
    now = time.monotonic()
    key = (username.strip()[:LOGIN_USERNAME_MAX_LENGTH].casefold(), client_ip)
    with _login_failures_lock:
        _prune_login_failures(now)
        if len(_login_failures.get(key, ())) >= LOGIN_MAX_FAILED_ATTEMPTS:
            return False
        if key not in _login_failures and len(_login_failures) >= LOGIN_RATE_LIMIT_MAX_KEYS:
            oldest = min(_login_failures, key=lambda item: _login_failures[item][0])
            del _login_failures[oldest]
        _login_failures.setdefault(key, deque()).append(now)
        return True


def clear_login_failures(username: str, client_ip: str) -> None:
    key = (username.strip()[:LOGIN_USERNAME_MAX_LENGTH].casefold(), client_ip)
    with _login_failures_lock:
        _login_failures.pop(key, None)


def reset_login_failures() -> None:
    with _login_failures_lock:
        _login_failures.clear()


def _get_secret_key() -> str:
    secret_key = os.getenv("SECRET_KEY")
    if not secret_key or len(secret_key) < MIN_SECRET_KEY_LENGTH:
        raise RuntimeError("SECRET_KEY must be configured with at least 32 characters.")
    return secret_key


def get_initial_admin_password() -> str:
    password = os.getenv("ADMIN_INITIAL_PASSWORD")
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        raise RuntimeError(
            f"ADMIN_INITIAL_PASSWORD must be configured with at least {MIN_PASSWORD_LENGTH} characters."
        )
    return password


def get_password_hash(password: str) -> str:
    salt = os.urandom(16)
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS)
    return f"{salt.hex()}:{hash_obj.hex()}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        salt_hex, hash_hex = hashed_password.split(':')
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hash_hex)
        actual_hash = hashlib.pbkdf2_hmac('sha256', plain_password.encode('utf-8'), salt, ITERATIONS)
        # MUST use hmac.compare_digest for constant-time comparison to prevent timing attacks
        return hmac.compare_digest(actual_hash, expected_hash)
    except Exception:
        return False

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, _get_secret_key(), algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, _get_secret_key(), algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise credentials_exception
    return user
