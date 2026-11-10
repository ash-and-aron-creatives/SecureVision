from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.auth import get_current_user, get_password_hash
from backend.models import AuditLog, User
from backend.schemas import DeletedUserResponse, UserResponse
from backend.rules_config import LOGIN_USERNAME_MAX_LENGTH

router = APIRouter(prefix="/users", tags=["users"])

VALID_ROLES = {"admin", "analyst", "viewer"}
MIN_PASSWORD_LEN = 8


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required.",
        )
    return current_user


class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: str = "analyst"


class UserUpdateRequest(BaseModel):
    role: Optional[str] = None
    password: Optional[str] = None


@router.get("", response_model=list[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    users = db.query(User).order_by(User.id.asc()).all()
    return [{"id": u.id, "username": u.username, "role": u.role} for u in users]


@router.post("", status_code=status.HTTP_201_CREATED, response_model=UserResponse)
def create_user(
    req: UserCreateRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    uname = req.username.strip()
    if not uname or len(uname) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters.")
    if len(uname) > LOGIN_USERNAME_MAX_LENGTH or any(
        ord(char) < 32 or ord(char) == 127 for char in uname
    ):
        raise HTTPException(
            status_code=400,
            detail=f"Username must be at most {LOGIN_USERNAME_MAX_LENGTH} characters and contain no control characters.",
        )
    if len(req.password) < MIN_PASSWORD_LEN:
        raise HTTPException(status_code=400, detail=f"Password must be at least {MIN_PASSWORD_LEN} characters.")
    if req.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="Role must be admin, analyst, or viewer.")

    exists = db.query(User).filter(func.lower(User.username) == uname.lower()).first()
    if exists:
        raise HTTPException(status_code=409, detail="Username already exists.")

    user = User(
        username=uname,
        hashed_password=get_password_hash(req.password),
        role=req.role,
    )
    try:
        db.add(user)
        db.flush()
        db.add(
            AuditLog(
                user_id=admin.id,
                action="USER_CREATED",
                details=f"Created user '{uname}' with role '{req.role}' (id={user.id})",
            )
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    db.refresh(user)
    return {"id": user.id, "username": user.username, "role": user.role}

@router.patch("/{user_id}", response_model=UserResponse)
@router.put("/{user_id}/role", response_model=UserResponse)
def update_user(
    user_id: int,
    req: UserUpdateRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")

    try:
        changes = []
        if req.role is not None:
            if req.role not in VALID_ROLES:
                raise HTTPException(status_code=400, detail="Role must be admin, analyst, or viewer.")
            if (
                target.role == "admin"
                and req.role != "admin"
                and db.query(func.count(User.id)).filter(User.role == "admin").scalar() <= 1
            ):
                raise HTTPException(status_code=400, detail="At least one administrator must remain.")
            if target.id == admin.id and req.role != "admin":
                raise HTTPException(status_code=400, detail="Administrators cannot demote themselves.")
            if target.role != req.role:
                old_role = target.role
                target.role = req.role
                changes.append(f"role:{old_role}->{req.role}")

        if req.password is not None and req.password != "":
            if len(req.password) < MIN_PASSWORD_LEN:
                raise HTTPException(status_code=400, detail=f"Password must be at least {MIN_PASSWORD_LEN} characters.")
            target.hashed_password = get_password_hash(req.password)
            changes.append("password_reset")

        if changes:
            db.add(
                AuditLog(
                    user_id=admin.id,
                    action="USER_UPDATED",
                    details=f"Updated user '{target.username}' (id={target.id}): {', '.join(changes)}",
                )
            )
            db.commit()
            db.refresh(target)
    except Exception:
        db.rollback()
        raise

    return {"id": target.id, "username": target.username, "role": target.role}

@router.delete("/{user_id}", response_model=DeletedUserResponse)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")
    if (
        target.role == "admin"
        and db.query(func.count(User.id)).filter(User.role == "admin").scalar() <= 1
    ):
        raise HTTPException(status_code=400, detail="At least one administrator must remain.")
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Administrators cannot delete themselves.")

    uname = target.username
    role = target.role
    try:
        db.delete(target)
        db.add(
            AuditLog(
                user_id=admin.id,
                action="USER_DELETED",
                details=f"Deleted user '{uname}' (id={user_id}, role={role})",
            )
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {"deleted": user_id, "username": uname}