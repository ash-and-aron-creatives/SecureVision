from sqlalchemy import Column, Integer, String, Float, Boolean, ForeignKey, JSON, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from backend.database import Base

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default='analyst')

class Asset(Base):
    __tablename__ = 'assets'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    type = Column(String, nullable=False, default='Other')
    ip_or_domain = Column(String, nullable=False, default='')
    owner = Column(String, nullable=False, default='')
    environment = Column(String, nullable=False, default='Unknown')
    exposure = Column(String)
    criticality = Column(Integer)
    needs_review = Column(Boolean, default=False, nullable=False)
    findings = relationship('Finding', back_populates='asset')

class CVECache(Base):
    __tablename__ = 'cves'
    cve_id = Column(String, primary_key=True)
    data = Column(JSON, nullable=False)

class Finding(Base):
    __tablename__ = 'findings'
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey('assets.id'))
    cve_id = Column(String, index=True)
    cvss_score = Column(Float)
    in_kev = Column(Boolean, default=False)
    status = Column(String, default='Open')
    date_found = Column(String, nullable=True) # <-- ADDED FOR CSV IMPORT
    asset = relationship('Asset', back_populates='findings')
    scores = relationship('FindingScore', back_populates='finding')

class FindingScore(Base):
    __tablename__ = 'finding_scores'
    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey('findings.id'))
    provider_id = Column(Integer)
    likelihood = Column(Float)
    priority_tier = Column(String)
    provenance = Column(JSON)
    explanation = Column(String)
    ml_likelihood = Column(Float, nullable=True)
    ml_risk = Column(Float, nullable=True)
    ml_priority = Column(String, nullable=True)
    ml_top_reasons = Column(JSON, nullable=True)
    ml_model_version = Column(String, nullable=True)
    ml_recommended_action = Column(String, nullable=True)
    ml_unavailable_reason = Column(String, nullable=True)
    finding = relationship('Finding', back_populates='scores')

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    action = Column(String)
    details = Column(String)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    user = relationship('User')

from sqlalchemy import event

@event.listens_for(AuditLog, 'before_update')
def _prevent_audit_update(mapper, connection, target):
    raise RuntimeError('AuditLog records are immutable and cannot be updated.')

@event.listens_for(AuditLog, 'before_delete')
def _prevent_audit_delete(mapper, connection, target):
    raise RuntimeError('AuditLog records are immutable and cannot be deleted.')
