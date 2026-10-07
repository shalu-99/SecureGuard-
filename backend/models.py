from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.sql import func

from backend.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(150), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    status = Column(String(20), default="active")
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    event_type = Column(String(100), nullable=False)
    ip_address = Column(String(50), nullable=True)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    event_type = Column(String(100), nullable=False)
    severity = Column(String(20), default="medium")
    message = Column(Text, nullable=False)
    status = Column(String(20), default="new")
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    ip_address = Column(String(50), nullable=True)
    success = Column(Boolean, default=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())