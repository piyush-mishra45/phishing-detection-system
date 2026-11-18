"""SQLAlchemy ORM models (see database/schema.sql for the equivalent MySQL DDL)."""
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.mysql import LONGTEXT
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.db import Base


BigText = Text().with_variant(LONGTEXT(), "mysql")  # MySQL TEXT is capped at 64 KB


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="user")  # user | admin
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    email_scans = relationship("EmailScan", back_populates="user", cascade="all, delete-orphan")
    website_scans = relationship("WebsiteScan", back_populates="user", cascade="all, delete-orphan")
    history = relationship("ScanHistory", back_populates="user", cascade="all, delete-orphan")


class EmailScan(Base):
    __tablename__ = "email_scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    sender_email: Mapped[str] = mapped_column(String(255), default="")
    subject: Mapped[str] = mapped_column(String(500), default="")
    # PRIVACY: only a short, PII-redacted excerpt is stored, never the full email.
    email_content: Mapped[str] = mapped_column(Text, default="")
    prediction: Mapped[str] = mapped_column(String(20), index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    report_json: Mapped[str] = mapped_column(BigText, default="{}")  # extra: full report for the detail view
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    user = relationship("User", back_populates="email_scans")


class WebsiteScan(Base):
    __tablename__ = "website_scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(String(2048))
    domain: Mapped[str] = mapped_column(String(255), index=True)
    prediction: Mapped[str] = mapped_column(String(20), index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    ssl_status: Mapped[str] = mapped_column(String(30), default="unknown")
    report_json: Mapped[str] = mapped_column(BigText, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    user = relationship("User", back_populates="website_scans")


class ScanHistory(Base):
    __tablename__ = "scan_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    scan_type: Mapped[str] = mapped_column(String(10))  # email | website
    scan_reference_id: Mapped[int] = mapped_column(Integer)  # id in email_scans / website_scans
    status: Mapped[str] = mapped_column(String(20), default="completed")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    user = relationship("User", back_populates="history")
    features = relationship("ScanFeature", back_populates="scan", cascade="all, delete-orphan")
    __table_args__ = (Index("ix_history_type_ref", "scan_type", "scan_reference_id"),)


class ScanFeature(Base):
    """scan_id references scan_history.id (a polymorphic FK to two scan tables is not possible)."""
    __tablename__ = "scan_features"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_history.id", ondelete="CASCADE"), index=True)
    feature_name: Mapped[str] = mapped_column(String(100))
    feature_value: Mapped[str] = mapped_column(Text, default="")
    risk_reason: Mapped[str] = mapped_column(String(500), default="")
    scan = relationship("ScanHistory", back_populates="features")


class ModelMetric(Base):
    __tablename__ = "model_metrics"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    model_name: Mapped[str] = mapped_column(String(100), index=True)
    accuracy: Mapped[float] = mapped_column(Float)
    precision: Mapped[float] = mapped_column(Float)
    recall: Mapped[float] = mapped_column(Float)
    f1_score: Mapped[float] = mapped_column(Float)
    roc_auc: Mapped[float] = mapped_column(Float, nullable=True)
    trained_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    # extras so the UI can be honest about where the numbers come from
    confusion_matrix: Mapped[str] = mapped_column(String(200), default="[]")
    dataset: Mapped[str] = mapped_column(String(255), default="")
    is_demo_data: Mapped[int] = mapped_column(Integer, default=0)
