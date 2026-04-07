from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from datetime import UTC, date, datetime
from pathlib import Path, PurePosixPath
from typing import Generator

import pyotp
import uvicorn
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from .parsers import parse_planning_workbook, parse_risk_register
from .settings import get_settings


settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
INTRUM_GANTT_PATH = Path("/Users/Farah/Tecnolife/Intrum/DD_Intrum/DD_Intrum-Ganttv1_2_EN.xlsx")
INTRUM_RISK_REGISTER_PATH = Path("/Users/Farah/Tecnolife/Intrum/DD_Intrum/ITA-DD_Intrum/DD_Intrum-Risk_Registerv1_0.xlsx")


def _connect_args() -> dict[str, object]:
    if settings.database_url.startswith("sqlite"):
        return {"check_same_thread": False}
    return {}


engine = create_engine(settings.database_url, future=True, connect_args=_connect_args())
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass


class Engagement(Base):
    __tablename__ = "engagements"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    client_name: Mapped[str] = mapped_column(String(120))
    project_name: Mapped[str] = mapped_column(String(120))
    contact_first_name: Mapped[str] = mapped_column(String(120))
    contact_last_name: Mapped[str] = mapped_column(String(120))
    start_date: Mapped[date] = mapped_column(Date)
    end_date: Mapped[date] = mapped_column(Date)
    scope_template: Mapped[str] = mapped_column(Text, default="")
    roe_template: Mapped[str] = mapped_column(Text, default="")
    planning_json: Mapped[str] = mapped_column(Text, default="{}")
    risk_register_json: Mapped[str] = mapped_column(Text, default="{}")
    telemetry_json: Mapped[str] = mapped_column(Text, default="{}")
    heartbeat_status: Mapped[str] = mapped_column(String(32), default="offline")
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    agent_key_hash: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    users: Mapped[list["User"]] = relationship(back_populates="engagement")
    deliverables: Mapped[list["Deliverable"]] = relationship(back_populates="engagement")
    events: Mapped[list["Event"]] = relationship(back_populates="engagement")
    notifications: Mapped[list["Notification"]] = relationship(back_populates="engagement")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int | None] = mapped_column(ForeignKey("engagements.id"), nullable=True)
    username: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(120))
    role: Mapped[str] = mapped_column(String(16), default="client")
    mfa_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    must_rotate_password: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    engagement: Mapped[Engagement | None] = relationship(back_populates="users")


class Deliverable(Base):
    __tablename__ = "deliverables"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"), index=True)
    kind: Mapped[str] = mapped_column(String(64))
    filename: Mapped[str] = mapped_column(String(255))
    path: Mapped[str] = mapped_column(Text)
    sha512: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    engagement: Mapped[Engagement] = relationship(back_populates="deliverables")


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"), index=True)
    kind: Mapped[str] = mapped_column(String(64))
    level: Mapped[str] = mapped_column(String(32))
    message: Mapped[str] = mapped_column(Text)
    payload_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    engagement: Mapped[Engagement] = relationship(back_populates="events")


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"), index=True)
    title: Mapped[str] = mapped_column(String(160))
    body: Mapped[str] = mapped_column(Text)
    level: Mapped[str] = mapped_column(String(32), default="info")
    read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    engagement: Mapped[Engagement] = relationship(back_populates="notifications")


class LoginRequest(BaseModel):
    username: str
    password: str


class MfaSetupRequest(BaseModel):
    token: str


class MfaVerifyRequest(BaseModel):
    token: str
    code: str


class EngagementCreateRequest(BaseModel):
    client_name: str
    project_name: str
    contact_first_name: str
    contact_last_name: str
    start_date: date
    end_date: date
    scope_template: str = ""
    roe_template: str = ""


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "engagement"


def _safe_upload_name(filename: str) -> str:
    candidate = PurePosixPath(filename.replace("\\", "/"))
    if candidate.is_absolute() or ".." in candidate.parts:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid upload path")
    normalized = candidate.as_posix().lstrip("./")
    if not normalized or normalized == ".":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing upload filename")
    return normalized


def _hash_password(password: str) -> str:
    return pwd_context.hash(password)


def _verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def _hash_agent_key(agent_key: str) -> str:
    return hashlib.sha256(agent_key.encode("utf-8")).hexdigest()


def _sign_token(payload: dict[str, object]) -> str:
    blob = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("utf-8")
    signature = hmac.new(settings.auth_secret.encode("utf-8"), blob.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{blob}.{signature}"


def _decode_token(token: str) -> dict[str, object]:
    try:
        blob, signature = token.split(".", 1)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed token") from exc
    expected = hmac.new(settings.auth_secret.encode("utf-8"), blob.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token signature")
    payload = json.loads(base64.urlsafe_b64decode(blob.encode("utf-8")).decode("utf-8"))
    if payload.get("exp", 0) < int(time.time()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    return payload


def _mint_access_token(user: User) -> str:
    return _sign_token(
        {
            "sub": user.id,
            "role": user.role,
            "engagement_id": user.engagement_id,
            "scope": "access",
            "exp": int(time.time()) + 60 * 60 * 12,
        }
    )


def _mint_mfa_token(user: User) -> str:
    return _sign_token(
        {
            "sub": user.id,
            "scope": "mfa",
            "exp": int(time.time()) + 60 * 10,
        }
    )


def _username_for(client_name: str, first_name: str, last_name: str) -> str:
    return f"{slugify(client_name)}.{first_name[:1].lower()}{slugify(last_name)}"


def _memorable_password(client_name: str, first_name: str, last_name: str, start_date: date) -> str:
    digest = hashlib.sha256(
        f"{client_name}|{first_name}|{last_name}|{start_date.isoformat()}|{settings.auth_secret}".encode("utf-8")
    ).hexdigest()[:4].upper()
    return f"{client_name[:3].title()}{first_name[:2].title()}{last_name[:2].title()}-{start_date:%d%m}-{digest}!"


def _admin_password() -> str:
    digest = hashlib.sha256(f"admin|{settings.auth_secret}".encode("utf-8")).hexdigest()[:5].upper()
    return f"Niobe-Admin-{digest}!"


def _agent_key_for(slug: str) -> str:
    digest = hashlib.sha256(f"{slug}|agent|{settings.auth_secret}".encode("utf-8")).hexdigest()[:32]
    return f"da_{slug}_{digest}"


def _json_load(value: str | None, default: object) -> object:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _json_dump(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, indent=2, default=str)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _default_faq() -> list[dict[str, str]]:
    return [
        {
            "question": "Perche vedo sia SBOM CycloneDX sia Syft JSON?",
            "answer": "CycloneDX e l artifact interoperabile; il JSON Syft e il raw output utile per riesecuzioni e validazione.",
        },
        {
            "question": "Cosa significa LIVE o OFFLINE nella barra superiore?",
            "answer": "LIVE significa che il tool remoto sta inviando heartbeat validi al control plane entro la finestra di timeout.",
        },
        {
            "question": "Perche alcuni deliverable arrivano prima dell'AI Technical Intelligence Review?",
            "answer": "Gli artifact tecnici sono pubblicati appena firmati; l'AI Technical Intelligence Review arriva solo dopo la fase finale di review.",
        },
    ]


def _default_planning() -> dict[str, object]:
    return {
        "tasks": [
            {"Task": "Kick-off, governance & evidence intake", "Start": "2026-03-26", "End": "2026-03-27", "Owner": "Tecnolife"},
            {"Task": "Compliance, RoE, provisioning", "Start": "2026-03-27", "End": "2026-03-30", "Owner": "Tecnolife"},
            {"Task": "OSS, trust boundaries, architecture", "Start": "2026-03-30", "End": "2026-04-01", "Owner": "Tecnolife"},
            {"Task": "Supply chain, SBOM, SCA", "Start": "2026-04-01", "End": "2026-04-03", "Owner": "Tecnolife"},
            {"Task": "Code review & Technical Intelligence", "Start": "2026-04-03", "End": "2026-04-10", "Owner": "Tecnolife"},
            {"Task": "Runtime posture & validation", "Start": "2026-04-10", "End": "2026-04-14", "Owner": "Tecnolife"},
            {"Task": "AI Technical Intelligence Review & sign-off", "Start": "2026-04-15", "End": "2026-04-15", "Owner": "Tecnolife"},
        ]
    }


def _intrum_risk_register_seed() -> dict[str, object]:
    if INTRUM_RISK_REGISTER_PATH.exists():
        return parse_risk_register(INTRUM_RISK_REGISTER_PATH)
    return {
        "sheet_names": ["Risk Register", "Scoring Parameters", "Executive Vulnerabilities"],
        "entries": [
            {
                "Finding ID": "TLF-SEC-017",
                "Title": "Broken authorization on export endpoint",
                "Finding Type": "Vulnerability",
                "Affected Asset": "Billing API | ExportController | /api/admin/export",
                "Taxonomy": "CWE-639 | OWASP ASVS 5.0 | OWASP WSTG",
                "Description": "A standard user can export another tenant's data by manipulating tenantId.",
                "Evidence Reference / Evidence Summary": "Request tampering allowed cross-tenant data export during controlled validation.",
                "Validation Status": "Validated finding (Reproduced)",
                "Evidence Confidence": "High",
                "Likelihood": 4,
                "Technical Impact": 5,
                "Business Impact": 4,
                "Control Weakness": 4,
                "Compliance Exposure": 4,
                "Remediation Effort": 2,
                "Transaction Impact": 4,
                "Inherent Risk": 4.4,
                "Residual Risk": 4.28,
                "Transaction Materiality": 3.5,
                "Final Score": 4.28,
                "Grade": "E",
                "Classification (Red Flag / Negotiation Relevant / Integration Item / Observation)": "Negotiation Relevant",
                "Suggested Action": "Enforce server-side tenant authorization checks",
            }
        ],
        "executive_entries": [
            {
                "Finding ID": "TLF-SEC-017",
                "Title": "Broken authorization on export endpoint",
                "Affected Asset": "Billing API | ExportController | /api/admin/export",
                "Taxonomy / Standard Mapping": "CWE-639 | OWASP ASVS 5.0 | OWASP WSTG",
                "Validation Status": "Validated finding (Reproduced)",
                "Evidence Confidence": "High",
                "Residual Risk": 4.28,
                "Final Score": 4.28,
                "Grade": "E",
                "Classification": "Negotiation Relevant",
                "Executive Description": "Cross-tenant export remained reachable through tenantId tampering.",
                "Key Evidence": "Controlled request tampering reproduced the issue.",
                "Suggested Action": "Enforce server-side tenant authorization checks",
            }
        ],
        "total_entries": 1,
        "critical_entries": 1,
    }


def _intrum_planning_seed() -> dict[str, object]:
    if INTRUM_GANTT_PATH.exists():
        parsed = parse_planning_workbook(INTRUM_GANTT_PATH)
        parsed["source_file"] = str(INTRUM_GANTT_PATH)
        return parsed
    return _default_planning()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _current_user(authorization: str = Header(default=""), db: Session = Depends(get_db)) -> User:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    payload = _decode_token(authorization.split(" ", 1)[1])
    if payload.get("scope") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong token scope")
    user = db.get(User, int(payload["sub"]))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown user")
    return user


def _require_admin(user: User = Depends(_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin scope required")
    return user


def _engagement_from_agent(
    x_agent_key: str = Header(default=""),
    db: Session = Depends(get_db),
) -> Engagement:
    hashed = _hash_agent_key(x_agent_key)
    engagement = db.scalar(select(Engagement).where(Engagement.agent_key_hash == hashed))
    if not engagement:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown agent key")
    return engagement


def _write_bootstrap_file(admin_password: str, client_username: str, client_password: str, agent_key: str) -> None:
    bootstrap_path = settings.storage_root / "bootstrap-credentials.md"
    bootstrap_path.write_text(
        "\n".join(
            [
                "# Bootstrap Credentials",
                "",
                f"- Admin username: `digitalaudit-admin`",
                f"- Admin password: `{admin_password}`",
                "",
                f"- Client username: `{client_username}`",
                f"- Client temporary password: `{client_password}`",
                "",
                f"- Intrum agent key: `{agent_key}`",
                "",
                "The client account is forced to enable MFA at first login.",
            ]
        ),
        encoding="utf-8",
    )


def _seed(db: Session) -> None:
    if db.scalar(select(User).limit(1)):
        return
    admin_password = _admin_password()
    intrum_password = _memorable_password("Intrum", "Massimiliano", "Daniele", date(2026, 3, 26))
    intrum_agent_key = _agent_key_for("intrum")

    engagement = Engagement(
        slug="intrum",
        client_name="Intrum",
        project_name="Intrum",
        contact_first_name="Massimiliano",
        contact_last_name="Daniele",
        start_date=date(2026, 3, 26),
        end_date=date(2026, 4, 15),
        scope_template="Audit applicativo, supply chain, maintainability, technical debt e compliance application-side.",
        roe_template="Out of scope: infra hardening del target, penetration test full-scope, firewall/WAF e produzione del Vendor.",
        planning_json=_json_dump(_intrum_planning_seed()),
        risk_register_json=_json_dump(_intrum_risk_register_seed()),
        telemetry_json=_json_dump({"faq": _default_faq()}),
        heartbeat_status="offline",
        agent_key_hash=_hash_agent_key(intrum_agent_key),
    )
    db.add(engagement)
    db.flush()

    admin = User(
        username="digitalaudit-admin",
        password_hash=_hash_password(admin_password),
        display_name="Digital Audit Admin",
        role="admin",
        must_rotate_password=True,
    )
    intrum_user = User(
        engagement_id=engagement.id,
        username=_username_for("Intrum", "Massimiliano", "Daniele"),
        password_hash=_hash_password(intrum_password),
        display_name="Massimiliano Daniele",
        role="client",
        must_rotate_password=True,
    )
    db.add_all([admin, intrum_user])
    db.add(
        Notification(
            engagement_id=engagement.id,
            title="Workspace ready",
            body="The engagement workspace is active. Deliverables will appear here as soon as the signed artifacts are uploaded.",
            level="info",
        )
    )
    db.commit()
    _write_bootstrap_file(admin_password, intrum_user.username, intrum_password, intrum_agent_key)


app = FastAPI(title="Digital Audit Control Plane", version="0.1.0")
app.mount("/static", StaticFiles(directory=settings.frontend_root), name="static")


@app.on_event("startup")
def startup() -> None:
    settings.ensure_dirs()
    settings.require_auth_secret()
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        _seed(db)


@app.get("/")
def index() -> FileResponse:
    return FileResponse(settings.frontend_root / "index.html")


@app.get("/health")
def health() -> dict[str, object]:
    return {"status": "ok", "timestamp": datetime.now(UTC).isoformat()}


@app.post("/api/auth/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> dict[str, object]:
    user = db.scalar(select(User).where(User.username == payload.username))
    if not user or not _verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if user.mfa_enabled:
        return {"status": "mfa_required", "token": _mint_mfa_token(user)}
    return {"status": "mfa_setup_required", "token": _mint_mfa_token(user)}


@app.post("/api/auth/mfa/setup")
def mfa_setup(payload: MfaSetupRequest, db: Session = Depends(get_db)) -> dict[str, object]:
    token = _decode_token(payload.token)
    if token.get("scope") != "mfa":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong token scope")
    user = db.get(User, int(token["sub"]))
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if not user.mfa_secret:
        user.mfa_secret = pyotp.random_base32()
        db.commit()
    totp = pyotp.TOTP(user.mfa_secret)
    return {
        "secret": user.mfa_secret,
        "otpauth_uri": totp.provisioning_uri(name=user.username, issuer_name="Digital Audit"),
    }


@app.post("/api/auth/mfa/verify")
def mfa_verify(payload: MfaVerifyRequest, db: Session = Depends(get_db)) -> dict[str, object]:
    token = _decode_token(payload.token)
    if token.get("scope") != "mfa":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong token scope")
    user = db.get(User, int(token["sub"]))
    if not user or not user.mfa_secret:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="MFA context missing")
    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(payload.code, valid_window=1):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")
    user.mfa_enabled = True
    db.commit()
    return {
        "access_token": _mint_access_token(user),
        "must_rotate_password": user.must_rotate_password,
        "role": user.role,
    }


@app.get("/api/me")
def me(user: User = Depends(_current_user)) -> dict[str, object]:
    return {
        "username": user.username,
        "display_name": user.display_name,
        "role": user.role,
        "must_rotate_password": user.must_rotate_password,
        "engagement_slug": user.engagement.slug if user.engagement else None,
    }


def _dashboard_payload(user: User, db: Session) -> dict[str, object]:
    if user.role == "admin":
        engagements = db.scalars(select(Engagement).order_by(Engagement.created_at.desc())).all()
        return {
            "role": "admin",
            "engagements": [
                {
                    "slug": item.slug,
                    "client_name": item.client_name,
                    "project_name": item.project_name,
                    "start_date": item.start_date.isoformat(),
                    "end_date": item.end_date.isoformat(),
                    "live": bool(
                        _as_utc(item.last_heartbeat_at)
                        and (datetime.now(UTC) - _as_utc(item.last_heartbeat_at)).total_seconds() <= settings.default_heartbeat_timeout
                    ),
                }
                for item in engagements
            ],
            "bootstrap_path": str(settings.storage_root / "bootstrap-credentials.md"),
        }

    engagement = user.engagement
    if not engagement:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No engagement assigned")
    deliverables = db.scalars(
        select(Deliverable).where(Deliverable.engagement_id == engagement.id).order_by(Deliverable.created_at.desc())
    ).all()
    notifications = db.scalars(
        select(Notification).where(Notification.engagement_id == engagement.id).order_by(Notification.created_at.desc())
    ).all()
    events = db.scalars(select(Event).where(Event.engagement_id == engagement.id).order_by(Event.created_at.desc())).all()
    live = bool(
        _as_utc(engagement.last_heartbeat_at)
        and (datetime.now(UTC) - _as_utc(engagement.last_heartbeat_at)).total_seconds() <= settings.default_heartbeat_timeout
    )
    telemetry = _json_load(engagement.telemetry_json, {})
    risk_register = _json_load(engagement.risk_register_json, {})
    planning = _json_load(engagement.planning_json, _default_planning())
    placeholder = (
        f"Gli artifact firmati e l'AI Technical Intelligence Review saranno pubblicati qui entro il {engagement.end_date.strftime('%d %b %Y')}."
    )
    return {
        "role": "client",
        "engagement": {
            "slug": engagement.slug,
            "client_name": engagement.client_name,
            "project_name": engagement.project_name,
            "contact": f"{engagement.contact_first_name} {engagement.contact_last_name}",
            "start_date": engagement.start_date.isoformat(),
            "end_date": engagement.end_date.isoformat(),
            "scope_template": engagement.scope_template,
            "roe_template": engagement.roe_template,
            "live": live,
            "heartbeat_status": engagement.heartbeat_status,
            "last_heartbeat_at": _as_utc(engagement.last_heartbeat_at).isoformat() if engagement.last_heartbeat_at else None,
        },
        "planning": planning,
        "risk_register": risk_register,
        "deliverables": [
            {
                "id": item.id,
                "kind": item.kind,
                "filename": item.filename,
                "created_at": item.created_at.isoformat(),
                "download_url": f"/api/deliverables/{item.id}/download",
                "sha512": item.sha512,
            }
            for item in deliverables
        ],
        "deliverables_placeholder": placeholder if not deliverables else None,
        "notifications": [
            {"title": item.title, "body": item.body, "level": item.level, "created_at": item.created_at.isoformat()}
            for item in notifications[:8]
        ],
        "events": [
            {"kind": item.kind, "level": item.level, "message": item.message, "created_at": item.created_at.isoformat()}
            for item in events[:12]
        ],
        "faq": telemetry.get("faq", _default_faq()),
    }


@app.get("/api/dashboard")
def dashboard(user: User = Depends(_current_user), db: Session = Depends(get_db)) -> dict[str, object]:
    return _dashboard_payload(user, db)


@app.get("/api/admin/bootstrap")
def admin_bootstrap(_: User = Depends(_require_admin)) -> FileResponse:
    return FileResponse(settings.storage_root / "bootstrap-credentials.md")


@app.post("/api/admin/engagements")
def create_engagement(
    payload: EngagementCreateRequest,
    _: User = Depends(_require_admin),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    slug = slugify(payload.project_name)
    if db.scalar(select(Engagement).where(Engagement.slug == slug)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Engagement already exists")
    username = _username_for(payload.client_name, payload.contact_first_name, payload.contact_last_name)
    password = _memorable_password(payload.client_name, payload.contact_first_name, payload.contact_last_name, payload.start_date)
    agent_key = _agent_key_for(slug)
    engagement = Engagement(
        slug=slug,
        client_name=payload.client_name,
        project_name=payload.project_name,
        contact_first_name=payload.contact_first_name,
        contact_last_name=payload.contact_last_name,
        start_date=payload.start_date,
        end_date=payload.end_date,
        scope_template=payload.scope_template,
        roe_template=payload.roe_template,
        planning_json=_json_dump(_default_planning()),
        risk_register_json=_json_dump({"entries": [], "executive_entries": [], "total_entries": 0, "critical_entries": 0}),
        telemetry_json=_json_dump({"faq": _default_faq()}),
        heartbeat_status="offline",
        agent_key_hash=_hash_agent_key(agent_key),
    )
    db.add(engagement)
    db.flush()
    user = User(
        engagement_id=engagement.id,
        username=username,
        password_hash=_hash_password(password),
        display_name=f"{payload.contact_first_name} {payload.contact_last_name}",
        role="client",
        must_rotate_password=True,
    )
    db.add(user)
    db.add(
        Notification(
            engagement_id=engagement.id,
            title="Engagement created",
            body="The client workspace is ready and waiting for the first remote heartbeat.",
            level="info",
        )
    )
    db.commit()
    return {
        "engagement_slug": slug,
        "username": username,
        "temporary_password": password,
        "agent_key": agent_key,
    }


@app.post("/api/admin/engagements/{slug}/planning")
def upload_planning(
    slug: str,
    file: UploadFile = File(...),
    _: User = Depends(_require_admin),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    engagement = db.scalar(select(Engagement).where(Engagement.slug == slug))
    if not engagement:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Engagement not found")
    target_dir = settings.storage_root / "uploads" / slug
    target_dir.mkdir(parents=True, exist_ok=True)
    relative_name = _safe_upload_name(file.filename or "")
    target_path = target_dir / relative_name
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_bytes(file.file.read())
    planning = parse_planning_workbook(target_path)
    engagement.planning_json = _json_dump(planning)
    db.add(
        Notification(
            engagement_id=engagement.id,
            title="Planning updated",
            body=f"Planning workbook {relative_name} parsed and published to the client view.",
            level="info",
        )
    )
    db.commit()
    return planning


@app.post("/api/heartbeat")
def heartbeat(
    payload: dict[str, object],
    engagement: Engagement = Depends(_engagement_from_agent),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    engagement.last_heartbeat_at = datetime.now(UTC)
    engagement.heartbeat_status = str(payload.get("state", "running"))
    telemetry = _json_load(engagement.telemetry_json, {})
    telemetry["last_heartbeat"] = payload
    engagement.telemetry_json = _json_dump(telemetry)
    db.commit()
    return {"status": "accepted"}


@app.post("/api/events")
def create_event(
    payload: dict[str, object],
    engagement: Engagement = Depends(_engagement_from_agent),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    event = Event(
        engagement_id=engagement.id,
        kind=str(payload.get("kind", "audit")),
        level=str(payload.get("level", "info")),
        message=str(payload.get("message", "")),
        payload_json=_json_dump(payload),
    )
    db.add(event)
    if event.level in {"warning", "error"}:
        db.add(
            Notification(
                engagement_id=engagement.id,
                title=event.kind.title(),
                body=event.message,
                level=event.level,
            )
        )
    db.commit()
    return {"status": "accepted"}


@app.post("/api/deliverables/upload")
def upload_deliverable(
    kind: str = Form(...),
    file: UploadFile = File(...),
    engagement: Engagement = Depends(_engagement_from_agent),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    target_dir = settings.storage_root / "deliverables" / engagement.slug
    target_dir.mkdir(parents=True, exist_ok=True)
    relative_name = _safe_upload_name(file.filename or "")
    target_path = target_dir / relative_name
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_bytes(file.file.read())
    sha512 = hashlib.sha512(target_path.read_bytes()).hexdigest()
    deliverable = Deliverable(
        engagement_id=engagement.id,
        kind=kind,
        filename=relative_name,
        path=str(target_path),
        sha512=sha512,
    )
    db.add(deliverable)
    if file.filename.lower().endswith(".xlsx") and "risk" in kind.lower():
        engagement.risk_register_json = _json_dump(parse_risk_register(target_path))
    if file.filename.lower().endswith(".xlsx") and "planning" in kind.lower():
        engagement.planning_json = _json_dump(parse_planning_workbook(target_path))
    db.add(
        Notification(
            engagement_id=engagement.id,
            title="Deliverable received",
            body=f"{relative_name} uploaded and registered as {kind}.",
            level="info",
        )
    )
    db.commit()
    return {"status": "stored", "sha512": sha512}


@app.get("/api/deliverables/{deliverable_id}/download")
def download_deliverable(
    deliverable_id: int,
    user: User = Depends(_current_user),
    db: Session = Depends(get_db),
) -> FileResponse:
    deliverable = db.get(Deliverable, deliverable_id)
    if not deliverable:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deliverable not found")
    if user.role != "admin" and user.engagement_id != deliverable.engagement_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Out of scope")
    return FileResponse(deliverable.path, filename=Path(deliverable.filename).name)


def serve() -> None:
    uvicorn.run(app, host=settings.api_host, port=settings.api_port)
