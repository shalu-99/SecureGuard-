import os
import jwt
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from pathlib import Path

from backend.database import engine, Base, get_db
from backend import models
from backend.schemas import RegisterRequest, LoginRequest, ActivityEventRequest, ExternalLoginEventRequest
from backend.auth import hash_password, verify_password, needs_rehash
from backend.email_service import send_security_alert


app = FastAPI(title="SecureGuard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["chrome-extension://bffjjjpijhejdojfeaenijcjbfpinpgj"],
    allow_credentials=False,
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not JWT_SECRET_KEY or JWT_SECRET_KEY == "PASTE_YOUR_GENERATED_SECRET_HERE":
    raise RuntimeError("JWT_SECRET_KEY missing from .env")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30



# =========================================================
# DATABASE TABLE CREATION
# =========================================================

def create_access_token(user_id: int, email: str):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": email,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def get_current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db)
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = int(payload["sub"])
    except (jwt.InvalidTokenError, KeyError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user or user.status == "deactivated":
        raise HTTPException(status_code=401, detail="User unavailable")
    return user


Base.metadata.create_all(bind=engine)


# =========================================================
# FRONTEND DIRECTORY
# =========================================================

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


# =========================================================
# STATIC FILES
# =========================================================

app.mount(
    "/frontend",
    StaticFiles(directory=str(FRONTEND_DIR)),
    name="frontend"
)


# =========================================================
# PAGE ROUTES
# =========================================================

# 1st page
# SecureGuard logo + loading screen
@app.get("/")
def home():
    return FileResponse(
        FRONTEND_DIR / "landing.html"
    )


# 2nd page
# Login / Register selection page
@app.get("/auth.html")
def auth_page():
    return FileResponse(
        FRONTEND_DIR / "auth.html"
    )


# 3rd page
# Final Security Operations Dashboard
@app.get("/dashboard")
def dashboard():
    return FileResponse(
        FRONTEND_DIR / "dashboard.html"
    )


# Login page
@app.get("/login.html")
def login_page():
    return FileResponse(
        FRONTEND_DIR / "login.html"
    )


# Register page
@app.get("/register.html")
def register_page():
    return FileResponse(
        FRONTEND_DIR / "register.html"
    )


# =========================================================
# DATABASE HEALTH CHECK
# =========================================================

@app.get("/api/health/db")
def database_health():

    try:

        with engine.connect() as connection:

            connection.execute(
                text("SELECT 1")
            )

        return {
            "database": "connected",
            "status": "healthy"
        }

    except Exception as e:

        return {
            "database": "disconnected",
            "status": "error",
            "message": str(e)
        }


# =========================================================
# USER REGISTRATION
# =========================================================

@app.post("/api/register")
def register(
    user_data: RegisterRequest,
    db: Session = Depends(get_db)
):

    # Check whether email already exists
    existing_user = (

        db.query(models.User)

        .filter(
            models.User.email == user_data.email
        )

        .first()

    )


    if existing_user:

        raise HTTPException(

            status_code=400,

            detail="Email already registered"

        )


    # Create new user
    new_user = models.User(

        name=user_data.name,

        email=user_data.email,

        password_hash=hash_password(
            user_data.password
        ),

        status="active"

    )


    db.add(new_user)

    db.commit()

    db.refresh(new_user)


    # Send welcome email
    email_sent = send_security_alert(

        new_user.email,

        "Welcome to SecureGuard",

        f"""Hello {new_user.name},

Your SecureGuard account has been successfully registered.

Your account is now protected by the SecureGuard
Real-Time Cybersecurity Monitoring System.

Thank you,
SecureGuard Security Team
"""

    )


    return {

        "message":
            "User registered successfully",

        "user_id":
            new_user.id,

        "name":
            new_user.name,

        "email":
            new_user.email,

        "status":
            new_user.status,

        "registration_email_sent":
            email_sent

    }


# =========================================================
# USER LOGIN
# =========================================================

@app.post("/api/login")
def login(
    login_data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):

    # Find user
    user = (

        db.query(models.User)

        .filter(
            models.User.email == login_data.email
        )

        .first()

    )


    # User not found
    if not user:

        raise HTTPException(

            status_code=401,

            detail="Invalid email or password"

        )


    # Check if account is deactivated
    if user.status == "deactivated":

        raise HTTPException(

            status_code=403,

            detail="Account is deactivated"

        )


    # =====================================================
    # FAILED LOGIN
    # =====================================================

    if not verify_password(

        login_data.password,

        user.password_hash

    ):


        failed_attempt = models.LoginAttempt(

            user_id=user.id,

            ip_address=(request.client.host if request.client else "unknown"),

            success=False

        )


        db.add(failed_attempt)

        db.commit()


        # Count failed login attempts
        failed_count = (

            db.query(models.LoginAttempt)

            .filter(

                models.LoginAttempt.user_id == user.id,

                models.LoginAttempt.success == False

            )

            .count()

        )


        # =================================================
        # MULTIPLE FAILED LOGIN DETECTION
        # =================================================

        if failed_count >= 3:


            existing_alert = (

                db.query(models.Alert)

                .filter(

                    models.Alert.user_id == user.id,

                    models.Alert.event_type ==
                        "multiple_failed_logins",

                    models.Alert.status == "new"

                )

                .first()

            )


            if not existing_alert:


                alert = models.Alert(

                    user_id=user.id,

                    event_type=
                        "multiple_failed_logins",

                    severity="high",

                    message=
                        "Multiple failed login attempts detected",

                    status="new"

                )


                db.add(alert)

                db.commit()


                # Send security alert email
                send_security_alert(

                    user.email,

                    "SecureGuard Security Alert",

                    f"""Hello {user.name},

Multiple failed login attempts were detected
on your SecureGuard account.

If this activity was not performed by you,
please review your account security.

SecureGuard Security Team
"""

                )


        raise HTTPException(

            status_code=401,

            detail="Invalid email or password"

        )


    # =====================================================
    # SUCCESSFUL LOGIN
    # =====================================================

    # Upgrade legacy SHA-256 hashes after successful verification
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(login_data.password)
        db.commit()

    successful_attempt = models.LoginAttempt(

        user_id=user.id,

        ip_address=(request.client.host if request.client else "unknown"),

        success=True

    )


    db.add(successful_attempt)

    db.commit()


    access_token = create_access_token(user.id, user.email)

    return {
        "message": "Login successful",
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "name": user.name,
        "email": user.email,
        "status": user.status
    }


# =========================================================
# AUTHENTICATED LOGIN HISTORY
# =========================================================

@app.get("/api/login-history")
def get_login_history(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    attempts = (
        db.query(models.LoginAttempt)
        .filter(models.LoginAttempt.user_id == current_user.id)
        .order_by(models.LoginAttempt.timestamp.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "timestamp": attempt.timestamp,
            "success": attempt.success,
            "status": "Success" if attempt.success else "Failed",
            "ip_address": attempt.ip_address,
        }
        for attempt in attempts
    ]


# =========================================================
# SECURITY ALERTS
# =========================================================

@app.get("/api/alerts")
def get_alerts(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    alerts = (
        db.query(models.Alert)
        .filter(models.Alert.user_id == current_user.id)
        .order_by(models.Alert.created_at.desc())
        .all()
    )

    return [
        {
            "id": alert.id,
            "user_id": alert.user_id,
            "event_type": alert.event_type,
            "severity": alert.severity,
            "message": alert.message,
            "status": alert.status,
            "created_at": alert.created_at
        }
        for alert in alerts
    ]


# =========================================================
# ACCOUNT DEACTIVATION
# =========================================================

@app.post("/api/account/deactivate/{user_id}")
def deactivate_account(
    user_id: int,
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Users may deactivate only their own account.
    if current_user.id != user_id:
        raise HTTPException(
            status_code=403,
            detail="You can only deactivate your own account"
        )

    user = (
        db.query(models.User)
        .filter(models.User.id == user_id)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    if user.status == "deactivated":
        raise HTTPException(
            status_code=400,
            detail="Account is already deactivated"
        )

    user.status = "deactivated"


# =====================================================
    # SECURITY EVENT
    # =====================================================

    event = models.SecurityEvent(

        user_id=user.id,

        event_type=
            "account_deactivation",

        ip_address=(
            request.client.host if request.client else "unknown"
        ),

        details=
            "User account was deactivated"

    )


    # =====================================================
    # SECURITY ALERT
    # =====================================================

    alert = models.Alert(

        user_id=user.id,

        event_type=
            "account_deactivation",

        severity="high",

        message=
            "User account has been deactivated",

        status="new"

    )


    db.add(event)

    db.add(alert)

    db.commit()


    # =====================================================
    # SECURITY EMAIL
    # =====================================================

    email_sent = send_security_alert(

        user.email,

        "SecureGuard Security Alert",

        f"""Hello {user.name},

Your SecureGuard account has been deactivated.

If you did not perform this action,
please review your account security immediately.

SecureGuard Security Team
"""

    )


    return {

        "message":
            "Account deactivated successfully",

        "user_id":
            user.id,

        "status":
            user.status,

        "email_sent":
            email_sent

    }

# =========================================================
# AUTHENTICATED USER ACTIVITY TRACKING
# =========================================================

@app.post("/api/activity")
def record_user_activity(
    activity: ActivityEventRequest,
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    client_ip = request.client.host if request.client else None

    event = models.SecurityEvent(
        user_id=current_user.id,
        event_type=activity.event_type,
        ip_address=client_ip,
        details=activity.details or "User activity recorded"
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    return {
        "message": "Activity recorded",
        "event_id": event.id,
        "event_type": event.event_type,
        "timestamp": event.timestamp
    }


@app.get("/api/activity")
def get_user_activity(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    events = (
        db.query(models.SecurityEvent)
        .filter(models.SecurityEvent.user_id == current_user.id)
        .order_by(models.SecurityEvent.timestamp.desc())
        .limit(30)
        .all()
    )

    return [
        {
            "id": event.id,
            "event_type": event.event_type,
            "details": event.details,
            "ip_address": event.ip_address,
            "timestamp": event.timestamp
        }
        for event in events
    ]


@app.post("/api/external-login")
def record_external_login(
    activity: ExternalLoginEventRequest,
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    website = activity.website.strip().lower()

    if activity.signal != "possible_post_login_navigation":
        raise HTTPException(status_code=400, detail="Unsupported activity signal")

    if not website or "/" in website or "@" in website:
        raise HTTPException(
            status_code=400,
            detail="Invalid website hostname"
        )

    client_ip = request.client.host if request.client else None

    event = models.SecurityEvent(
        user_id=current_user.id,
        event_type="possible_external_login",
        ip_address=client_ip,
        details=f"Website: {website} | {activity.details}"
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    return {
        "message": "External login event recorded",
        "event_id": event.id,
        "website": website,
        "timestamp": event.timestamp
    }
