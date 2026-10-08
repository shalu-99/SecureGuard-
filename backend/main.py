from fastapi import FastAPI, Depends, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from pathlib import Path

from backend.database import engine, Base, get_db
from backend import models
from backend.schemas import RegisterRequest, LoginRequest
from backend.auth import hash_password, verify_password
from backend.email_service import send_security_alert


app = FastAPI(title="SecureGuard API")

Base.metadata.create_all(bind=engine)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


app.mount(
    "/frontend",
    StaticFiles(directory=str(FRONTEND_DIR)),
    name="frontend"
)


# =========================
# FRONTEND PAGES
# =========================

@app.get("/")
def home():
    return FileResponse(FRONTEND_DIR / "dashboard.html")


@app.get("/register.html")

# REGISTER
# =========================
# =========================
def register_page():

    return FileResponse(FRONTEND_DIR / "register.html")
        password_hash=hash_password(user_data.password),
        status="active"
    )
    db.add(new_user)
    db.commit()
    registration_email_sent = send_security_alert(
        new_user.email,
Hello {new_user.name},

Your SecureGuard account has been successfully registered.

Your account is now protected by the SecureGuard
Real-Time Cybersecurity Monitoring System.

If you did not create this account, please review

Thank you,
SecureGuard Security Team
"""
    )

    return {
        "message": "User registered successfully",
        "user_id": new_user.id,
        "name": new_user.name,
        "email": new_user.email,
        "status": new_user.status,
        "registration_email_sent": registration_email_sent
    }


# =========================
# LOGIN
# =========================

@app.post("/api/login")
def login(
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):

    user = (
        db.query(models.User)
        .filter(models.User.email == login_data.email)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    if user.status == "deactivated":
        raise HTTPException(
            status_code=403,
            detail="Account is deactivated"
        )

    if not verify_password(
        login_data.password,
        user.password_hash
        "message": "Login successful",
        "email": user.email,
    }
# =========================
# SECURITY ALERTS
# =========================
@app.get("/api/alerts")
def get_alerts(
    db: Session = Depends(get_db)

    alerts = (
        db.query(models.Alert)
        .order_by(models.Alert.created_at.desc())
        .all()
    )

    return [
        {
            "id": alert.id,
        "email_sent": email_sent
    }            "user_id": alert.user_id,
            "event_type": alert.event_type,
            "severity": alert.severity,
            "message": alert.message,
            "status": alert.status,
            "created_at": alert.created_at
        }
        for alert in alerts
        "message": "Account deactivated successfully",
        "user_id": user.id,
        "status": user.status,
    ]

Your SecureGuard account has been deactivated.
SecureGuard Security Team
"""
    )

    return {

If you did not perform this action,
please review your account security immediately.

Hello {user.name},

        f"""

# =========================
        user.email,
        "SecureGuard Security Alert",
# ACCOUNT DEACTIVATION
# =========================

@app.post("/api/account/deactivate/{user_id}")
    email_sent = send_security_alert(
def deactivate_account(
    user_id: int,
    db: Session = Depends(get_db)
):


    user = (
        db.query(models.User)
        .filter(models.User.id == user_id)
        .first()
    )

    if not user:
    db.add(event)
    db.add(alert)
    db.commit()
        raise HTTPException(
            status_code=404,
            detail="User not found"

        )

    user.status = "deactivated"

    )
    event = models.SecurityEvent(
        user_id=user.id,
        event_type="account_deactivation",
        ip_address="local-test",
        status="new"
        details="User account was deactivated"
    )

    alert = models.Alert(
        user_id=user.id,
        event_type="account_deactivation",
        severity="high",
        message="User account has been deactivated",
):



        "status": user.status
        "user_id": user.id,
        "name": user.name,
    db.commit()

    return {
        success=True

    db.add(successful_attempt)
    )
    ):

        failed_attempt = models.LoginAttempt(
    successful_attempt = models.LoginAttempt(
        user_id=user.id,
        ip_address="local-test",
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
            user_id=user.id,
            ip_address="local-test",
            success=False
SecureGuard Security Team
"""
                )

        )

        db.add(failed_attempt)
        db.commit()
please review your account security.


        failed_count = (
            db.query(models.LoginAttempt)

Multiple failed login attempts were detected
on your SecureGuard account.

If this activity was not performed by you,
            .filter(
Hello {user.name},
                models.LoginAttempt.user_id == user.id,
                    f"""
                models.LoginAttempt.success == False
            )
            .count()
                    "SecureGuard Security Alert",
        )

        if failed_count >= 3:
                    user.email,

            existing_alert = (
                db.query(models.Alert)
                .filter(
                    models.Alert.user_id == user.id,
                    models.Alert.event_type == "multiple_failed_logins",
                    models.Alert.status == "new"
                )

                send_security_alert(
                .first()
            )

                db.commit()
            if not existing_alert:

                alert = models.Alert(
                    user_id=user.id,
                    event_type="multiple_failed_logins",
                    severity="high",
                    message="Multiple failed login attempts detected",
                    status="new"
                )

                db.add(alert)
your account security immediately.
        "Welcome to SecureGuard",
        f"""
    db.refresh(new_user)


            "message": str(e)
    new_user = models.User(
        name=user_data.name,
        email=user_data.email,
    if existing_user:
        )

        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        }

            "database": "disconnected",
    )

        db.query(models.User)
        .filter(models.User.email == user_data.email)
        .first()

    user_data: RegisterRequest,
    db: Session = Depends(get_db)
):

    existing_user = (
@app.post("/api/register")
def register(
            "status": "error",

@app.get("/login.html")
def login_page():
        return {
    return FileResponse(FRONTEND_DIR / "login.html")

    except Exception as e:

# =========================

# DATABASE HEALTH
            "status": "healthy"
        }
# =========================
    try:
            "database": "connected",
        with engine.connect() as connection:
        return {
            connection.execute(text("SELECT 1"))


@app.get("/api/health/db")

