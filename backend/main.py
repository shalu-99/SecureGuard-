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


# Create database tables
Base.metadata.create_all(bind=engine)


# Frontend location
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


# Serve frontend files
app.mount(
    "/frontend",
    StaticFiles(directory=str(FRONTEND_DIR)),
    name="frontend"
)


# --------------------------------------------------
# HOME / DASHBOARD
# --------------------------------------------------

@app.get("/")
def home():
    return FileResponse(FRONTEND_DIR / "dashboard.html")


# --------------------------------------------------
# DATABASE HEALTH
# --------------------------------------------------

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


# --------------------------------------------------
# REGISTER
# --------------------------------------------------

@app.post("/api/register")
def register(
    user_data: RegisterRequest,
    db: Session = Depends(get_db)
):

    # Check existing email

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


    # --------------------------------------------------
    # REGISTRATION EMAIL
    # --------------------------------------------------

    registration_email_sent = send_security_alert(

        new_user.email,

        "Welcome to SecureGuard",

        f"""
Hello {new_user.name},

Your SecureGuard account has been successfully registered.

Your account is now protected by the SecureGuard
Real-Time Cybersecurity Monitoring System.

If you did not create this account, please review
your account security immediately.

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
            registration_email_sent
    }


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.post("/api/login")
def login(
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):

    user = (
        db.query(models.User)
        .filter(
            models.User.email ==
            login_data.email
        )
        .first()
    )


    if not user:

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )


    # Check account status

    if user.status == "deactivated":

        raise HTTPException(
            status_code=403,
            detail="Account is deactivated"
        )


    # Verify password

    if not verify_password(
        login_data.password,
        user.password_hash
    ):

        failed_attempt = models.LoginAttempt(

            user_id=user.id,

            ip_address="local-test",

            success=False
        )

        db.add(failed_attempt)

        db.commit()


        # Count failed attempts

        failed_count = (

            db.query(models.LoginAttempt)

            .filter(

                models.LoginAttempt.user_id ==
                user.id,

                models.LoginAttempt.success ==
                False

            )

            .count()

        )


        # Multiple failed login detection

        if failed_count >= 3:

            existing_alert = (

                db.query(models.Alert)

                .filter(

                    models.Alert.user_id ==
                    user.id,

                    models.Alert.event_type ==
                    "multiple_failed_logins",

                    models.Alert.status ==
                    "new"

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


                # Send security email

                send_security_alert(

                    user.email,

                    "SecureGuard Security Alert",

                    f"""
Hello {user.name},

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


    # Successful login

    successful_attempt = models.LoginAttempt(

        user_id=user.id,

        ip_address="local-test",

        success=True

    )


    db.add(successful_attempt)

    db.commit()


    return {

        "message":
            "Login successful",

        "user_id":
            user.id,

        "name":
            user.name,

        "email":
            user.email,

        "status":
            user.status

    }


# --------------------------------------------------
# GET SECURITY ALERTS
# --------------------------------------------------

@app.get("/api/alerts")
def get_alerts(
    db: Session = Depends(get_db)
):

    alerts = (

        db.query(models.Alert)

        .order_by(
            models.Alert.created_at.desc()
        )

        .all()

    )


    return [

        {

            "id":
                alert.id,

            "user_id":
                alert.user_id,

            "event_type":
                alert.event_type,

            "severity":
                alert.severity,

            "message":
                alert.message,

            "status":
                alert.status,

            "created_at":
                alert.created_at

        }

        for alert in alerts

    ]


# --------------------------------------------------
# ACCOUNT DEACTIVATION
# --------------------------------------------------

@app.post("/api/account/deactivate/{user_id}")
def deactivate_account(

    user_id: int,

    db: Session = Depends(get_db)

):

    # Find user

    user = (

        db.query(models.User)

        .filter(
            models.User.id == user_id
        )

        .first()

    )


    if not user:

        raise HTTPException(

            status_code=404,

            detail="User not found"

        )


    # Deactivate account

    user.status = "deactivated"


    # Create security event

    event = models.SecurityEvent(

        user_id=user.id,

        event_type=
            "account_deactivation",

        ip_address=
            "local-test",

        details=
            "User account was deactivated"

    )


    # Create alert

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


    # --------------------------------------------------
    # SEND SECURITY ALERT EMAIL
    # --------------------------------------------------

    email_sent = send_security_alert(

        user.email,

        "SecureGuard Security Alert",

        f"""
Hello {user.name},

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