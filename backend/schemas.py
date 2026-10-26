
from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ActivityEventRequest(BaseModel):
    event_type: str = Field(
        pattern="^(dashboard_open|alerts_view|login_history_view)$"
    )
    details: str = Field(default="", max_length=500)


class ExternalLoginEventRequest(BaseModel):
    website: str = Field(min_length=1, max_length=253)
    details: str = Field(default="Possible external website activity; login not confirmed", max_length=500)
    signal: str = Field(default="possible_post_login_navigation", pattern="^possible_post_login_navigation$")
