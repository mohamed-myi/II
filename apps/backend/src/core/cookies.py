from datetime import datetime
from fastapi import Response

from .config import get_settings


SESSION_COOKIE_NAME = "session_id"


def create_session_cookie(
    response: Response,
    session_id: str,
    expires_at: datetime | None = None,
) -> None:
    """
    Sets session cookie with security flags.
    If expires_at is None, creates a session cookie that expires when browser closes.
    If expires_at is provided, creates a persistent cookie with Expires attribute.
    """
    settings = get_settings()
    is_production = settings.environment == "production"
    
    cookie_params = {
        "key": SESSION_COOKIE_NAME,
        "value": session_id,
        "httponly": True,
        "samesite": "lax",
        "secure": is_production,
        "path": "/",
    }
    
    if expires_at is not None:
        cookie_params["expires"] = int(expires_at.timestamp())
    
    response.set_cookie(**cookie_params)


def clear_session_cookie(response: Response) -> None:
    """
    Clears session cookie by setting it with past expiry.
    """
    settings = get_settings()
    is_production = settings.environment == "production"
    
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        samesite="lax",
        secure=is_production,
        path="/",
    )
