from datetime import datetime, timezone
from uuid import UUID

from fastapi import Request, HTTPException, Depends
from starlette.responses import Response
from sqlmodel.ext.asyncio.session import AsyncSession

from src.core.cookies import SESSION_COOKIE_NAME, create_session_cookie
from src.services.session_service import get_session_by_id, refresh_session
from src.middleware.context import RequestContext, get_request_context


async def get_current_session(
    request: Request,
    ctx: RequestContext = Depends(get_request_context),
    db: AsyncSession = Depends(lambda: None),  # Placeholder - will be replaced with actual dependency
) -> "Session":
    """
    Validates session cookie.
    
    Fingerprint Logic:
    - Missing fingerprint at login: Handled by require_fingerprint (returns 400)
    - Changed fingerprint mid-session: ALLOW but flag for notification
    
    Raises HTTPException(401) if session invalid/expired.
    """
    from src.models.identity import Session
    
    session_id_str = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id_str:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        session_uuid = UUID(session_id_str)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid session format")
    
    session = await get_session_by_id(db, session_uuid)
    
    if session is None:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    
    # Compare fingerprints, should reject (to be changed)
    if ctx.fingerprint_hash and ctx.fingerprint_hash != session.fingerprint:
        # Flag for downstream notification - email notis not setup yet.
        request.state.fingerprint_changed = True
        request.state.old_fingerprint = session.fingerprint
        request.state.new_fingerprint = ctx.fingerprint_hash
    else:
        request.state.fingerprint_changed = False
    
    return session


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(lambda: None),  # Placeholder
) -> "User":
    """
    Returns the authenticated user from session.
    
    Must be used after get_current_session in the dependency chain.
    """
    from src.models.identity import User

    session = await get_current_session(
        request,
        await get_request_context(request),
        db
    )
    
    user = await db.get(User, session.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def require_auth(
    request: Request,
    ctx: RequestContext = Depends(get_request_context),
    db: AsyncSession = Depends(lambda: None),  # Placeholder
) -> tuple["User", "Session"]:
    """
    Validates session and refreshes if needed.
    Stores new expires_at in request.state for response middleware.
    
    Usage in routes:
        @router.get("/protected")
        async def protected_route(auth: tuple[User, Session] = Depends(require_auth)):
            user, session = auth
            ...
    """
    from src.models.identity import User
    
    session = await get_current_session(request, ctx, db)
    
    user = await db.get(User, session.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    new_expires = await refresh_session(db, session)
    if new_expires:
        request.state.session_expires_at = new_expires
        request.state.session_id = str(session.id)
    
    return user, session


def require_fingerprint(
    ctx: RequestContext = Depends(get_request_context),
) -> str:
    """
    Dependency for login routes that REQUIRE fingerprint.
    Raises 400 if missing.
    
    Usage:
        @router.post("/auth/callback")
        async def oauth_callback(fingerprint: str = Depends(require_fingerprint)):
            ...
    """
    if not ctx.fingerprint_hash:
        raise HTTPException(
            status_code=400,
            detail="Please enable JavaScript to sign in."
        )
    return ctx.fingerprint_hash


async def session_cookie_sync_middleware(request: Request, call_next) -> Response:
    """
    Injects updated session cookie if refresh_session updated expires_at.
    
    Must be registered after CORS middleware in main.py - Middleware executes in reverse order for responses.
    """
    response = await call_next(request)
    
    # Check if auth dependency flagged a refresh
    if hasattr(request.state, "session_expires_at") and hasattr(request.state, "session_id"):
        create_session_cookie(
            response,
            request.state.session_id,
            request.state.session_expires_at
        )
    
    return response
