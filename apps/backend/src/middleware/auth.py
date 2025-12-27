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
    db: AsyncSession = Depends(lambda: None),  # todo: replace with actual dependency at route level
) -> "Session":
    """Rejects if session invalid; expired; or fingerprint mismatch"""
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
    
    # Hard enforcement; reject on fingerprint mismatch to prevent session hijacking
    if ctx.fingerprint_hash and ctx.fingerprint_hash != session.fingerprint:
        raise HTTPException(
            status_code=401,
            detail="Session invalid for this device"
        )
    
    if session.fingerprint and not ctx.fingerprint_hash:
        raise HTTPException(
            status_code=401,
            detail="Device identification required"
        )
    
    return session


async def get_current_user(
    session: "Session" = Depends(get_current_session),
    db: AsyncSession = Depends(lambda: None),
) -> "User":
    from src.models.identity import User
    
    user = await db.get(User, session.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def require_auth(
    request: Request,
    session: "Session" = Depends(get_current_session),
    user: "User" = Depends(get_current_user),
    db: AsyncSession = Depends(lambda: None),
) -> tuple["User", "Session"]:
    """Stores new expires_at in request state for response middleware"""
    new_expires = await refresh_session(db, session)
    if new_expires:
        request.state.session_expires_at = new_expires
        request.state.session_id = str(session.id)
    
    return user, session


def require_fingerprint(
    ctx: RequestContext = Depends(get_request_context),
) -> str:
    """Returns 400 if X_Device_Fingerprint header missing"""
    if not ctx.fingerprint_hash:
        raise HTTPException(
            status_code=400,
            detail="Please enable JavaScript to sign in."
        )
    return ctx.fingerprint_hash


async def session_cookie_sync_middleware(request: Request, call_next) -> Response:
    """Injects updated session cookie if refresh_session updated expires_at"""
    response = await call_next(request)
    
    if response.status_code < 400:
        if hasattr(request.state, "session_expires_at") and hasattr(request.state, "session_id"):
            create_session_cookie(
                response,
                request.state.session_id,
                request.state.session_expires_at
            )
    
    return response
