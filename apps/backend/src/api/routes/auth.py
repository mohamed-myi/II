import secrets
from urllib.parse import urlencode
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, HTTPException, Response
from fastapi.responses import RedirectResponse, JSONResponse
import httpx
from sqlmodel.ext.asyncio.session import AsyncSession

from src.api.dependencies import get_db, get_http_client
from src.core.audit import log_audit_event, AuditEvent
from src.core.config import get_settings
from src.core.cookies import (
    create_session_cookie,
    clear_session_cookie,
    create_login_flow_cookie,
)
from src.core.oauth import (
    OAuthProvider,
    get_authorization_url,
    exchange_code_for_token,
    fetch_user_profile,
    InvalidCodeError,
    EmailNotVerifiedError,
    NoEmailError,
    OAuthStateError,
)
from src.middleware.auth import require_fingerprint, get_current_session, get_current_user
from src.middleware.context import RequestContext, get_request_context
from src.middleware.rate_limit import check_auth_rate_limit
from src.services.session_service import (
    upsert_user,
    create_session,
    link_provider,
    list_sessions,
    invalidate_session,
    invalidate_all_sessions,
    get_session_by_id,
    ExistingAccountError,
    ProviderConflictError,
)


router = APIRouter()


STATE_COOKIE_NAME = "oauth_state"
STATE_COOKIE_MAX_AGE = 300


def _get_state_cookie_params(settings) -> dict:
    is_production = settings.environment == "production"
    return {
        "httponly": True,
        "secure": is_production,
        "samesite": "lax",
        "max_age": STATE_COOKIE_MAX_AGE,
        "path": "/",
    }


def _build_error_redirect(error_code: str, provider: str | None = None) -> str:
    settings = get_settings()
    params = {"error": error_code}
    if provider:
        params["provider"] = provider
    return f"{settings.frontend_base_url}/login?{urlencode(params)}"


@router.get("/init", status_code=204)
async def init_login_flow() -> Response:
    """Sets X-Login-Flow-ID cookie for rate limiting compound key"""
    flow_id = secrets.token_urlsafe(16)
    response = Response(status_code=204)
    create_login_flow_cookie(response, flow_id)
    return response


@router.get("/login/{provider}")
async def login(
    provider: str,
    request: Request,
    remember_me: bool = Query(default=False),
    _: None = Depends(check_auth_rate_limit),
) -> RedirectResponse:
    try:
        oauth_provider = OAuthProvider(provider)
    except ValueError:
        return RedirectResponse(
            url=_build_error_redirect("invalid_provider"),
            status_code=302,
        )
    
    settings = get_settings()
    state = secrets.token_urlsafe(32)
    redirect_uri = str(request.url_for("callback", provider=provider))
    auth_url = get_authorization_url(oauth_provider, redirect_uri, state)
    response = RedirectResponse(url=auth_url, status_code=302)
    
    # Encode remember_me in state cookie for callback to extract
    state_value = f"{state}:{1 if remember_me else 0}"
    response.set_cookie(
        key=STATE_COOKIE_NAME,
        value=state_value,
        **_get_state_cookie_params(settings),
    )
    
    return response


@router.get("/callback/{provider}")
async def callback(
    provider: str,
    request: Request,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
    fingerprint_hash: str = Depends(require_fingerprint),
    ctx: RequestContext = Depends(get_request_context),
    db: AsyncSession = Depends(get_db),
    client: httpx.AsyncClient = Depends(get_http_client),
    _: None = Depends(check_auth_rate_limit),
) -> RedirectResponse:
    settings = get_settings()
    
    if error:
        return RedirectResponse(
            url=_build_error_redirect("consent_denied"),
            status_code=302,
        )
    
    try:
        oauth_provider = OAuthProvider(provider)
    except ValueError:
        return RedirectResponse(
            url=_build_error_redirect("invalid_provider"),
            status_code=302,
        )
    
    stored_state = request.cookies.get(STATE_COOKIE_NAME)
    if not stored_state or not state:
        return RedirectResponse(
            url=_build_error_redirect("csrf_failed"),
            status_code=302,
        )
    
    # Validate format to prevent 500 on malformed cookies
    parts = stored_state.rsplit(":", 1)
    if len(parts) != 2:
        return RedirectResponse(
            url=_build_error_redirect("csrf_failed"),
            status_code=302,
        )
    
    stored_state_value, remember_me_flag = parts
    remember_me = remember_me_flag == "1"
    
    if state != stored_state_value:
        return RedirectResponse(
            url=_build_error_redirect("csrf_failed"),
            status_code=302,
        )
    
    if not code:
        return RedirectResponse(
            url=_build_error_redirect("missing_code"),
            status_code=302,
        )
    
    # Redirect URI must match login redirect
    redirect_uri = str(request.url_for("callback", provider=provider))
    
    try:
        token = await exchange_code_for_token(
            oauth_provider, code, redirect_uri, client
        )
        profile = await fetch_user_profile(oauth_provider, token, client)
        user = await upsert_user(db, profile, oauth_provider)
        
        session, expires_at = await create_session(
            db=db,
            user_id=user.id,
            fingerprint_hash=fingerprint_hash,
            remember_me=remember_me,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            os_family=ctx.os_family,
            ua_family=ctx.ua_family,
            asn=ctx.asn,
            country_code=ctx.country_code,
        )
        
        log_audit_event(
            AuditEvent.LOGIN_SUCCESS,
            user_id=user.id,
            session_id=session.id,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            provider=provider,
        )
        
        response = RedirectResponse(
            url=f"{settings.frontend_base_url}/dashboard",
            status_code=302,
        )
        response.delete_cookie(
            key=STATE_COOKIE_NAME,
            path="/",
        )
        create_session_cookie(response, str(session.id), expires_at)
        
        return response
        
    except InvalidCodeError:
        log_audit_event(
            AuditEvent.LOGIN_FAILED,
            ip_address=request.client.host if request.client else None,
            provider=provider,
            metadata={"reason": "code_expired"},
        )
        return RedirectResponse(
            url=_build_error_redirect("code_expired"),
            status_code=302,
        )
    except EmailNotVerifiedError:
        log_audit_event(
            AuditEvent.LOGIN_FAILED,
            ip_address=request.client.host if request.client else None,
            provider=provider,
            metadata={"reason": "email_not_verified"},
        )
        return RedirectResponse(
            url=_build_error_redirect("email_not_verified", provider),
            status_code=302,
        )
    except NoEmailError:
        log_audit_event(
            AuditEvent.LOGIN_FAILED,
            ip_address=request.client.host if request.client else None,
            provider=provider,
            metadata={"reason": "no_email"},
        )
        return RedirectResponse(
            url=_build_error_redirect("no_email", provider),
            status_code=302,
        )
    except ExistingAccountError as e:
        log_audit_event(
            AuditEvent.LOGIN_FAILED,
            ip_address=request.client.host if request.client else None,
            provider=provider,
            metadata={"reason": "existing_account", "original_provider": e.original_provider},
        )
        return RedirectResponse(
            url=_build_error_redirect("existing_account", e.original_provider),
            status_code=302,
        )
    except OAuthStateError:
        log_audit_event(
            AuditEvent.LOGIN_FAILED,
            ip_address=request.client.host if request.client else None,
            provider=provider,
            metadata={"reason": "csrf_failed"},
        )
        return RedirectResponse(
            url=_build_error_redirect("csrf_failed"),
            status_code=302,
        )


LINK_STATE_COOKIE_NAME = "oauth_link_state"


def _build_settings_redirect(error_code: str | None = None) -> str:
    settings = get_settings()
    base = f"{settings.frontend_base_url}/settings/accounts"
    if error_code:
        return f"{base}?{urlencode({'error': error_code})}"
    return base


@router.get("/link/{provider}")
async def link(
    provider: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(check_auth_rate_limit),
) -> RedirectResponse:
    """Initiates OAuth flow to link additional provider to authenticated user"""
    try:
        oauth_provider = OAuthProvider(provider)
    except ValueError:
        return RedirectResponse(
            url=_build_settings_redirect("invalid_provider"),
            status_code=302,
        )
    
    ctx = await get_request_context(request)
    
    try:
        session = await get_current_session(request, ctx, db)
    except Exception:
        return RedirectResponse(
            url=_build_error_redirect("not_authenticated"),
            status_code=302,
        )
    
    settings = get_settings()
    state = secrets.token_urlsafe(32)
    redirect_uri = str(request.url_for("link_callback", provider=provider))
    auth_url = get_authorization_url(oauth_provider, redirect_uri, state)
    response = RedirectResponse(url=auth_url, status_code=302)
    
    response.set_cookie(
        key=LINK_STATE_COOKIE_NAME,
        value=state,
        **_get_state_cookie_params(settings),
    )
    
    return response


@router.get("/link/callback/{provider}")
async def link_callback(
    provider: str,
    request: Request,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    client: httpx.AsyncClient = Depends(get_http_client),
    _: None = Depends(check_auth_rate_limit),
) -> RedirectResponse:
    """Handles OAuth callback for account linking; requires existing session"""
    ctx = await get_request_context(request)
    
    try:
        session = await get_current_session(request, ctx, db)
        user = await get_current_user(session, db)
    except Exception:
        return RedirectResponse(
            url=_build_error_redirect("not_authenticated"),
            status_code=302,
        )
    
    if error:
        return RedirectResponse(
            url=_build_settings_redirect("consent_denied"),
            status_code=302,
        )
    
    try:
        oauth_provider = OAuthProvider(provider)
    except ValueError:
        return RedirectResponse(
            url=_build_settings_redirect("invalid_provider"),
            status_code=302,
        )
    
    stored_state = request.cookies.get(LINK_STATE_COOKIE_NAME)
    if not stored_state or not state or state != stored_state:
        return RedirectResponse(
            url=_build_settings_redirect("csrf_failed"),
            status_code=302,
        )
    
    if not code:
        return RedirectResponse(
            url=_build_settings_redirect("missing_code"),
            status_code=302,
        )
    
    redirect_uri = str(request.url_for("link_callback", provider=provider))
    
    try:
        token = await exchange_code_for_token(
            oauth_provider, code, redirect_uri, client
        )
        profile = await fetch_user_profile(oauth_provider, token, client)
        await link_provider(db, user, profile, oauth_provider)
        
        log_audit_event(
            AuditEvent.ACCOUNT_LINKED,
            user_id=user.id,
            session_id=session.id,
            ip_address=request.client.host if request.client else None,
            provider=provider,
        )
        
        response = RedirectResponse(
            url=_build_settings_redirect(),
            status_code=302,
        )
        response.delete_cookie(key=LINK_STATE_COOKIE_NAME, path="/")
        
        return response
        
    except InvalidCodeError:
        return RedirectResponse(
            url=_build_settings_redirect("code_expired"),
            status_code=302,
        )
    except EmailNotVerifiedError:
        return RedirectResponse(
            url=_build_settings_redirect("email_not_verified"),
            status_code=302,
        )
    except NoEmailError:
        return RedirectResponse(
            url=_build_settings_redirect("no_email"),
            status_code=302,
        )
    except ProviderConflictError:
        return RedirectResponse(
            url=_build_settings_redirect("provider_conflict"),
            status_code=302,
        )


@router.get("/sessions")
async def get_sessions(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Returns all active sessions for authenticated user"""
    ctx = await get_request_context(request)
    
    try:
        session = await get_current_session(request, ctx, db)
        user = await get_current_user(session, db)
    except Exception:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    sessions = await list_sessions(db, user.id, session.id)
    
    return {
        "sessions": [
            {
                "id": s.id,
                "fingerprint_partial": s.fingerprint_partial,
                "created_at": s.created_at.isoformat(),
                "last_active_at": s.last_active_at.isoformat(),
                "user_agent": s.user_agent,
                "ip_address": s.ip_address,
                "is_current": s.is_current,
            }
            for s in sessions
        ],
        "count": len(sessions),
    }


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Revokes a specific session; must belong to authenticated user"""
    ctx = await get_request_context(request)
    
    try:
        current_session = await get_current_session(request, ctx, db)
        user = await get_current_user(current_session, db)
    except Exception:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        target_session_id = UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    
    target_session = await get_session_by_id(db, target_session_id)
    
    if target_session is None or target_session.user_id != user.id:
        raise HTTPException(status_code=404, detail="Session not found")
    
    is_current = target_session_id == current_session.id
    
    await invalidate_session(db, target_session_id)
    
    log_audit_event(
        AuditEvent.SESSION_REVOKED,
        user_id=user.id,
        session_id=target_session_id,
        ip_address=request.client.host if request.client else None,
        metadata={"was_current": is_current},
    )
    
    response_data = {"revoked": True, "was_current": is_current}
    
    if is_current:
        response = JSONResponse(content=response_data)
        clear_session_cookie(response)
        return response
    
    return response_data


@router.delete("/sessions")
async def revoke_all_sessions(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Revokes all sessions except current"""
    ctx = await get_request_context(request)
    
    try:
        current_session = await get_current_session(request, ctx, db)
        user = await get_current_user(current_session, db)
    except Exception:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    revoked_count = await invalidate_all_sessions(
        db, user.id, except_session_id=current_session.id
    )
    
    return {"revoked_count": revoked_count}


@router.post("/logout")
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Invalidates current session; always returns success even if session expired"""
    session_id_str = request.cookies.get("session_id")
    session_uuid = None
    
    if session_id_str:
        try:
            session_uuid = UUID(session_id_str)
            await invalidate_session(db, session_uuid)
        except ValueError:
            pass
    
    log_audit_event(
        AuditEvent.LOGOUT,
        session_id=session_uuid,
        ip_address=request.client.host if request.client else None,
    )
    
    response = JSONResponse(content={"logged_out": True})
    clear_session_cookie(response)
    return response


@router.post("/logout/all")
async def logout_all(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Invalidates all sessions including current"""
    ctx = await get_request_context(request)
    
    try:
        current_session = await get_current_session(request, ctx, db)
        user = await get_current_user(current_session, db)
    except Exception:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    revoked_count = await invalidate_all_sessions(db, user.id, except_session_id=None)
    
    log_audit_event(
        AuditEvent.LOGOUT_ALL,
        user_id=user.id,
        session_id=current_session.id,
        ip_address=request.client.host if request.client else None,
        metadata={"revoked_count": revoked_count},
    )
    
    response = JSONResponse(content={"revoked_count": revoked_count, "logged_out": True})
    clear_session_cookie(response)
    return response
