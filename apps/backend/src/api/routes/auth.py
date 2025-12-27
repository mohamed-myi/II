import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse
import httpx
from sqlmodel.ext.asyncio.session import AsyncSession

from src.api.dependencies import get_db, get_http_client
from src.core.config import get_settings
from src.core.cookies import create_session_cookie
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
from src.middleware.auth import require_fingerprint
from src.middleware.context import RequestContext, get_request_context
from src.services.session_service import (
    upsert_user,
    create_session,
    link_provider,
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


@router.get("/login/{provider}")
async def login(
    provider: str,
    request: Request,
    remember_me: bool = Query(default=False),
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
    db: AsyncSession = Depends(get_db),
    client: httpx.AsyncClient = Depends(get_http_client),
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
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
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
        return RedirectResponse(
            url=_build_error_redirect("code_expired"),
            status_code=302,
        )
    except EmailNotVerifiedError:
        return RedirectResponse(
            url=_build_error_redirect("email_not_verified", provider),
            status_code=302,
        )
    except NoEmailError:
        return RedirectResponse(
            url=_build_error_redirect("no_email", provider),
            status_code=302,
        )
    except ExistingAccountError as e:
        return RedirectResponse(
            url=_build_error_redirect("existing_account", e.original_provider),
            status_code=302,
        )
    except OAuthStateError:
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
) -> RedirectResponse:
    """Initiates OAuth flow to link additional provider to authenticated user"""
    from src.middleware.auth import get_current_session
    from src.middleware.context import get_request_context
    
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
) -> RedirectResponse:
    """Handles OAuth callback for account linking; requires existing session"""
    from src.middleware.auth import get_current_session, get_current_user
    from src.middleware.context import get_request_context
    
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

