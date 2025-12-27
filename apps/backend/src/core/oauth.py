from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlencode
import httpx

from .config import get_settings


class OAuthProvider(str, Enum):
    GITHUB = "github"
    GOOGLE = "google"


@dataclass
class UserProfile:
    email: str
    provider_id: str
    avatar_url: str | None
    is_verified: bool
    username: str | None = None


@dataclass
class OAuthToken:
    """Includes optional refresh_token for background workers"""
    access_token: str
    token_type: str
    scope: str | None = None
    refresh_token: str | None = None
    expires_in: int | None = None


class OAuthError(Exception):
    pass


class EmailNotVerifiedError(OAuthError):
    pass


class NoEmailError(OAuthError):
    pass


class OAuthStateError(OAuthError):
    pass


class InvalidCodeError(OAuthError):
    pass


GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"

GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

RETRYABLE_STATUS_CODES = {500, 502, 503, 504, 429}


STATE_MIN_LENGTH = 32
STATE_MAX_LENGTH = 128
STATE_ALLOWED_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")


def validate_state(state: str) -> None:
    """Validates state parameter to prevent injection attacks"""
    if not state:
        raise OAuthStateError("State parameter is required")
    
    if len(state) < STATE_MIN_LENGTH:
        raise OAuthStateError(f"State must be at least {STATE_MIN_LENGTH} characters")
    
    if len(state) > STATE_MAX_LENGTH:
        raise OAuthStateError(f"State must be at most {STATE_MAX_LENGTH} characters")
    
    if not all(c in STATE_ALLOWED_CHARS for c in state):
        raise OAuthStateError("State contains invalid characters")


def get_authorization_url(provider: OAuthProvider, redirect_uri: str, state: str) -> str:
    """State is validated and should be stored server side for CSRF verification"""
    validate_state(state)
    settings = get_settings()
    
    if provider == OAuthProvider.GITHUB:
        params = {
            "client_id": settings.github_client_id,
            "redirect_uri": redirect_uri,
            "scope": "read:user user:email",
            "state": state,
        }
        return f"{GITHUB_AUTHORIZE_URL}?{urlencode(params)}"
    
    elif provider == OAuthProvider.GOOGLE:
        params = {
            "client_id": settings.google_client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "access_type": "offline",
            "prompt": "consent",
        }
        return f"{GOOGLE_AUTHORIZE_URL}?{urlencode(params)}"
    
    raise ValueError(f"Unknown provider: {provider}")


async def exchange_code_for_token(
    provider: OAuthProvider,
    code: str,
    redirect_uri: str,
    client: httpx.AsyncClient,
) -> OAuthToken:
    """Retries on 5xx or network failures; fails fast on 4xx"""
    settings = get_settings()
    
    if provider == OAuthProvider.GITHUB:
        token_url = GITHUB_TOKEN_URL
        data = {
            "client_id": settings.github_client_id,
            "client_secret": settings.github_client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        }
        headers = {"Accept": "application/json"}
    
    elif provider == OAuthProvider.GOOGLE:
        token_url = GOOGLE_TOKEN_URL
        data = {
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
    
    else:
        raise ValueError(f"Unknown provider: {provider}")
    
    max_retries = 3
    last_error: Exception | None = None
    
    for attempt in range(max_retries):
        try:
            response = await client.post(token_url, data=data, headers=headers)
            
            if response.status_code in RETRYABLE_STATUS_CODES:
                last_error = OAuthError(f"Server error: {response.status_code}")
                if attempt < max_retries - 1:
                    import asyncio
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise last_error
            
            try:
                token_data = response.json() if response.content else {}
            except Exception:
                raise OAuthError("Provider returned invalid JSON response")
            
            # GitHub returns 200 OK with error in body - check for error key first
            error_code = token_data.get("error", "")
            if error_code:
                error_msg = token_data.get("error_description", error_code)
                if error_code in ("bad_verification_code", "invalid_grant", "expired_token"):
                    raise InvalidCodeError(f"Authorization code expired or invalid: {error_msg}")
                raise OAuthError(f"Token exchange failed: {error_msg}")
            
            if response.status_code >= 400:
                raise OAuthError(f"Token exchange failed: HTTP {response.status_code}")
            
            if "access_token" not in token_data:
                raise OAuthError("Provider response missing access_token")
            
            return OAuthToken(
                access_token=token_data["access_token"],
                token_type=token_data.get("token_type", "bearer"),
                scope=token_data.get("scope"),
                refresh_token=token_data.get("refresh_token"),
                expires_in=token_data.get("expires_in"),
            )
            
        except httpx.TimeoutException as e:
            last_error = e
            if attempt < max_retries - 1:
                import asyncio
                await asyncio.sleep(2 ** attempt)
                continue
            raise OAuthError(f"Request timed out after {max_retries} attempts")
            
        except httpx.RequestError as e:
            last_error = e
            if attempt < max_retries - 1:
                import asyncio
                await asyncio.sleep(2 ** attempt)
                continue
            raise OAuthError(f"Network error after {max_retries} attempts: {e}")
    
    raise OAuthError("Token exchange failed")


async def fetch_user_profile(
    provider: OAuthProvider,
    token: OAuthToken,
    client: httpx.AsyncClient,
) -> UserProfile:
    """Uses node_id for GitHub to match GraphQL schema"""
    if provider == OAuthProvider.GITHUB:
        return await _fetch_github_profile(token.access_token, client)
    elif provider == OAuthProvider.GOOGLE:
        return await _fetch_google_profile(token.access_token, client)
    else:
        raise ValueError(f"Unknown provider: {provider}")


async def _fetch_github_profile(access_token: str, client: httpx.AsyncClient) -> UserProfile:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
    }
    
    user_response = await client.get(GITHUB_USER_URL, headers=headers)
    user_response.raise_for_status()
    user_data = user_response.json()
    
    emails_response = await client.get(GITHUB_EMAILS_URL, headers=headers)
    emails_response.raise_for_status()
    emails_data = emails_response.json()
    
    primary_email = None
    is_verified = False
    
    for email_obj in emails_data:
        if email_obj.get("primary"):
            primary_email = email_obj.get("email")
            is_verified = email_obj.get("verified", False)
            break
    
    if not primary_email:
        raise NoEmailError("GitHub account has no primary email")
    
    if not is_verified:
        raise EmailNotVerifiedError("Please verify your email with GitHub before signing in")
    
    return UserProfile(
        email=primary_email,
        provider_id=user_data.get("node_id"),
        avatar_url=user_data.get("avatar_url"),
        is_verified=is_verified,
        username=user_data.get("login"),
    )


async def _fetch_google_profile(access_token: str, client: httpx.AsyncClient) -> UserProfile:
    headers = {"Authorization": f"Bearer {access_token}"}
    
    response = await client.get(GOOGLE_USERINFO_URL, headers=headers)
    response.raise_for_status()
    user_data = response.json()
    
    email = user_data.get("email")
    if not email:
        raise NoEmailError("Google account has no email")
    
    is_verified = user_data.get("verified_email", False)
    if not is_verified:
        raise EmailNotVerifiedError("Please verify your email with Google before signing in")
    
    return UserProfile(
        email=email,
        provider_id=str(user_data.get("id")),
        avatar_url=user_data.get("picture"),
        is_verified=is_verified,
        username=None,
    )


def get_http_client() -> httpx.AsyncClient:
    """todo: remove this; use dependency injection version instead"""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(10.0),
        limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
    )
