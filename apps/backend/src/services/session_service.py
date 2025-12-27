from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import delete
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from src.core.config import get_settings
from src.core.oauth import UserProfile, OAuthProvider
from src.core.security import generate_session_id


# Maximum length of user agent string.
USER_AGENT_MAX_LENGTH = 512

# Only update DB if session is over 10% through lifespan.
REFRESH_THRESHOLD_RATIO = 0.1


def _utc_now() -> datetime:
    """Returns timezone-aware UTC datetime; avoids deprecated utcnow()."""
    return datetime.now(timezone.utc)


class ExistingAccountError(Exception):
    """
    Raised when unauthenticated login attempts to use email 
    that belongs to an account created via different provider.
    Contains original_provider for UI messaging.
    """
    def __init__(self, original_provider: str):
        self.original_provider = original_provider
        super().__init__(
            f"Account exists, Please sign in with {original_provider}"
        )


class ProviderConflictError(Exception):
    """
    Raised when authenticated user tries to link provider ID 
    that is already associated with a different user.
    """
    pass


class SessionNotFoundError(Exception):
    """Raised when session lookup fails."""
    pass


class FingerprintMismatchError(Exception):
    """Raised when session fingerprint does not match request fingerprint."""
    pass


async def upsert_user(
    db: AsyncSession,
    profile: UserProfile,
    provider: OAuthProvider,
) -> "User":
    """
    For UNAUTHENTICATED login flow only.
    
    Logic:
    1, If email does not exist -> create new user with created_via = provider
    2, If email exists AND provider matches created_via -> return existing user
    3, If email exists AND provider differs -> raise ExistingAccountError
    """
    # Import from database package (installed via pip install -e ../../packages/database)
    from src.models.identity import User
    
    statement = select(User).where(User.email == profile.email)
    result = await db.exec(statement)
    existing_user = result.first()
    
    if existing_user is None:
        # Create new user
        new_user = User(
            email=profile.email,
            created_via=provider.value,
        )
        
        if provider == OAuthProvider.GITHUB:
            new_user.github_node_id = profile.provider_id
            new_user.github_username = profile.username
        elif provider == OAuthProvider.GOOGLE:
            new_user.google_id = profile.provider_id
        
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        return new_user
    
    # User exists, check if same provider
    if existing_user.created_via != provider.value:
        raise ExistingAccountError(existing_user.created_via)
    
    # Same provider, update provider-specific fields if needed
    if provider == OAuthProvider.GITHUB:
        if existing_user.github_node_id != profile.provider_id:
            existing_user.github_node_id = profile.provider_id
        if existing_user.github_username != profile.username:
            existing_user.github_username = profile.username
    elif provider == OAuthProvider.GOOGLE:
        if existing_user.google_id != profile.provider_id:
            existing_user.google_id = profile.provider_id
    
    await db.commit()
    await db.refresh(existing_user)
    return existing_user


async def link_provider(
    db: AsyncSession,
    user: "User",
    profile: UserProfile,
    provider: OAuthProvider,
) -> "User":
    """
    For AUTHENTICATED account linking only.
    
    Logic:
    1, Verify provider_id is not already linked to different user
    2, If conflict -> raise ProviderConflictError
    3, Update github_node_id or google_id on current user
    """
    from src.models.identity import User
    
    # Check if provider ID is already linked to another user
    if provider == OAuthProvider.GITHUB:
        statement = select(User).where(
            User.github_node_id == profile.provider_id,
            User.id != user.id
        )
    else:
        statement = select(User).where(
            User.google_id == profile.provider_id,
            User.id != user.id
        )
    
    result = await db.exec(statement)
    conflict_user = result.first()
    
    if conflict_user is not None:
        raise ProviderConflictError(
            f"{provider.value} account is already linked to another user"
        )
    
    # Update the provider ID on current user
    if provider == OAuthProvider.GITHUB:
        user.github_node_id = profile.provider_id
        user.github_username = profile.username
    elif provider == OAuthProvider.GOOGLE:
        user.google_id = profile.provider_id
    
    await db.commit()
    await db.refresh(user)
    return user


async def create_session(
    db: AsyncSession,
    user_id: UUID,
    fingerprint_hash: str,
    remember_me: bool,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple["Session", datetime]:
    """
    Creates session record in DB.
    Truncates user_agent to USER_AGENT_MAX_LENGTH chars.
    Returns session and calculated expires_at.
    """
    from src.models.identity import Session
    
    settings = get_settings()
    now = _utc_now()
    
    if remember_me:
        expires_at = now + timedelta(days=settings.session_remember_me_days)
    else:
        expires_at = now + timedelta(hours=settings.session_default_hours)
    
    # Truncate user agent if needed
    truncated_user_agent = None
    if user_agent:
        truncated_user_agent = user_agent[:USER_AGENT_MAX_LENGTH]
    
    session = Session(
        user_id=user_id,
        fingerprint=fingerprint_hash,
        jti=generate_session_id(),
        expires_at=expires_at,
        remember_me=remember_me,
        created_at=now,
        last_active_at=now,
        ip_address=ip_address,
        user_agent_string=truncated_user_agent,
    )
    
    db.add(session)
    await db.commit()
    await db.refresh(session)
    
    return session, expires_at


async def refresh_session(
    db: AsyncSession,
    session: "Session",
) -> datetime | None:
    """
    Updates expires_at and last_active_at in DB.
    Returns new expires_at for cookie update, or None if no update needed.
    
    OPTIMIZATION: Only updates DB if session is >10% through its lifespan.
    This reduces DB writes on high-traffic endpoints.
    """
    settings = get_settings()
    now = _utc_now()
    
    # Calculate total lifespan and elapsed time
    if session.remember_me:
        total_lifespan = timedelta(days=settings.session_remember_me_days)
    else:
        total_lifespan = timedelta(hours=settings.session_default_hours)
    
    # Make expires_at timezone-aware if it isn't
    session_expires = session.expires_at
    if session_expires.tzinfo is None:
        session_expires = session_expires.replace(tzinfo=timezone.utc)
    
    time_remaining = session_expires - now
    elapsed = total_lifespan - time_remaining
    
    # Only update if elapsed > threshold (default 10% of lifespan)
    if elapsed < (total_lifespan * REFRESH_THRESHOLD_RATIO):
        return None
    
    new_expires_at = now + total_lifespan
    session.expires_at = new_expires_at
    session.last_active_at = now
    
    await db.commit()
    await db.refresh(session)
    
    return new_expires_at


async def get_session_by_id_and_fingerprint(
    db: AsyncSession,
    session_id: UUID,
    fingerprint_hash: str,
) -> "Session | None":
    """
    Fetches session by ID AND fingerprint.
    Returns None if not found, fingerprint mismatch, or expired.
    
    SECURITY: Validates fingerprint to prevent session hijacking from different devices.
    """
    from src.models.identity import Session
    
    now = _utc_now()
    
    statement = select(Session).where(
        Session.id == session_id,
        Session.fingerprint == fingerprint_hash,
        Session.expires_at > now,
    )
    result = await db.exec(statement)
    return result.first()


async def get_session_by_id(
    db: AsyncSession,
    session_id: UUID,
) -> "Session | None":
    """
    Fetches session by ID only (for admin/internal use).
    Returns None if not found or expired.
    
    WARNING: Does NOT validate fingerprint; use get_session_by_id_and_fingerprint for auth flows.
    """
    from src.models.identity import Session
    
    now = _utc_now()
    
    statement = select(Session).where(
        Session.id == session_id,
        Session.expires_at > now,
    )
    result = await db.exec(statement)
    return result.first()


async def invalidate_session(
    db: AsyncSession,
    session_id: UUID,
) -> bool:
    """
    Deletes session from DB (logout).
    Returns True if session was deleted, False if not found.
    """
    from src.models.identity import Session
    
    statement = delete(Session).where(Session.id == session_id)
    result = await db.exec(statement)
    await db.commit()
    
    return result.rowcount > 0


async def invalidate_all_sessions(
    db: AsyncSession,
    user_id: UUID,
    except_session_id: UUID | None = None,
) -> int:
    """
    Deletes all sessions for user except optionally the current one.
    Returns count of deleted sessions.
    
    Uses bulk DELETE for efficiency (single SQL command).
    """
    from src.models.identity import Session
    
    statement = delete(Session).where(Session.user_id == user_id)
    
    if except_session_id is not None:
        statement = statement.where(Session.id != except_session_id)
    
    result = await db.exec(statement)
    await db.commit()
    
    return result.rowcount
