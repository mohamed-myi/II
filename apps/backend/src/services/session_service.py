from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import delete
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from src.core.config import get_settings
from src.core.oauth import UserProfile, OAuthProvider
from src.core.security import generate_session_id


USER_AGENT_MAX_LENGTH = 512
REFRESH_THRESHOLD_RATIO = 0.1


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ExistingAccountError(Exception):
    """Contains original_provider for UI messaging"""
    def __init__(self, original_provider: str):
        self.original_provider = original_provider
        super().__init__(
            f"Account exists, Please sign in with {original_provider}"
        )


class ProviderConflictError(Exception):
    """Provider ID already associated with different user"""
    pass


class SessionNotFoundError(Exception):
    pass


class FingerprintMismatchError(Exception):
    pass


async def upsert_user(
    db: AsyncSession,
    profile: UserProfile,
    provider: OAuthProvider,
) -> "User":
    """
    For UNAUTHENTICATED login flow only;
    1 Email not exist creates new user; 2 Email exists AND provider matches returns existing;
    3 Email exists AND provider differs raises ExistingAccountError
    """
    from src.models.identity import User
    
    statement = select(User).where(User.email == profile.email)
    result = await db.exec(statement)
    existing_user = result.first()
    
    if existing_user is None:
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
    
    if existing_user.created_via != provider.value:
        raise ExistingAccountError(existing_user.created_via)
    
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
    """For AUTHENTICATED account linking only; raises ProviderConflictError if provider_id linked to different user"""
    from src.models.identity import User
    
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
    from src.models.identity import Session
    
    settings = get_settings()
    now = _utc_now()
    
    if remember_me:
        expires_at = now + timedelta(days=settings.session_remember_me_days)
    else:
        expires_at = now + timedelta(hours=settings.session_default_hours)
    
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
    """Only updates DB if session is over 10% through lifespan; reduces DB writes"""
    settings = get_settings()
    now = _utc_now()
    
    if session.remember_me:
        total_lifespan = timedelta(days=settings.session_remember_me_days)
    else:
        total_lifespan = timedelta(hours=settings.session_default_hours)
    
    session_expires = session.expires_at
    if session_expires.tzinfo is None:
        session_expires = session_expires.replace(tzinfo=timezone.utc)
    
    time_remaining = session_expires - now
    elapsed = total_lifespan - time_remaining
    
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
    """Validates fingerprint to prevent session hijacking from different devices"""
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
    """Does NOT validate fingerprint; use get_session_by_id_and_fingerprint for auth flows"""
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
    """Uses bulk DELETE for efficiency"""
    from src.models.identity import Session
    
    statement = delete(Session).where(Session.user_id == user_id)
    
    if except_session_id is not None:
        statement = statement.where(Session.id != except_session_id)
    
    result = await db.exec(statement)
    await db.commit()
    
    return result.rowcount
