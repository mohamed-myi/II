"""Service for managing linked OAuth accounts for profile features.

Handles token storage (with encryption), retrieval, refresh, and revocation.
Used by the profile connect flow to store GitHub OAuth tokens for background
fetching of user activity data.
"""
from datetime import datetime, timezone
from uuid import UUID

from cryptography.fernet import Fernet, InvalidToken
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from src.core.config import get_settings
from models.identity import LinkedAccount


class TokenEncryptionError(Exception):
    """Raised when token encryption or decryption fails"""
    pass


class LinkedAccountNotFoundError(Exception):
    """Raised when a linked account does not exist for the given user and provider"""
    pass


class LinkedAccountRevokedError(Exception):
    """Raised when attempting to use a revoked linked account"""
    pass


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _get_fernet() -> Fernet:
    """Returns Fernet instance for token encryption/decryption"""
    settings = get_settings()
    if not settings.fernet_key:
        raise TokenEncryptionError("FERNET_KEY not configured")
    return Fernet(settings.fernet_key.encode())


def encrypt_token(token: str) -> str:
    """Encrypts a token for secure database storage"""
    try:
        fernet = _get_fernet()
        return fernet.encrypt(token.encode()).decode()
    except Exception as e:
        raise TokenEncryptionError(f"Failed to encrypt token: {e}")


def decrypt_token(encrypted_token: str) -> str:
    """Decrypts a stored token for API use"""
    try:
        fernet = _get_fernet()
        return fernet.decrypt(encrypted_token.encode()).decode()
    except InvalidToken:
        raise TokenEncryptionError("Token decryption failed; key may have rotated")
    except Exception as e:
        raise TokenEncryptionError(f"Failed to decrypt token: {e}")


async def store_linked_account(
    db: AsyncSession,
    user_id: UUID,
    provider: str,
    provider_user_id: str,
    access_token: str,
    refresh_token: str | None = None,
    scopes: list[str] | None = None,
    expires_at: datetime | None = None,
) -> LinkedAccount:
    """
    Stores or updates a linked account with encrypted tokens.
    If an account for the same user+provider exists, updates it (reactivates if revoked).
    """
    statement = select(LinkedAccount).where(
        LinkedAccount.user_id == user_id,
        LinkedAccount.provider == provider,
    )
    result = await db.exec(statement)
    existing = result.first()
    
    encrypted_access = encrypt_token(access_token)
    encrypted_refresh = encrypt_token(refresh_token) if refresh_token else None
    
    if existing is not None:
        # Update existing account (reactivate if was revoked)
        existing.provider_user_id = provider_user_id
        existing.access_token = encrypted_access
        existing.refresh_token = encrypted_refresh
        existing.scopes = scopes or []
        existing.expires_at = expires_at
        existing.revoked_at = None  # Reactivate
        
        await db.commit()
        await db.refresh(existing)
        return existing
    
    # Create new linked account
    account = LinkedAccount(
        user_id=user_id,
        provider=provider,
        provider_user_id=provider_user_id,
        access_token=encrypted_access,
        refresh_token=encrypted_refresh,
        scopes=scopes or [],
        expires_at=expires_at,
    )
    
    db.add(account)
    await db.commit()
    await db.refresh(account)
    return account


async def get_linked_account(
    db: AsyncSession,
    user_id: UUID,
    provider: str,
) -> LinkedAccount | None:
    """
    Fetches linked account for user+provider.
    Returns None if not found; does NOT filter out revoked accounts.
    """
    statement = select(LinkedAccount).where(
        LinkedAccount.user_id == user_id,
        LinkedAccount.provider == provider,
    )
    result = await db.exec(statement)
    return result.first()


async def get_active_linked_account(
    db: AsyncSession,
    user_id: UUID,
    provider: str,
) -> LinkedAccount | None:
    """Fetches linked account only if not revoked"""
    statement = select(LinkedAccount).where(
        LinkedAccount.user_id == user_id,
        LinkedAccount.provider == provider,
        LinkedAccount.revoked_at.is_(None),
    )
    result = await db.exec(statement)
    return result.first()


async def get_valid_access_token(
    db: AsyncSession,
    user_id: UUID,
    provider: str,
) -> str:
    """
    Returns a decrypted access token for API use.
    Raises LinkedAccountNotFoundError if no account exists.
    Raises LinkedAccountRevokedError if account was revoked.
    """
    account = await get_linked_account(db, user_id, provider)
    
    if account is None:
        raise LinkedAccountNotFoundError(
            f"No linked {provider} account for user {user_id}"
        )
    
    if account.revoked_at is not None:
        raise LinkedAccountRevokedError(
            f"{provider} account was disconnected at {account.revoked_at}"
        )
    
    return decrypt_token(account.access_token)


async def mark_revoked(
    db: AsyncSession,
    user_id: UUID,
    provider: str,
) -> bool:
    """
    Marks a linked account as revoked. Does NOT delete the record
    (keeps historical data for stale profile signals).
    Returns True if account was found and revoked, False if not found.
    """
    account = await get_linked_account(db, user_id, provider)
    
    if account is None:
        return False
    
    account.revoked_at = _utc_now()
    await db.commit()
    return True


async def list_linked_accounts(
    db: AsyncSession,
    user_id: UUID,
    include_revoked: bool = False,
) -> list[LinkedAccount]:
    """Lists all linked accounts for a user"""
    statement = select(LinkedAccount).where(
        LinkedAccount.user_id == user_id,
    )
    
    if not include_revoked:
        statement = statement.where(LinkedAccount.revoked_at.is_(None))
    
    result = await db.exec(statement)
    return list(result.all())


async def update_tokens(
    db: AsyncSession,
    user_id: UUID,
    provider: str,
    access_token: str,
    refresh_token: str | None = None,
    expires_at: datetime | None = None,
) -> LinkedAccount:
    """Updates tokens for an existing linked account."""
    account = await get_linked_account(db, user_id, provider)
    
    if account is None:
        raise LinkedAccountNotFoundError(
            f"No linked {provider} account for user {user_id}"
        )
    
    account.access_token = encrypt_token(access_token)
    if refresh_token is not None:
        account.refresh_token = encrypt_token(refresh_token)
    if expires_at is not None:
        account.expires_at = expires_at
    
    await db.commit()
    await db.refresh(account)
    return account

