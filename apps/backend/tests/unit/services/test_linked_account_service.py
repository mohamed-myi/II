import pytest
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock, patch
import os

# Import all models to ensure SQLAlchemy mappers are configured
# before LinkedAccount is used (models have inter-dependent relationships)
import models.identity
import models.profiles
import models.persistence


@pytest.fixture(autouse=True)
def mock_settings():
    # Generate a valid Fernet key for testing
    from cryptography.fernet import Fernet
    test_fernet_key = Fernet.generate_key().decode()
    
    with patch.dict(os.environ, {
        "FERNET_KEY": test_fernet_key,
    }):
        from src.core.config import get_settings
        get_settings.cache_clear()
        yield
        get_settings.cache_clear()


@pytest.fixture
def mock_db():
    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.exec = AsyncMock()
    return db


class TestTokenEncryption:
    """Token encryption and decryption behavior"""
    
    def test_encrypt_decrypt_roundtrip(self):
        """Encrypted token decrypts to original value"""
        from src.services.linked_account_service import encrypt_token, decrypt_token
        
        original = "gho_test_token_12345"
        encrypted = encrypt_token(original)
        decrypted = decrypt_token(encrypted)
        
        assert decrypted == original
        assert encrypted != original

    def test_encrypted_tokens_differ(self):
        """Same token produces different ciphertext each time (salt)"""
        from src.services.linked_account_service import encrypt_token
        
        token = "gho_test_token_12345"
        encrypted1 = encrypt_token(token)
        encrypted2 = encrypt_token(token)
        
        assert encrypted1 != encrypted2

    def test_decrypt_invalid_token_raises(self):
        """Invalid ciphertext raises TokenEncryptionError"""
        from src.services.linked_account_service import decrypt_token, TokenEncryptionError
        
        with pytest.raises(TokenEncryptionError) as exc:
            decrypt_token("not_a_valid_encrypted_token")
        
        assert "decryption failed" in str(exc.value).lower()

    def test_encrypt_raises_without_fernet_key(self):
        """Missing FERNET_KEY raises TokenEncryptionError"""
        from src.services.linked_account_service import encrypt_token, TokenEncryptionError
        from src.core.config import get_settings
        
        with patch.dict(os.environ, {"FERNET_KEY": ""}):
            get_settings.cache_clear()
            
            with pytest.raises(TokenEncryptionError) as exc:
                encrypt_token("test_token")
            
            assert "not configured" in str(exc.value).lower()
            get_settings.cache_clear()


class TestStoreLinkedAccount:
    """Token storage logic"""
    
    async def test_creates_new_account(self, mock_db):
        """Stores new linked account with encrypted token"""
        from src.services.linked_account_service import store_linked_account
        from models.identity import LinkedAccount
        
        user_id = uuid4()
        
        mock_result = MagicMock()
        mock_result.first.return_value = None
        mock_db.exec.return_value = mock_result
        
        await store_linked_account(
            db=mock_db,
            user_id=user_id,
            provider="github",
            provider_user_id="MDQ6VXNlcjEyMzQ1Njc=",
            access_token="gho_test_token",
            scopes=["read:user", "repo"],
        )
        
        mock_db.add.assert_called_once()
        added_account = mock_db.add.call_args[0][0]
        
        assert added_account.user_id == user_id
        assert added_account.provider == "github"
        assert added_account.access_token != "gho_test_token"  # Encrypted
        mock_db.commit.assert_called_once()

    async def test_updates_existing_account(self, mock_db):
        """Replaces tokens when account already exists"""
        from src.services.linked_account_service import store_linked_account, encrypt_token
        
        user_id = uuid4()
        existing = MagicMock()
        existing.user_id = user_id
        existing.provider = "github"
        existing.access_token = encrypt_token("old_token")
        existing.revoked_at = None
        
        mock_result = MagicMock()
        mock_result.first.return_value = existing
        mock_db.exec.return_value = mock_result
        
        result = await store_linked_account(
            db=mock_db,
            user_id=user_id,
            provider="github",
            provider_user_id="MDQ6VXNlcjEyMzQ1Njc=",
            access_token="new_token",
        )
        
        assert result == existing
        assert existing.access_token != encrypt_token("old_token")
        mock_db.add.assert_not_called()  # Updated existing, didnt add new

    async def test_reactivates_revoked_account(self, mock_db):
        """Reconnecting clears revoked_at timestamp"""
        from src.services.linked_account_service import store_linked_account
        
        user_id = uuid4()
        revoked_account = MagicMock()
        revoked_account.revoked_at = datetime.now(timezone.utc)
        
        mock_result = MagicMock()
        mock_result.first.return_value = revoked_account
        mock_db.exec.return_value = mock_result
        
        await store_linked_account(
            db=mock_db,
            user_id=user_id,
            provider="github",
            provider_user_id="MDQ6VXNlcjEyMzQ1Njc=",
            access_token="new_token",
        )
        
        assert revoked_account.revoked_at is None


class TestGetValidAccessToken:
    """Token retrieval logic"""
    
    async def test_returns_decrypted_token(self, mock_db):
        """Returns usable token from encrypted storage"""
        from src.services.linked_account_service import (
            get_valid_access_token,
            encrypt_token,
        )
        
        user_id = uuid4()
        raw_token = "gho_actual_api_token"
        
        account = MagicMock()
        account.access_token = encrypt_token(raw_token)
        account.revoked_at = None
        
        mock_result = MagicMock()
        mock_result.first.return_value = account
        mock_db.exec.return_value = mock_result
        
        token = await get_valid_access_token(mock_db, user_id, "github")
        
        assert token == raw_token

    async def test_raises_not_found_error(self, mock_db):
        """Raises LinkedAccountNotFoundError when no account exists"""
        from src.services.linked_account_service import (
            get_valid_access_token,
            LinkedAccountNotFoundError,
        )
        
        mock_result = MagicMock()
        mock_result.first.return_value = None
        mock_db.exec.return_value = mock_result
        
        with pytest.raises(LinkedAccountNotFoundError) as exc:
            await get_valid_access_token(mock_db, uuid4(), "github")
        
        assert "github" in str(exc.value).lower()

    async def test_raises_revoked_error(self, mock_db):
        """Raises LinkedAccountRevokedError for disconnected accounts"""
        from src.services.linked_account_service import (
            get_valid_access_token,
            LinkedAccountRevokedError,
            encrypt_token,
        )
        
        revoked_account = MagicMock()
        revoked_account.access_token = encrypt_token("old_token")
        revoked_account.revoked_at = datetime.now(timezone.utc)
        
        mock_result = MagicMock()
        mock_result.first.return_value = revoked_account
        mock_db.exec.return_value = mock_result
        
        with pytest.raises(LinkedAccountRevokedError) as exc:
            await get_valid_access_token(mock_db, uuid4(), "github")
        
        assert "disconnected" in str(exc.value).lower()


class TestMarkRevoked:
    """Account disconnection logic"""
    
    async def test_sets_revoked_timestamp(self, mock_db):
        """Revocation sets revoked_at without deleting record"""
        from src.services.linked_account_service import mark_revoked
        
        account = MagicMock()
        account.revoked_at = None
        
        mock_result = MagicMock()
        mock_result.first.return_value = account
        mock_db.exec.return_value = mock_result
        
        result = await mark_revoked(mock_db, uuid4(), "github")
        
        assert result is True
        assert account.revoked_at is not None
        mock_db.commit.assert_called_once()

    async def test_returns_false_when_not_found(self, mock_db):
        """Returns False when no account to revoke"""
        from src.services.linked_account_service import mark_revoked
        
        mock_result = MagicMock()
        mock_result.first.return_value = None
        mock_db.exec.return_value = mock_result
        
        result = await mark_revoked(mock_db, uuid4(), "github")
        
        assert result is False
        mock_db.commit.assert_not_called()


class TestListLinkedAccounts:
    """Account listing logic"""
    
    async def test_excludes_revoked_by_default(self, mock_db):
        """Only returns active accounts unless include_revoked is True"""
        from src.services.linked_account_service import list_linked_accounts
        
        mock_result = MagicMock()
        mock_result.all.return_value = []
        mock_db.exec.return_value = mock_result
        
        with patch("src.services.linked_account_service.select") as mock_select:
            mock_chain = MagicMock()
            mock_select.return_value.where.return_value = mock_chain
            mock_chain.where.return_value = mock_chain
            
            await list_linked_accounts(mock_db, uuid4())
            
            # First where for user_id, second where for revoked_at is None
            mock_chain.where.assert_called_once()

    async def test_includes_revoked_when_requested(self, mock_db):
        """Returns all accounts including revoked when include_revoked is True"""
        from src.services.linked_account_service import list_linked_accounts
        
        mock_result = MagicMock()
        mock_result.all.return_value = []
        mock_db.exec.return_value = mock_result
        
        with patch("src.services.linked_account_service.select") as mock_select:
            mock_chain = MagicMock()
            mock_select.return_value.where.return_value = mock_chain
            
            await list_linked_accounts(mock_db, uuid4(), include_revoked=True)
            
            # Only one where clause (user_id)
            mock_chain.where.assert_not_called()

