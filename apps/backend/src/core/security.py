import hmac
import hashlib
import secrets
from uuid import uuid4

from .config import get_settings


def hash_fingerprint(raw_value: str) -> str:
    """
    HMAC-SHA256 hashes a device fingerprint to prevent storing Personal Identification Information.
    """
    settings = get_settings()
    return hmac.new(
        key=settings.fingerprint_secret.encode("utf-8"),
        msg=raw_value.encode("utf-8"),
        digestmod=hashlib.sha256
    ).hexdigest()


def generate_session_id() -> str:
    """
    Generates a unique UUIDv4 for stateful session management.
    """
    return str(uuid4())


def compare_fingerprints(stored_hash: str, request_raw: str) -> bool:
    """
    O(1) comparison of fingerprints to prevent timing attacks.
    """
    request_hash = hash_fingerprint(request_raw)
    return secrets.compare_digest(stored_hash, request_hash)


def generate_login_flow_id() -> str:
    """
    Secure 16-byte token for rate limiting auth flows by user/device.
    """
    return secrets.token_urlsafe(16)
