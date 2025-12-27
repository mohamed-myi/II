from dataclasses import dataclass

from fastapi import Request

from src.core.security import hash_fingerprint


@dataclass
class RequestContext:
    fingerprint_raw: str | None
    fingerprint_hash: str | None
    ip_address: str
    user_agent: str | None
    login_flow_id: str | None


async def get_request_context(request: Request) -> RequestContext:
    fingerprint_raw = request.headers.get("X-Device-Fingerprint")
    fingerprint_hash = None
    if fingerprint_raw:
        fingerprint_hash = hash_fingerprint(fingerprint_raw)
    
    # X-Forwarded_For can be spoofed; reverse proxy must overwrite this header
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    ip_address = forwarded_for.split(",")[0].strip() if forwarded_for else None
    if not ip_address:
        ip_address = request.client.host if request.client else "0.0.0.0"
    
    user_agent = request.headers.get("User-Agent")
    login_flow_id = request.cookies.get("X-Login-Flow-ID")
    
    return RequestContext(
        fingerprint_raw=fingerprint_raw,
        fingerprint_hash=fingerprint_hash,
        ip_address=ip_address,
        user_agent=user_agent,
        login_flow_id=login_flow_id,
    )
