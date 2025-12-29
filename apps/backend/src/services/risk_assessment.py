from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.middleware.context import RequestContext
    from src.models.identity import Session


@dataclass
class RiskWeights:
    """Configurable weights for risk assessment; higher = more suspicious"""
    fingerprint_mismatch: float = 0.1
    os_mismatch: float = 0.3
    ua_mismatch: float = 0.2
    asn_change: float = 0.2
    country_change: float = 0.8


REAUTHENTICATE_THRESHOLD = 0.7
MEDIUM_RISK_THRESHOLD = 0.3
LOG_THROTTLE_HOURS = 4

DEFAULT_WEIGHTS = RiskWeights()


@dataclass
class RiskResult:
    """Outcome of risk assessment with recommended actions"""
    score: float
    should_reauthenticate: bool
    should_log: bool
    factors: list[str] = field(default_factory=list)


def _safe_compare(session_value: str | None, request_value: str | None) -> bool:
    """
    Returns True if values mismatch; None values on either side aren't considered mismatches
    since missing data should not trigger risk
    """
    if session_value is None or request_value is None:
        return False
    return session_value.lower() != request_value.lower()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _should_log_deviation(session: "Session") -> bool:
    """Returns True if enough time has passed since last deviation log"""
    if session.deviation_logged_at is None:
        return True
    
    logged_at = session.deviation_logged_at
    if logged_at.tzinfo is None:
        logged_at = logged_at.replace(tzinfo=timezone.utc)
    
    throttle_window = timedelta(hours=LOG_THROTTLE_HOURS)
    return _utc_now() - logged_at >= throttle_window


def assess_session_risk(
    session: "Session",
    ctx: "RequestContext",
    weights: RiskWeights | None = None,
) -> RiskResult:
    """
    Compares session metadata against current request context;
    returns risk score and recommended action
    
    Score >= 0.7: Delete session and require reauthentication
    Score 0.3-0.7: Allow but log deviation (throttled to 4h)
    Score < 0.3: Allow silently
    """
    if weights is None:
        weights = DEFAULT_WEIGHTS
    
    score = 0.0
    factors: list[str] = []
    
    # Fingerprint as soft signal; lowest weight since it can change legitimately
    if _safe_compare(session.fingerprint, ctx.fingerprint_hash):
        score += weights.fingerprint_mismatch
        factors.append("fingerprint")
    
    if _safe_compare(session.os_family, ctx.os_family):
        score += weights.os_mismatch
        factors.append(f"os:{session.os_family}->{ctx.os_family}")
    
    if _safe_compare(session.ua_family, ctx.ua_family):
        score += weights.ua_mismatch
        factors.append(f"ua:{session.ua_family}->{ctx.ua_family}")
    
    if _safe_compare(session.asn, ctx.asn):
        score += weights.asn_change
        factors.append(f"asn:{session.asn}->{ctx.asn}")
    
    if _safe_compare(session.country_code, ctx.country_code):
        score += weights.country_change
        factors.append(f"country:{session.country_code}->{ctx.country_code}")
    
    should_reauthenticate = score >= REAUTHENTICATE_THRESHOLD
    
    # Only log medium-risk if throttle window has passed
    should_log = (
        MEDIUM_RISK_THRESHOLD <= score < REAUTHENTICATE_THRESHOLD and
        _should_log_deviation(session)
    )
    
    return RiskResult(
        score=score,
        should_reauthenticate=should_reauthenticate,
        should_log=should_log,
        factors=factors,
    )
