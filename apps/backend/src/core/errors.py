"""
Centralized error definitions and user-friendly message mapping.
All profile-related errors should be caught and converted to appropriate HTTP responses.
"""
import logging
from typing import Optional

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


class ProfileError(Exception):
    """Base class for profile-related errors with user message and status code."""
    status_code: int = 500
    user_message: str = "Something went wrong. Please try again."
    log_message: Optional[str] = None
    
    def __init__(self, detail: Optional[str] = None):
        self.detail = detail
        super().__init__(detail or self.user_message)


class UnsupportedFormatError(ProfileError):
    status_code = 400
    user_message = "Please upload a PDF or DOCX file"


class FileTooLargeError(ProfileError):
    status_code = 413
    user_message = "Resume must be under 5MB"


class ResumeParseError(ProfileError):
    status_code = 422
    user_message = "We couldn't read your resume. Try a different format?"


class GitHubNotConnectedError(ProfileError):
    status_code = 400
    user_message = "Please connect GitHub first"


class RefreshRateLimitError(ProfileError):
    status_code = 429
    user_message = "GitHub refresh available in a few minutes"
    
    def __init__(self, seconds_remaining: int):
        self.seconds_remaining = seconds_remaining
        minutes = max(1, seconds_remaining // 60)
        self.user_message = f"GitHub refresh available in {minutes} minute{'s' if minutes > 1 else ''}"
        super().__init__(self.user_message)


class InvalidTaxonomyValueError(ProfileError):
    status_code = 400
    
    def __init__(self, field: str, invalid_value: str, valid_options: list[str]):
        self.field = field
        self.invalid_value = invalid_value
        self.valid_options = valid_options
        self.user_message = f"Invalid {field}: '{invalid_value}'"
        super().__init__(self.user_message)


class IntentAlreadyExistsError(ProfileError):
    status_code = 409
    user_message = "Intent already exists. Use update or delete first."


class IntentNotFoundError(ProfileError):
    status_code = 404
    user_message = "No intent data found"


class EmbeddingServiceError(ProfileError):
    status_code = 202
    user_message = "We're having trouble. Your profile will update shortly."


class CannotCompleteOnboardingError(ProfileError):
    status_code = 400
    user_message = "Please add at least one profile source before completing"


class OnboardingAlreadyCompletedError(ProfileError):
    status_code = 409
    user_message = "Onboarding already completed"


class LinkedAccountNotFoundError(ProfileError):
    status_code = 400
    user_message = "Account not connected"


class LinkedAccountRevokedError(ProfileError):
    status_code = 400
    user_message = "Please reconnect your account"


class BookmarkNotFoundError(ProfileError):
    status_code = 404
    user_message = "Bookmark not found"


class BookmarkAlreadyExistsError(ProfileError):
    status_code = 409
    user_message = "You already bookmarked this issue"


class NoteNotFoundError(ProfileError):
    status_code = 404
    user_message = "Note not found"


class IssueNotFoundError(ProfileError):
    status_code = 404
    user_message = "Issue not found"


ERROR_MAP = {
    "UnsupportedFormatError": (400, "Please upload a PDF or DOCX file"),
    "FileTooLargeError": (413, "Resume must be under 5MB"),
    "ResumeParseError": (422, "We couldn't read your resume. Try a different format?"),
    "GitHubNotConnectedError": (400, "Please connect GitHub first"),
    "RefreshRateLimitError": (429, "GitHub refresh available in a few minutes"),
    "GitHubRateLimitError": (503, "GitHub is busy. We'll try again shortly."),
    "GitHubAuthError": (400, "Please reconnect your GitHub account"),
    "InvalidTaxonomyValueError": (400, None),
    "IntentAlreadyExistsError": (409, "Intent already exists. Use update or delete first."),
    "IntentNotFoundError": (404, "No intent data found"),
    "EmbeddingServiceError": (202, "We're having trouble. Your profile will update shortly."),
    "CannotCompleteOnboardingError": (400, "Please add at least one profile source before completing"),
    "OnboardingAlreadyCompletedError": (409, "Onboarding already completed"),
    "LinkedAccountNotFoundError": (400, "Account not connected"),
    "LinkedAccountRevokedError": (400, "Please reconnect your account"),
    "BookmarkNotFoundError": (404, "Bookmark not found"),
    "BookmarkAlreadyExistsError": (409, "You already bookmarked this issue"),
    "NoteNotFoundError": (404, "Note not found"),
    "IssueNotFoundError": (404, "Issue not found"),
}


def handle_profile_error(exc: Exception) -> HTTPException:
    """
    Converts profile exceptions to HTTP responses with user-friendly messages.
    Logs detailed error info server-side.
    """
    error_name = type(exc).__name__
    
    if isinstance(exc, ProfileError):
        logger.warning(
            f"Profile error: {error_name}, detail={exc.detail}, user_message={exc.user_message}"
        )
        return HTTPException(
            status_code=exc.status_code,
            detail=exc.user_message,
        )
    
    if error_name in ERROR_MAP:
        status_code, user_message = ERROR_MAP[error_name]
        message = user_message or str(exc)
        logger.warning(f"Mapped error: {error_name}, message={message}")
        return HTTPException(status_code=status_code, detail=message)
    
    logger.error(f"Unhandled profile error: {error_name}, detail={exc}")
    return HTTPException(
        status_code=500,
        detail="Something went wrong. Please try again.",
    )


async def profile_exception_handler(request: Request, exc: ProfileError) -> JSONResponse:
    """FastAPI exception handler for ProfileError subclasses."""
    logger.warning(
        f"Profile error handler: {type(exc).__name__}, "
        f"path={request.url.path}, user_message={exc.user_message}"
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.user_message},
    )


__all__ = [
    "ProfileError",
    "UnsupportedFormatError",
    "FileTooLargeError",
    "ResumeParseError",
    "GitHubNotConnectedError",
    "RefreshRateLimitError",
    "InvalidTaxonomyValueError",
    "IntentAlreadyExistsError",
    "IntentNotFoundError",
    "EmbeddingServiceError",
    "CannotCompleteOnboardingError",
    "OnboardingAlreadyCompletedError",
    "LinkedAccountNotFoundError",
    "LinkedAccountRevokedError",
    "BookmarkNotFoundError",
    "BookmarkAlreadyExistsError",
    "NoteNotFoundError",
    "IssueNotFoundError",
    "handle_profile_error",
    "profile_exception_handler",
    "ERROR_MAP",
]

