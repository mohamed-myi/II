import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.core.config import get_settings
from src.core.redis import close_redis
from src.core.errors import ProfileError, profile_exception_handler
from src.middleware.auth import session_cookie_sync_middleware
from src.api.dependencies import close_http_client
from src.services.embedding_service import close_embedder

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

audit_logger = logging.getLogger("audit")
audit_handler = logging.StreamHandler()
audit_handler.setFormatter(logging.Formatter("%(message)s"))
audit_logger.handlers = [audit_handler]
audit_logger.propagate = False

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await close_http_client()
    await close_redis()
    await close_embedder()


app = FastAPI(
    title="IssueIndex API",
    description="Issue discovery and developer matching platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_exception_handler(ProfileError, profile_exception_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(",") if settings.cors_origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.middleware("http")(session_cookie_sync_middleware)


@app.get("/health")
async def health_check():
    return {"status": "ok"}


from src.api.routes import (
    auth,
    search,
    profile,
    profile_onboarding,
    profile_github,
    profile_resume,
    feed,
    bookmarks,
    recommendations,
    internal_recommendations,
)

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(search.router, prefix="/search", tags=["search"])
app.include_router(feed.router, prefix="/feed", tags=["feed"])
app.include_router(recommendations.router, prefix="/recommendations", tags=["recommendations"])
app.include_router(internal_recommendations.router, prefix="/internal", tags=["internal"])
app.include_router(profile.router, prefix="/profile", tags=["profile"])
app.include_router(profile_onboarding.router, prefix="/profile", tags=["profile"])
app.include_router(profile_github.router, prefix="/profile", tags=["profile"])
app.include_router(profile_resume.router, prefix="/profile", tags=["profile"])
app.include_router(bookmarks.router, prefix="/bookmarks", tags=["bookmarks"])
