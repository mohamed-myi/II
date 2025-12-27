from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.core.config import get_settings
from src.middleware.auth import session_cookie_sync_middleware

settings = get_settings()

app = FastAPI(
    title="IssueIndex API",
    description="Issue discovery and developer matching platform",
    version="0.1.0",
)

# Must be first for credentials to work
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(",") if settings.cors_origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Must be registered after CORS middleware - Middleware executes in reverse order for responses
app.middleware("http")(session_cookie_sync_middleware)


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    return {"status": "ok"}


# TODO: Include routers Ex:
# from src.api.routes import auth
# app.include_router(auth.router, prefix="/auth", tags=["auth"])
