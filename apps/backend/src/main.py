import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.core.config import get_settings
from src.core.redis import close_redis
from src.middleware.auth import session_cookie_sync_middleware
from src.api.dependencies import close_http_client

# Configure logging for Cloud Logging compatibility
# JSON audit logs need raw message format; other logs use standard format
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

# Audit logger uses raw format for JSON output
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

# CORS must be first for credentials to work
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(",") if settings.cors_origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware executes in reverse order for responses
app.middleware("http")(session_cookie_sync_middleware)


@app.get("/health")
async def health_check():
    return {"status": "ok"}


from src.api.routes import auth, search

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(search.router, prefix="/search", tags=["search"])
