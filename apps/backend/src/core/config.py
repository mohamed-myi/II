from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    database_url: str = ""
    direct_database_url: str = ""
    
    jwt_secret_key: str = ""
    fingerprint_secret: str = ""
    fernet_key: str = ""  # Token encryption key for linked_accounts
    
    github_client_id: str = ""
    github_client_secret: str = ""
    
    google_client_id: str = ""
    google_client_secret: str = ""
    
    environment: str = "development"
    cors_origins: str = "http://localhost:3000"
    
    session_remember_me_days: int = 7
    session_default_hours: int = 24
    max_sessions_per_user: int = 5
    
    frontend_base_url: str = "http://localhost:3000"
    
    redis_url: str = ""
    
    max_auth_requests_per_minute: int = 10
    rate_limit_window_seconds: int = 60
    
    git_token: str = ""
    
    model_config = SettingsConfigDict(
        env_file=".env.local",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()

