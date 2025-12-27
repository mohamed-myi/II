from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    database_url: str = ""
    direct_database_url: str = ""
    
    jwt_secret_key: str = ""
    fingerprint_secret: str = ""
    
    github_client_id: str = ""
    github_client_secret: str = ""
    
    google_client_id: str = ""
    google_client_secret: str = ""
    
    environment: str = "development"
    cors_origins: str = "http://localhost:3000"
    
    session_remember_me_days: int = 7
    session_default_hours: int = 24
    
    model_config = SettingsConfigDict(
        env_file=".env.local",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()

