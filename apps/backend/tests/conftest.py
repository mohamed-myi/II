import os
import pytest

# Set test environment variables before importing app modules
# These are test values only, not real secrets
os.environ.setdefault("FINGERPRINT_SECRET", "test_fingerprint_secret_for_testing_only_32chars")
os.environ.setdefault("JWT_SECRET_KEY", "test_jwt_secret_key_for_testing")
os.environ.setdefault("GITHUB_CLIENT_ID", "test_github_client_id")
os.environ.setdefault("GITHUB_CLIENT_SECRET", "test_github_client_secret")
os.environ.setdefault("GOOGLE_CLIENT_ID", "test_google_client_id")
os.environ.setdefault("GOOGLE_CLIENT_SECRET", "test_google_client_secret")
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("ENVIRONMENT", "development")
