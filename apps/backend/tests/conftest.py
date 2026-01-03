import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load .env.local from project root before setting any defaults.
# This ensures integration tests use the real DATABASE_URL.
project_root = Path(__file__).resolve().parent.parent.parent.parent
env_local_path = project_root / ".env.local"
load_dotenv(env_local_path)
load_dotenv(project_root / ".env")

if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Add database package source to path for models imports
database_src = project_root / "packages" / "database" / "src"
if str(database_src) not in sys.path:
    sys.path.insert(0, str(database_src))
os.environ.setdefault("FINGERPRINT_SECRET", "test_fingerprint_secret_for_testing_only_32chars")
os.environ.setdefault("JWT_SECRET_KEY", "test_jwt_secret_key_for_testing")
os.environ.setdefault("GITHUB_CLIENT_ID", "test_github_client_id")
os.environ.setdefault("GITHUB_CLIENT_SECRET", "test_github_client_secret")
os.environ.setdefault("GOOGLE_CLIENT_ID", "test_google_client_id")
os.environ.setdefault("GOOGLE_CLIENT_SECRET", "test_google_client_secret")
os.environ.setdefault("ENVIRONMENT", "development")
