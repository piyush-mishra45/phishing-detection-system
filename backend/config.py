"""Central configuration. All secrets come from environment variables."""
import os
from pathlib import Path

try:  # optional
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    load_dotenv()
except ImportError:  # pragma: no cover
    pass

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent


class Config:
    ENV = os.getenv("FLASK_ENV", "development")
    IS_PROD = ENV == "production"
    SECRET_KEY = os.getenv("SECRET_KEY", "")
    DATABASE_URL = os.getenv("DATABASE_URL") or f"sqlite:///{ROOT_DIR / 'phishguard_dev.db'}"
    CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if o.strip()]
    JWT_EXPIRES_HOURS = int(os.getenv("JWT_EXPIRES_HOURS", "8"))
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()
    RATE_LIMIT_SCAN_PER_MIN = int(os.getenv("RATE_LIMIT_SCAN_PER_MIN", "10"))
    RATE_LIMIT_AUTH_PER_MIN = int(os.getenv("RATE_LIMIT_AUTH_PER_MIN", "10"))
    MODEL_DIR = Path(os.getenv("MODEL_DIR", ROOT_DIR / "models"))
    UPLOAD_DIR = BASE_DIR / "uploads"
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB request cap (.eml uploads)

    # Website scanner safety limits
    FETCH_TIMEOUT = (3.05, 8)       # connect, read seconds
    FETCH_MAX_BYTES = 1_000_000     # response body cap
    FETCH_MAX_REDIRECTS = 5

    @classmethod
    def validate(cls):
        if not cls.SECRET_KEY:
            if cls.IS_PROD:
                raise RuntimeError("SECRET_KEY must be set in production")
            cls.SECRET_KEY = "dev-only-insecure-key-do-not-use-in-production"
