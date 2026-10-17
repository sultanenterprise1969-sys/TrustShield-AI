"""Central settings. Everything secret comes from environment variables (see .env.example)."""
import os
from pathlib import Path

try:  # python-dotenv is optional; .env is only a convenience for local use
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # pragma: no cover
    pass

BASE_DIR = Path(__file__).resolve().parent


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


DB_PATH = Path(os.getenv("TRUSTSHIELD_DB_PATH", BASE_DIR / "data" / "history.db"))
MODEL_PATH = Path(os.getenv("TRUSTSHIELD_MODEL_PATH", BASE_DIR / "models" / "url_model.joblib"))
METRICS_PATH = Path(os.getenv("TRUSTSHIELD_METRICS_PATH", BASE_DIR / "models" / "metrics.json"))
SAMPLE_LOGIN_CSV = BASE_DIR / "data" / "login_events_sample.csv"
TRAINING_CSV = BASE_DIR / "data" / "urls_synthetic.csv"

MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_MB", "5")) * 1024 * 1024
MAX_CSV_BYTES = 2 * 1024 * 1024
MAX_TEXT_CHARS = 20_000
MAX_URL_CHARS = 2_048
MAX_IMAGE_PIXELS = 25_000_000
MAX_LOGIN_ROWS = 5_000

CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:8501").split(",") if o.strip()]


def llm_settings() -> dict:
    """Read at call time so tests / users can change env vars without restarting."""
    return {
        "enabled": _bool("LLM_ENABLED"),
        "api_url": os.getenv("LLM_API_URL", "").strip(),
        "api_key": os.getenv("LLM_API_KEY", "").strip(),
        "model": os.getenv("LLM_MODEL", "").strip(),
    }


def threat_intel_settings() -> dict:
    return {
        "enabled": _bool("THREAT_INTEL_ENABLED"),
        "api_key": os.getenv("THREAT_INTEL_API_KEY", "").strip(),
        "provider": "Google Safe Browsing",
    }

TEAM_NAME = os.getenv("TEAM_NAME", "[TEAM NAME]")
