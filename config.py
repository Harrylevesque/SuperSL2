# python
"""
Project configuration: centralize filesystem base directory.
- Reads `BASE_SAVE_DIR` from environment or .env file (if python-dotenv installed).
- Exposes `PROJECT_ROOT` and `BASE_SAVE_DIR` as pathlib.Path objects.
- Falls back to a writable system temp directory if the configured location can't be created.
"""
from pathlib import Path
import os
import tempfile
import logging

logging.getLogger(__name__).addHandler(logging.NullHandler())

# Project root (directory containing this file)
PROJECT_ROOT = Path(__file__).resolve().parent

# Try to load a .env file if python-dotenv is installed (optional)
dotenv_path = PROJECT_ROOT / ".env"
try:
    from dotenv import load_dotenv  # type: ignore
    if dotenv_path.exists():
        load_dotenv(dotenv_path)
except Exception:
    # ignore if python-dotenv is not installed or load failed
    pass

# If BASE_SAVE_DIR isn't set via environment yet, attempt a small .env parser as a fallback
if os.getenv("BASE_SAVE_DIR") is None and dotenv_path.exists():
    try:
        with open(dotenv_path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                if k.strip() == "BASE_SAVE_DIR" and v.strip():
                    os.environ["BASE_SAVE_DIR"] = v.strip().strip('"').strip("'")
                    break
    except Exception:
        # ignore parse errors and continue using os.environ
        pass

# Resolve base directory choice
_env_base = os.getenv("BASE_SAVE_DIR")
if _env_base:
    candidate = Path(_env_base).expanduser()
else:
    candidate = PROJECT_ROOT / "storage"

# Use resolve(strict=False) to avoid raising if path doesn't exist yet
try:
    BASE_SAVE_DIR = candidate.resolve(strict=False)
except Exception:
    # If resolve fails for any reason, fall back to raw Path
    BASE_SAVE_DIR = candidate

# Try to create the directory; if that fails, fall back to system temp dir
try:
    BASE_SAVE_DIR.mkdir(parents=True, exist_ok=True)
except Exception as exc:
    fallback = Path(tempfile.gettempdir()) / "supersl2_storage"
    try:
        fallback.mkdir(parents=True, exist_ok=True)
        BASE_SAVE_DIR = fallback
        logging.warning(
            "Could not create configured BASE_SAVE_DIR '%s' (%s). Using fallback '%s'.",
            candidate,
            exc,
            BASE_SAVE_DIR,
        )
    except Exception as exc2:
        # last-resort: use tempfile.gettempdir() without subfolder
        BASE_SAVE_DIR = Path(tempfile.gettempdir())
        logging.warning(
            "Could not create fallback storage '%s' (%s). Using system temp '%s'.",
            fallback,
            exc2,
            BASE_SAVE_DIR,
        )

# Ensure BASE_SAVE_DIR is a Path object and exported for other modules
BASE_SAVE_DIR = Path(BASE_SAVE_DIR)

# Optional: expose a small helper to check writability
def is_base_dir_writable() -> bool:
    try:
        test_file = BASE_SAVE_DIR / ".write_test"
        with open(test_file, "w") as f:
            f.write("x")
        test_file.unlink(missing_ok=True)  # Python 3.8+; safe remove
        return True
    except Exception:
        return False