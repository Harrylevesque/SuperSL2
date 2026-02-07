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

# Always try to load .env if present
dotenv_path = PROJECT_ROOT / ".env"
try:
    from dotenv import load_dotenv  # type: ignore
    if dotenv_path.exists():
        load_dotenv(dotenv_path)
except Exception:
    pass

# Use BASE_SAVE_DIR from environment (set by .env if loaded), else fallback
_env_base = os.getenv("BASE_SAVE_DIR")
if _env_base:
    candidate = Path(_env_base).expanduser()
else:
    candidate = PROJECT_ROOT / "storage"

try:
    BASE_SAVE_DIR = candidate.resolve(strict=False)
except Exception:
    BASE_SAVE_DIR = candidate

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
        BASE_SAVE_DIR = Path(tempfile.gettempdir())
        logging.warning(
            "Could not create fallback storage '%s' (%s). Using system temp '%s'.",
            fallback,
            exc2,
            BASE_SAVE_DIR,
        )

BASE_SAVE_DIR = Path(BASE_SAVE_DIR)

def is_base_dir_writable() -> bool:
    try:
        test_file = BASE_SAVE_DIR / ".write_test"
        with open(test_file, "w") as f:
            f.write("x")
        test_file.unlink(missing_ok=True)
        return True
    except Exception:
        return False