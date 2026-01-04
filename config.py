"""
Project configuration: centralize filesystem base directory.
- Reads BASE_SAVE_DIR from environment or .env file (if python-dotenv installed).
- Exposes PROJECT_ROOT and BASE_SAVE_DIR as pathlib.Path objects.
"""
from pathlib import Path
import os

# Project root (directory containing this file)
PROJECT_ROOT = Path(__file__).parent

# Try to load a .env file if python-dotenv is installed (optional)
dotenv_path = PROJECT_ROOT / '.env'
try:
    # prefer an explicit import so the behavior is deterministic in runtime
    from dotenv import load_dotenv
    # load .env from project root
    if dotenv_path.exists():
        load_dotenv(dotenv_path)
except Exception:
    # python-dotenv not installed or load failed; fall back to reading .env manually below
    pass

# If BASE_SAVE_DIR isn't set via environment yet, attempt a small .env parser as a fallback
if os.getenv('BASE_SAVE_DIR') is None and dotenv_path.exists():
    try:
        with open(dotenv_path, 'r', encoding='utf-8') as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' not in line:
                    continue
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k == 'BASE_SAVE_DIR' and v:
                    os.environ['BASE_SAVE_DIR'] = v
                    break
    except Exception:
        # ignore parse errors and continue using os.environ
        pass

# Base save directory (can be overridden with the BASE_SAVE_DIR environment variable)
_base = os.getenv("BASE_SAVE_DIR")
if _base:
    BASE_SAVE_DIR = Path(_base).expanduser().resolve()
else:
    BASE_SAVE_DIR = (PROJECT_ROOT / "storage").resolve()

# Ensure base directory exists
BASE_SAVE_DIR.mkdir(parents=True, exist_ok=True)
