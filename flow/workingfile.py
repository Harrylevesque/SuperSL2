import time
# json is imported inside functions where needed to avoid unused-import warnings
from dotenv import load_dotenv
import os


load_dotenv()

serviceip = os.getenv("host")

def workingfile(sv_uuid, svu_uuid, con_uuid):
    sv_uuid = sv_uuid.strip()
    svu_uuid = svu_uuid.strip()
    con_uuid = con_uuid.strip()

    data=[
        {
            "status": "requested",
            "time_of_last_completion": "",
            "last_step_updated": "",

            "sv_uuid": sv_uuid,
            "svu_uuid": svu_uuid,
            "con_uuid": con_uuid,

            "time": time.time(),
            "host": serviceip,

            "steps": {
                "keymatch": "",
                "webauthn": "",
                "keypair": "",
                "otp": ""
            }
        }
    ]
    return data

def update_workingfile_status(con_uuid: str, status: str, step_name: str, time_of_last_completion: float = None):
    """
    Update the status and time_of_last_completion for a given step in the session/workingfile.
    Writes back to all existing copies (workingfiles and session) and uses atomic replace to avoid partial writes.
    Args:
        con_uuid: Connection UUID (e.g. 'con--...')
        status: New status string
        step_name: Step name (e.g., 'keymatch', 'webauthn', 'keypair', 'otp')
        time_of_last_completion: Optional timestamp
    Returns:
        True on success
    """
    import os
    from pathlib import Path
    import json
    import tempfile

    base_dir = os.getenv("BASE_SAVE_DIR", "./storage")
    working_path = Path(base_dir) / "workingfiles" / f"{con_uuid}.json"
    session_path = Path(base_dir) / "session" / f"{con_uuid}.json"

    # Collect existing file paths to update
    candidates = [p for p in (working_path, session_path) if p.exists()]
    if not candidates:
        # If no file exists, create session path as default destination
        session_path.parent.mkdir(parents=True, exist_ok=True)
        # initialize a workingfile structure if needed
        data = [
            {
                "status": status if status != "requested" else "requested",
                "time_of_last_completion": time_of_last_completion or "",
                "last_step_updated": step_name if status != "requested" else "",
                "sv_uuid": "",
                "svu_uuid": "",
                "con_uuid": con_uuid,
                "time": time.time(),
                "host": os.getenv("host", ""),
                "steps": {"keymatch": "", "webauthn": "", "keypair": "", "otp": ""},
            }
        ]
        candidates = [session_path]
        initial_data = data
    else:
        # Read primary candidate to obtain current structure
        primary = candidates[0]
        with open(primary, "r", encoding="utf-8") as f:
            try:
                initial_data = json.load(f)
            except Exception:
                # fallback to list structure
                initial_data = [
                    {
                        "status": "",
                        "time_of_last_completion": "",
                        "last_step_updated": "",
                        "sv_uuid": "",
                        "svu_uuid": "",
                        "con_uuid": con_uuid,
                        "time": time.time(),
                        "host": os.getenv("host", ""),
                        "steps": {"keymatch": "", "webauthn": "", "keypair": "", "otp": ""},
                    }
                ]

    # Determine mutable target inside loaded data
    if isinstance(initial_data, dict):
        target = initial_data
    elif isinstance(initial_data, list) and len(initial_data) > 0 and isinstance(initial_data[0], dict):
        target = initial_data[0]
    else:
        raise ValueError("Invalid working file format")

    # Apply updates
    if status != "requested":
        target["status"] = status
        target["last_step_updated"] = step_name
        if time_of_last_completion is not None:
            target["time_of_last_completion"] = time_of_last_completion
        if "steps" in target and isinstance(target["steps"], dict):
            target_steps = target["steps"]
            # ensure keys exist
            if step_name not in target_steps:
                target_steps[step_name] = {}
            target_steps[step_name] = {
                "status": "complete",
                "time_of_last_completion": time_of_last_completion,
            }

    # Write back to all candidate paths atomically
    for path in set(candidates):
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=path.name, dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmpf:
                json.dump(initial_data, tmpf, indent=2, ensure_ascii=False)
                tmpf.flush()
                os.fsync(tmpf.fileno())
            os.replace(tmp_path, str(path))
        except Exception:
            # cleanup temp on failure
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            raise

    return True

if __name__ == "__main__":
    # Example usage with dummy values
    workingfile("example_sv_uuid", "example_svu_uuid", "example_con_uuid")
