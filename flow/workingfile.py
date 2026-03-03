import time
import json
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
    Update the status and time_of_last_completion for a given step in the session working file.
    Args:
        con_uuid: Connection UUID
        status: New status string
        step_name: Step name (e.g., 'keymatch', 'webauthn', 'keypair', 'otp')
        time_of_last_completion: Optional timestamp
    """
    import os
    from pathlib import Path
    import json

    base_dir = os.getenv("BASE_SAVE_DIR", "./storage")
    file_path = Path(base_dir) / "session" / f"{con_uuid}.json"
    if not file_path.exists():
        raise FileNotFoundError(f"Working file not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Handle both list and dict formats
    if isinstance(data, dict):
        target = data
    elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
        target = data[0]
    else:
        raise ValueError("Invalid working file format")

    # Only update if not initialised connection (status != 'requested')
    if status != "requested":
        target["status"] = status
        target["last_step_updated"] = step_name
        if time_of_last_completion is not None:
            target["time_of_last_completion"] = time_of_last_completion
        if "steps" in target and isinstance(target["steps"], dict):
            target["steps"][step_name] = {
                "status": "complete",
                "time_of_last_completion": time_of_last_completion,
            }

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return True

if __name__ == "__main__":
    # Example usage with dummy values
    workingfile("example_sv_uuid", "example_svu_uuid", "example_con_uuid")
