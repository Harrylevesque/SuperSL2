# python
# File: flow/pubkey.py
import json
from pathlib import Path

from config import BASE_SAVE_DIR

def _read_json(path):
    with open(path, "r") as f:
        return json.load(f)

def _write_json(path, data):
    # ensure parent exists
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        json.dump(data, f, indent=4)

def update_service_pubkey(serviceuuid: str, new_pubk: str):
    """
    Update pubk for a service stored at storage/user/{serviceuuid}/{serviceuuid}.json
    """
    filepath = BASE_SAVE_DIR / "user" / serviceuuid / f"{serviceuuid}.json"
    if not filepath.exists():
        return {"status": "error", "message": "service not found", "serviceuuid": serviceuuid}
    data = _read_json(filepath)
    data.setdefault("keychain", {})["pubk"] = new_pubk
    _write_json(filepath, data)
    return {"status": "success", "serviceuuid": serviceuuid, "pubk": new_pubk}

def update_service_user_pubkey(serviceuuid: str, svu_uuid: str, new_pubk: str):
    """
    Update pubk for a service user (svu) stored at storage/user/{serviceuuid}/{svu_uuid}.json
    """
    filepath = BASE_SAVE_DIR / "user" / serviceuuid / f"{svu_uuid}.json"
    if not filepath.exists():
        return {"status": "error", "message": "service user not found", "svu_uuid": svu_uuid}
    data = _read_json(filepath)
    data.setdefault("keychain", {})["pubk"] = new_pubk
    _write_json(filepath, data)
    return {"status": "success", "svu_uuid": svu_uuid, "pubk": new_pubk}
