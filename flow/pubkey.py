# python
# File: flow/pubkey.py
import os
import json

def _read_json(path):
    with open(path, "r") as f:
        return json.load(f)

def _write_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)

def update_service_pubkey(serviceuuid: str, new_pubk: str):
    """
    Update pubk for a service stored at storage/user/{serviceuuid}/{serviceuuid}.json
    """
    filepath = os.path.join("storage", "user", serviceuuid, f"{serviceuuid}.json")
    if not os.path.exists(filepath):
        return {"status": "error", "message": "service not found", "serviceuuid": serviceuuid}
    data = _read_json(filepath)
    data.setdefault("keychain", {})["pubk"] = new_pubk
    _write_json(filepath, data)
    return {"status": "success", "serviceuuid": serviceuuid, "pubk": new_pubk}

def update_service_user_pubkey(serviceuuid: str, svu_uuid: str, new_pubk: str):
    """
    Update pubk for a service user (svu) stored at storage/user/{serviceuuid}/{svu_uuid}.json
    """
    filepath = os.path.join("storage", "user", serviceuuid, f"{svu_uuid}.json")
    if not os.path.exists(filepath):
        return {"status": "error", "message": "service user not found", "svu_uuid": svu_uuid}
    data = _read_json(filepath)
    data.setdefault("keychain", {})["pubk"] = new_pubk
    _write_json(filepath, data)
    return {"status": "success", "svu_uuid": svu_uuid, "pubk": new_pubk}
