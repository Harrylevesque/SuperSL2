import json, uuid, time
from pathlib import Path

from config import BASE_SAVE_DIR

def enroll_device(userUUID, privkeyD, ip):
    directory = BASE_SAVE_DIR / "user"
    filepath = directory / f"{userUUID}.json"
    if not filepath.exists():
        return {"error": "User not found"}

    with open(filepath, "r") as f:
        userfiledata = json.load(f)

    deviceUUID = f"d--{uuid.uuid4()}"
    device_entry = {
        "deviceUUID": deviceUUID,
        "deviceName": f"Device-{uuid.uuid4().hex[:6]}",
        "addedAt": int(time.time()),
        "trusted": False
    }
    if not userfiledata.get("allowedDevices"):
        userfiledata["allowedDevices"] = []
    if len(userfiledata["allowedDevices"]) == 0:
        device_entry["trusted"] = True
    userfiledata["allowedDevices"].append(device_entry)

    privD_entry = {
        "privkeyD": privkeyD,
        "ip": ip,
        "addedAt": int(time.time()),
        "connecteddeviceUUID": deviceUUID,
    }
    if "keychain" not in userfiledata:
        userfiledata["keychain"] = {}
    if "privD" not in userfiledata["keychain"]:
        userfiledata["keychain"]["privD"] = []
    userfiledata["keychain"]["privD"].append(privD_entry)

    session_entry = {
        "sessionUUID": f"s--{uuid.uuid4()}",
        "createdAt": int(time.time()),
        "lastActive": int(time.time()),
        "ipAddress": ip
    }
    if "sessions" not in userfiledata:
        userfiledata["sessions"] = []
    userfiledata["sessions"].append(session_entry)

    with open(filepath, "w") as f:
        json.dump(userfiledata, f, indent=4)

    return {"status": "success", "deviceUUID": deviceUUID, "deviceName": device_entry["deviceName"]}