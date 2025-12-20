import json
import os
import copy
from typing import Optional, Dict, Any


step1_content: Dict[str, Any] = {
    "context": {
        "con_uuid": "",
        "svu_uuid": "",
        "sv_uuid": "",
        "ip": "",
        "pubk": "",
        "keypair_number": 0,
        "unixTime": ""
    },
    "steps": {
        "connection_check": {"name": "connection check", "startpoint": "user", "endpoint": "service"},
        "ssh_prep": {"name": "ssh prep", "startpoint": "service", "endpoint": "user"},
        "ssh_connection": {"name": "ssh connection", "startpoint": "user", "endpoint": "service"},
        "keypair_request": {"name": "keypair request", "startpoint": "user", "endpoint": "service"},
        "return_pubkey": {"name": "return pubkey", "startpoint": "service", "endpoint": "user"},
        "request_totp_info": {"name": "request totp info", "startpoint": "user", "endpoint": "dispatch"},
        "return_totp_info": {"name": "return totp info", "startpoint": "dispatch", "endpoint": "user"},
        "user_return_totp": {"name": "user return totp", "startpoint": "user", "endpoint": "dispatch", "answer": ""},
        "service_return_totp": {"name": "service return totp", "startpoint": "service", "endpoint": "dispatch", "answer": ""}
    }
}


def create_template(
    con_uuid: str = "",
    svu_uuid: str = "",
    sv_uuid: str = "",
    ip: str = "",
    pubk: str = "",
    keypair_number: int = 0,
    unixTime: str = "",
) -> Dict[str, Any]:

    tpl = copy.deepcopy(step1_content)
    tpl["context"]["con_uuid"] = con_uuid
    tpl["context"]["svu_uuid"] = svu_uuid
    tpl["context"]["sv_uuid"] = sv_uuid
    tpl["context"]["ip"] = ip
    tpl["context"]["pubk"] = pubk
    tpl["context"]["keypair_number"] = keypair_number
    tpl["context"]["unixTime"] = unixTime
    if pubk:
        if "pubk" in tpl["steps"].get("return_pubkey", {}):
            tpl["steps"]["return_pubkey"]["pubk"] = pubk
    return tpl


def write_json(path: str, data: Dict[str, Any]) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def working_file(
    con_uuid: str,
    svu_uuid: str,
    sv_uuid: str,
    pubkey: Optional[str] = "",
    ip: Optional[str] = "",
    keypair_number: int = 0,
    unixTime: Optional[str] = "",
    out_dir: str = "../storage/session",
) -> Dict[str, Any]:
    """Create the JSON template populated with provided context and write to disk.

    Returns the template dict.
    """
    template = create_template(
        con_uuid=con_uuid,
        svu_uuid=svu_uuid,
        sv_uuid=sv_uuid,
        ip=ip or "",
        pubk=pubkey or "",
        keypair_number=keypair_number,
        unixTime=unixTime or "",
    )

    filepath = os.path.join(out_dir, f"{con_uuid}.json")
    write_json(filepath, template)
    return template






if __name__ == "__main__":
    # Simple CLI for manual testing
    sv_uuid = input("Enter service UUID: ")
    svu_uuid = input("Enter service-user UUID: ")
    con_uuid = input("Enter connection UUID: ")
    pubkey = input("Enter public key: ")
    tpl = working_file(con_uuid=con_uuid, svu_uuid=svu_uuid, sv_uuid=sv_uuid, pubkey=pubkey)
    print(f"Wrote template for connection {con_uuid} to ../storage/session/{con_uuid}.json")
    print(json.dumps(tpl, indent=2))
