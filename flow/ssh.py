# python
from pathlib import Path
import json
import copy
from typing import Dict, Any, Optional

from config import BASE_SAVE_DIR

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
        "service_return_totp": {"name": "service return totp", "startpoint": "service", "endpoint": "dispatch",
                                "answer": ""}
    }
}


def create_template(
        con_uuid: str = "",
        svu_uuid: str = "",
        sv_uuid: str = "",
        ip: str = "",
        pubk: Optional[str] = None,
        keypair_number: int = 0,
        unixTime: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Return a fresh template copied from step1_content and populate context.
    Only set the 'pubk' field inside the 'return_pubkey' step when a pubk is provided.
    """
    tpl = copy.deepcopy(step1_content)
    tpl["context"].update({
        "con_uuid": con_uuid,
        "svu_uuid": svu_uuid,
        "sv_uuid": sv_uuid,
        "ip": ip or "",
        "pubk": pubk or "",
        "keypair_number": keypair_number,
        "unixTime": unixTime or ""
    })
    if pubk:
        # assign directly to the existing dict so it persists in the template
        tpl["steps"]["return_pubkey"]["pubk"] = pubk
    return tpl


def write_json(path: Path, data: Dict[str, Any]):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def working_file(
        con_uuid: str,
        svu_uuid: str,
        sv_uuid: str,
        pubkey: Optional[str] = None,
        ip: Optional[str] = None,
        keypair_number: int = 0,
        unixTime: Optional[str] = None,
) -> Dict[str, Any]:
    template = create_template(
        con_uuid=con_uuid,
        svu_uuid=svu_uuid,
        sv_uuid=sv_uuid,
        ip=ip or "",
        pubk=pubkey,
        keypair_number=keypair_number,
        unixTime=unixTime,
    )

    save_dir = BASE_SAVE_DIR / "session"
    filepath = save_dir / f"{con_uuid}.json"

    save_dir.mkdir(parents=True, exist_ok=True)
    write_json(filepath, template)

    return {"path": str(filepath.resolve()), "template": template}



def create_ssh_user():

    pass



if __name__ == "__main__":
    sv_uuid = input("Enter service UUID: ")
    svu_uuid = input("Enter service-user UUID: ")
    con_uuid = input("Enter connection UUID: ")
    pubkey = input("Enter public key: ")
    tpl = working_file(con_uuid=con_uuid, svu_uuid=svu_uuid, sv_uuid=sv_uuid, pubkey=pubkey)
    print(f"Wrote template for connection {con_uuid} to ../storage/session/{con_uuid}.json")
    print(json.dumps(tpl, indent=2))