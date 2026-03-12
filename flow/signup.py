import uuid, time, os, json, random, secrets, socket, requests

from internal.recovery import checksum_passphrase, select_words, create_passphrase

from pathlib import Path
from config import BASE_SAVE_DIR



def new_user(pubk, keypairs=None):
    userUUID = str(f"u--{uuid.uuid4()}")
    directory = BASE_SAVE_DIR / "user"
    filename = f"{userUUID}.json"
    filepath = directory / filename

    num_words = 24
    words = select_words("internal/wordlist.txt", num_words)
    passphrase = create_passphrase(words)
    checksum = checksum_passphrase(passphrase)


    def get_local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def get_public_ip():
        try:
            return requests.get("https://api.ipify.org").text
        except Exception:
            return '0.0.0.0'

    userfiledata = {
        "userUUID": userUUID,
        "createdAt": int(time.time()),
        "keychain": {
            "location": str(f"kchin--{uuid.uuid4()}"),
            "createdAt": int(time.time()),
            "pubk": pubk,
            "keypairs": keypairs if keypairs else {},
            #"passphrase": passphrase,
            "passphrase_checksum": checksum,
            "privD": [
                {
                    "privkeyD": "sample+changeme",
                    "ip": f"{get_public_ip()}",
                    "addedAt": int(time.time()),
                    "connecteddeviceUUID": None,
                }
            ]
        },
        "allowedDevices": [
            {
                "deviceUUID": str(f"d--{uuid.uuid4()}"),
                "deviceName": f"Device-{random.randint(1000, 9999)}",
                "addedAt": int(time.time()),
            }
        ],
        "sessions": [
            {
                "sessionUUID": str(f"s--{uuid.uuid4()}"),
                "createdAt": int(time.time()),
                "lastActive": int(time.time()),
                "ipAddress": f"{get_public_ip()}:{get_local_ip()}"
            }
        ],
        "allowedIPs": [
            {
                "ipAddress": f"{get_public_ip()}",
                "addedAt": int(time.time()),
            }
        ],
    }

    directory.mkdir(parents=True, exist_ok=True)


    with open(filepath, "w") as json_file:
        def make_json_serializable(obj):
            if isinstance(obj, set):
                return list(obj)
            if isinstance(obj, dict):
                return {k: make_json_serializable(v) for k, v in obj.items()}
            if isinstance(obj, (list, tuple)):
                return [make_json_serializable(v) for v in obj]
            return obj

        json.dump(make_json_serializable(userfiledata), json_file, indent=4)

    return {
        "status": "success",
        "userUUID": userUUID,
        "pubk": userfiledata["keychain"]["pubk"],
        "passphrase_words": words,
        #"passphrase_checksum": checksum
    }




def new_user_service(serviceuuid, pubk=None, keypairs=None):
    # Use provided serviceuuid if it's valid, otherwise generate a new one
    if serviceuuid and isinstance(serviceuuid, str) and serviceuuid.startswith("sv--"):
        # Validate it's a proper UUID format after the prefix
        try:
            uuid.UUID(serviceuuid[5:])
            # Valid custom UUID provided, use it
        except (ValueError, IndexError):
            # Invalid format, generate new one
            serviceuuid = str(f"sv--{uuid.uuid4()}")
    else:
        # Generate new UUID if not provided or invalid
        serviceuuid = str(f"sv--{uuid.uuid4()}")
    directory = BASE_SAVE_DIR / "user" / serviceuuid
    filename = f"{serviceuuid}.json"
    filepath = directory / filename
    num_words = 24
    words = select_words("internal/wordlist.txt", num_words)
    passphrase = create_passphrase(words)
    checksum = checksum_passphrase(passphrase)




    def get_local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def get_public_ip():
        localip = requests.get("https://api.ipify.org").text
        try:
            return localip
        except Exception:
            return '0.0.0.0'

    # use provided pubk if given, otherwise generate one
    pubk_value = pubk if pubk else str(f"pk--{secrets.token_urlsafe(1024)}")

    userfiledata = {
        "serviceuuid": serviceuuid,
        "createdAt": int(time.time()),
        "keychain": {
            "location": str(f"kchin--{uuid.uuid4()}"),
            "createdAt": int(time.time()),
            "pubk": pubk_value,
            "keypairs": keypairs if keypairs else {},
            #"passphrase": passphrase,
            "passphrase_checksum": checksum,
            "privD": [
                {
                    "privkeyD": "sample+changeme",
                    "ip": f"{get_public_ip()}",
                    "addedAt": int(time.time()),
                    "connecteddeviceUUID": None,
                }
            ]
        },
        "allowedDevices": [
            {
                "deviceUUID": str(f"d--{uuid.uuid4()}"),
                "deviceName": f"Device-{random.randint(1000, 9999)}",
                "addedAt": int(time.time()),
            }
        ],
        "sessions": [
            {
                "sessionUUID": str(f"s--{uuid.uuid4()}"),
                "createdAt": int(time.time()),
                "lastActive": int(time.time()),
                "ipAddress": f"{get_public_ip()}:{get_local_ip()}"
            }
        ],
        "allowedIPs": [
            {
                "ipAddress": f"{get_public_ip()}",
                "addedAt": int(time.time()),
            }
        ],
    }

    directory.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w") as json_file:
        json.dump(userfiledata, json_file, indent=4)

    return {
        "status": "success",
        "serviceuuid": serviceuuid,
        "pubk": userfiledata["keychain"]["pubk"],
        "passphrase_words": words,
        #"passphrase_checksum": checksum
    }



def new_user_service_user(serviceuuid, pubk=None, KPek=None, client_pubk=None, keypairs=None, otp_pubK=None):
    service_user_user = str(f"svu--{uuid.uuid4()}")
    directory = BASE_SAVE_DIR / "user" / serviceuuid
    filename = f"{service_user_user}.json"
    filepath = directory / filename

    num_words = 24
    words = select_words("internal/wordlist.txt", num_words)
    passphrase = create_passphrase(words)
    checksum = checksum_passphrase(passphrase)

    def get_local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def get_public_ip():
        try:
            return requests.get("https://api.ipify.org").text
        except Exception:
            return '0.0.0.0'

    pubk_value = pubk if pubk else str(f"pk--{secrets.token_urlsafe(1024)}")

    userfiledata = {
        "serviceuuid": serviceuuid,
        "svuUUI": service_user_user,
        "createdAt": int(time.time()),
        "keychain": {
            "location": str(f"kchin--{uuid.uuid4()}"),
            "createdAt": int(time.time()),
            "pubk": pubk_value,
            "KPek": KPek,
            "client_pubk": client_pubk,
            "keypairs": keypairs if keypairs else {"error"},
            #"passphrase": passphrase,
            #"passphrase_checksum": checksum,
            "otp_pubK": otp_pubK,
            "otp_pubk": otp_pubK,
            "privD": [
                {
                    "privkeyD": "sample+changeme",
                    "ip": f"{get_public_ip()}",
                    "addedAt": int(time.time()),
                    "connecteddeviceUUID": None,
                }
            ]
        },
        "allowedDevices": [
            {
                "deviceUUID": str(f"d--{uuid.uuid4()}"),
                "deviceName": f"Device-{random.randint(1000, 9999)}",
                "addedAt": int(time.time()),
            }
        ],
        "sessions": [
            {
                "sessionUUID": str(f"s--{uuid.uuid4()}"),
                "createdAt": int(time.time()),
                "lastActive": int(time.time()),
                "ipAddress": f"{get_public_ip()}:{get_local_ip()}"
            }
        ],
        "allowedIPs": [
            {
                "ipAddress": f"{get_public_ip()}",
                "addedAt": int(time.time()),
            }
        ],
    }

    directory.mkdir(parents=True, exist_ok=True)
    def make_json_serializable(obj):
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, dict):
            return {k: make_json_serializable(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [make_json_serializable(v) for v in obj]
        return obj
    with open(filepath, "w") as json_file:
        json.dump(make_json_serializable(userfiledata), json_file, indent=4)

    return {
        "status": "success",
        "serviceuuid": serviceuuid,
        "svuUUID": service_user_user,
        "pubk": userfiledata["keychain"]["pubk"],
        "KPek": KPek,
        "client_pubk": client_pubk,
        "otp_pubK": otp_pubK,
        #"passphrase_words": words,
        #"passphrase_checksum": checksum
    }
