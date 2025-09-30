import uuid, time, os, json, random, secrets, socket, requests

from internal.recovery import generate_passphrase, checksum_passphrase, select_words, create_passphrase
from flow.servicemanagement.newservice import new_service



def new_user():
    userUUID = str(f"u--{uuid.uuid4()}")
    directory = "storage/user"
    filename = f"{userUUID}.json"
    filepath = os.path.join(directory, filename)

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
            "pubk": str(f"pk--{secrets.token_urlsafe(1024)}"),
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

    os.makedirs(directory, exist_ok=True)
    with open(filepath, "w") as json_file:
        json.dump(userfiledata, json_file, indent=4)

    return {
        "status": "success",
        "userUUID": userUUID,
        "pubk": userfiledata["keychain"]["pubk"],
        "passphrase_words": words,
        #"passphrase_checksum": checksum
    }


def new_user_with_service(username, service_name, service_description):
    useruuid = f"u--{uuid.uuid4()}"
    user_dir = f"storage/{useruuid}/service"
    os.makedirs(user_dir, exist_ok=True)

    # Normal user data
    user_data = {
        "userUUID": useruuid,
        "username": username,
        "createdAt": int(time.time()),
        "status": "active"
    }
    user_file = os.path.join(user_dir, f"{useruuid}.json")
    with open(user_file, "w") as f:
        json.dump(user_data, f, indent=4)

    # Create service
    service_result = new_service(useruuid, service_name, service_description)

    return {
        "user": user_data,
        "service": service_result
    }