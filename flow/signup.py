import uuid, time, os, json, random, secrets, socket, requests


def new_user():
    userUUID = str(f"u--{uuid.uuid4()}")
    directory = "../storage/user"
    filename = f"{userUUID}.json"
    filepath = os.path.join(directory, filename)


    def get_local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't need to be reachable
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

    kchindata = {
        "location": str(f"kchin--{uuid.uuid4()}"),
        "createdAt": int(time.time()),
        "pubk": str(f"pk--{secrets.token_urlsafe(1024)}"),
        "privD": [
            {
                "privkeyD": "sample+changeme", ############################################
                "ip": f"{get_public_ip()}",
                "addedAt": int(time.time()),
                "connecteddeviceUUID": None,
            }
        ]
    }

    userfiledata = {
        "userUUID": userUUID,
        "createdAt": int(time.time()),
        "keychain": kchindata,


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
    #create the file and put data in it defined above
    os.makedirs(directory, exist_ok=True)
    with open(filepath, "w") as json_file:
        json.dump(userfiledata, json_file, indent=4)

    return {"status": "success", "userUUID": userUUID, "pubk": kchindata["pubk"]}


if __name__ == "__main__":
    result = new_user()
    print(result)