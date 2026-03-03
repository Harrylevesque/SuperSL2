import uuid, time, json

from config import BASE_SAVE_DIR

def new_service(useruuid, service_name, service_description):
    directory = BASE_SAVE_DIR / "user" / useruuid / "services"
    directory.mkdir(parents=True, exist_ok=True)
    serviceUUID = f"svc--{uuid.uuid4()}"
    filepath = directory / f"{serviceUUID}.json"

    if filepath.exists():
        return {"error": "Service already exists"}

    service_data = {
        "serviceUUID": serviceUUID,
        "serviceName": service_name,
        "serviceDescription": service_description,
        "createdAt": int(time.time()),
        "status": "active"
    }

    with open(filepath, "w") as json_file:
        json.dump(service_data, json_file, indent=4)

    return {
        "status": "success",
        "serviceUUID": serviceUUID,
        "serviceName": service_name
    }
