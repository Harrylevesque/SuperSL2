import uuid, time, os, json

def new_service(useruuid, service_name, service_description):
    directory = f"storage/user/{useruuid}/services"
    os.makedirs(directory, exist_ok=True)
    serviceUUID = f"svc--{uuid.uuid4()}"
    filepath = os.path.join(directory, f"{serviceUUID}.json")

    if os.path.exists(filepath):
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
