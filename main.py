from fastapi import FastAPI, Request
from flow.signup import new_user
from flow.adddevice import enroll_device
from internal.recovery import checksum_checker

app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/user/new")
async def new_user_api():
    return new_user()


@app.post("/user/adddevice/{u_uuid}")
async def add_device_api(u_uuid: str, request: Request):
    data = await request.json()
    k = data.get("k")
    ip = data.get("ip")
    result = add_device(u_uuid, k, ip)
    return result

@app.get("/user/checksum/{userUUID}/{entered_words}")
async def checkcksum(userUUID, entered_words):
    return checksum_checker(userUUID, entered_words)

@app.post("/user/{useruuid}/service/new")
async def create_service(useruuid: str, request: Request):
    data = await request.json()
    service_name = data.get("service_name")
    service_description = data.get("service_description")
    from flow.servicemanagement.newservice import new_service
    return new_service(useruuid, service_name, service_description)



@app.post("/user/new_with_service")
async def new_user_with_service_api(request: Request):
    data = await request.json()
    username = data.get("username")
    service_name = data.get("service_name")
    service_description = data.get("service_description")
    return new_user_with_service(username, service_name, service_description)


@app.post("/service/{serviceUUID}/user/new")
async def create_service_user(serviceUUID: str, request: Request):
    from flow.signup import new_user
    import os, json

    # Generate user data using the same logic as /user/new
    user_data = new_user()

    # Save user file in the service's users directory
    useruuid = user_data["userUUID"]
    users_dir = f"storage/user/{serviceUUID}/users"
    os.makedirs(users_dir, exist_ok=True)
    user_file = os.path.join(users_dir, f"{useruuid}.json")
    with open(user_file, "w") as f:
        json.dump(user_data, f, indent=4)
    return {"status": "success", "userUUID": useruuid}