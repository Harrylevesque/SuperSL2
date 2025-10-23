from fastapi import FastAPI, Request
from flow.signup import new_user, new_user_service, new_user_service_user
from flow.adddevice import enroll_device
from internal.recovery import checksum_checker

app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/serviceuser/new")
async def new_user_api():
    return new_user()


@app.get("/service/{serviceuuid}/service/new")
async def create_service(serviceuuid: str, request: Request):
    return new_user_service(serviceuuid)


@app.get("/service/{serviceuuid}/user/new")
async def new_user_service_user_api(serviceuuid: str, request: Request):
    return new_user_service_user(serviceuuid)


#
@app.post("/user/adddevice/{u_uuid}")
async def add_device_api(u_uuid: str, request: Request):
    data = await request.json()
    k = data.get("k")
    ip = data.get("ip")
    result = enroll_device(u_uuid, k, ip)
    return result

@app.get("/user/checksum/{userUUID}/{entered_words}")
async def checkcksum(userUUID, entered_words):
    return checksum_checker(userUUID, entered_words)

@app.post("/user/create")
async def create_user_api(request: Request):
    data = await request.json()
    pubk = data.get("pubk")
    if not pubk:
        return {"status": "error", "message": "Missing public key (pubk)"}
    result = new_user(pubk)
    return result
