from fastapi import FastAPI, Request
from flow.signup import new_user
from flow.adddevice import add_device

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