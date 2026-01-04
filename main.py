"""
Rewritten main.py: single FastAPI app, request models for OpenAPI, and all existing endpoints
preserved and annotated so /docs shows complete schemas.
"""
from fastapi import FastAPI, HTTPException, Path as FastAPIPath
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import os
import json
from pathlib import Path

from flow.signup import new_user, new_user_service, new_user_service_user
from flow.adddevice import enroll_device
from flow.pubkey import update_service_pubkey, update_service_user_pubkey
from internal.recovery import checksum_checker
from flow.ssh import step1_content, working_file
from config import BASE_SAVE_DIR

app = FastAPI(
    title="SuperSL2 API",
    description="API for user/service creation, device enrollment and pubkey management.",
    version="0.1.0",
    openapi_url="/openapi.json",
    docs_url="/docs",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



# --- Request models (show up in OpenAPI and docs) ---
class PubKeyRequest(BaseModel):
    pubk: str


class AddDeviceRequest(BaseModel):
    k: Optional[str] = None
    ip: Optional[str] = None


# --- Endpoints ---
@app.get("/", tags=["root"])
async def root():
    return {"message": "Hello World"}


@app.post("/serviceuser/new", tags=["signup"], summary="Create a new top-level user")
async def new_user_api(payload: PubKeyRequest):
    return new_user(payload.pubk)


@app.post("/service/{serviceuuid}/service/new", tags=["signup"], summary="Create a new service (serviceUUID parameter kept for routing)")
async def create_service(serviceuuid: str = FastAPIPath(..., description="service UUID (not used for generation)"), payload: PubKeyRequest = None):
    pubk = payload.pubk if payload else None
    return new_user_service(serviceuuid, pubk)


@app.post("/service/{serviceuuid}/user/new", tags=["signup"], summary="Create a new service user (svu)")
async def new_user_service_user_api(serviceuuid: str = FastAPIPath(..., description="Parent service UUID"), payload: PubKeyRequest = None):
    pubk = payload.pubk if payload else None
    return new_user_service_user(serviceuuid, pubk)


@app.post("/user/adddevice/{u_uuid}", tags=["device"], summary="Enroll a new device for user")
async def add_device_api(u_uuid: str, payload: AddDeviceRequest):
    result = enroll_device(u_uuid, payload.k, payload.ip)
    return result


@app.get("/user/checksum/{userUUID}/{entered_words}", tags=["recovery"], summary="Check passphrase checksum")
async def checkcksum(userUUID: str, entered_words: str):
    return checksum_checker(userUUID, entered_words)


@app.post("/user/create", tags=["signup"], summary="Create a user with provided public key")
async def create_user_api(payload: PubKeyRequest):
    if not payload.pubk:
        raise HTTPException(status_code=400, detail="Missing public key (pubk)")
    return new_user(payload.pubk)


@app.post("/service/{serviceuuid}/pubkey", tags=["pubkey"], summary="Update a service's public key")
async def set_service_pubkey(serviceuuid: str, payload: PubKeyRequest):
    if not payload.pubk:
        raise HTTPException(status_code=400, detail="Missing pubk")
    return update_service_pubkey(serviceuuid, payload.pubk)


@app.post("/service/{serviceuuid}/user/{svu_uuid}/pubkey", tags=["pubkey"], summary="Update a service-user (svu) pubkey")
async def set_service_user_pubkey(
    serviceuuid: str,
    svu_uuid: str,
    payload: PubKeyRequest,
):
    if not payload.pubk:
        raise HTTPException(status_code=400, detail="Missing pubk")
    return update_service_user_pubkey(serviceuuid, svu_uuid, payload.pubk)


@app.get("/service/{sv_uuid}/user/find/{svu_uuid}")
async def findSVU(sv_uuid: str, svu_uuid: str):
    filepath = f"{sv_uuid}/{svu_uuid}.json"
    if not os.path.exists(filepath):
        return {"error": "User not found"}
    with open(filepath, "r") as f:
        data = json.load(f)

    data.update({"sv_uuid": sv_uuid, "svu_uuid": svu_uuid, "exists": True})
    return data


@app.get("/service/{sv_uuid}/user/{svu_uuid}/{con_uuid}/step/1")
async def svu_step1(sv_uuid: str, svu_uuid: str, con_uuid: str, pubkey: Optional[str] = None):
    # build working file data (uses flow.ssh.working_file)
    workingfile = working_file(
        con_uuid=con_uuid,
        svu_uuid=svu_uuid,
        sv_uuid=sv_uuid,
        pubkey=pubkey,
    )

    # write to storage/session/<con_uuid>.json, creating directories if needed
    con_uuid_path = BASE_SAVE_DIR / "session" / f"{con_uuid}.json"
    con_uuid_path.parent.mkdir(parents=True, exist_ok=True)
    con_uuid_path.write_text(json.dumps(workingfile, indent=2, ensure_ascii=False), encoding="utf-8")




    return step1_content

