"""
Rewritten main.py: single FastAPI app, request models for OpenAPI, and all existing endpoints
preserved and annotated so /docs shows complete schemas.
"""
from fastapi import FastAPI, HTTPException, Path as FastAPIPath, Body, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi import Request

from pydantic import BaseModel, Field
from typing import Optional
import os
import json
from pathlib import Path
import logging
import dotenv
import base64
from nacl.signing import VerifyKey  # optional for validation
import time
from uuid import UUID
import asyncio

from flow.signup import new_user, new_user_service, new_user_service_user
from flow.adddevice import enroll_device
from flow.pubkey import update_service_pubkey, update_service_user_pubkey
from internal.recovery import checksum_checker
from flow.workingfile import workingfile, update_workingfile_status
from config import BASE_SAVE_DIR
from flow.keymatch import get_pubk
from flow.keypair import generate_challenge as generate_keypair_challenge, verify_client_signature
from flow.humans import humans as humanInfo
from flow.otp import (
    generate_challenge as generate_otp_challenge,
    verify_client_signature as verify_otp_signature,
)
from flow.webauthn_flow import (
    register_start, register_finish, auth_start, auth_finish, resolve_webauthn_config
)

# Load environment variables from .env file
dotenv.load_dotenv()

app = FastAPI(
    title="SuperSL2 API",
    description="API for user/service creation, device enrollment and pubkey management.",
    version="0.1.0",
    openapi_url="/openapi.json",
    docs_url="/docs",
)

# set up basic logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Add a rotating file handler so logs persist across restarts and are easy to inspect
try:
    from logging.handlers import RotatingFileHandler
    log_dir = BASE_SAVE_DIR / "log"
    log_dir.mkdir(parents=True, exist_ok=True)
    logfile = log_dir / "webauthn.log"
    file_handler = RotatingFileHandler(str(logfile), maxBytes=5 * 1024 * 1024, backupCount=3)
    file_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    file_handler.setFormatter(formatter)
    logging.getLogger().addHandler(file_handler)
    logger.debug("File logging enabled at %s", logfile)
except Exception as exc:
    logger.warning("Could not set up file logging: %s", exc)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



# --- Request models (show up in OpenAPI and docs) ---
class PubKeyRequest(BaseModel):
    pubk: Optional[str] = None
    KPek: Optional[str] = None
    KPdk: Optional[str] = None
    client_pubk: Optional[str] = None  # Now optional for generic use


class ServiceUserRequest(BaseModel):
    client_pubk: str = Field(..., description="Base64-encoded client public signing key")
    otp_pubK: str = Field(None, description="OTP public key to store and return to the client")


class AddDeviceRequest(BaseModel):
    k: Optional[str] = None
    ip: Optional[str] = None


class Username(BaseModel):
    username: str

class CredentialPayload(BaseModel):
    username: str
    credential: dict


class Step2Payload(BaseModel):
    pubkey: str

class Step3_5Payload(BaseModel):
    signature: str
    challenge: str

class Step4_5Payload(BaseModel):
    payload_json: str
    signature: str


# Helper to resolve mode strings
def _is_auth_mode(mode: Optional[str]) -> bool:
    return (mode or "").strip().lower() in {"authentication", "auth", "authenticate", "login"}


# Load sv/svu from workingfiles or session using con-uuid
def _load_sv_pair_from_file(file_path: Path) -> tuple[str, str]:
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Session file not found")

    session_data = json.loads(file_path.read_text(encoding="utf-8"))
    if isinstance(session_data, dict):
        sv_uuid = session_data.get("sv_uuid")
        svu_uuid = session_data.get("svu_uuid")
    elif isinstance(session_data, list) and session_data and isinstance(session_data[0], dict):
        sv_uuid = session_data[0].get("sv_uuid")
        svu_uuid = session_data[0].get("svu_uuid")
    else:
        raise HTTPException(status_code=400, detail="Invalid session file format")

    if not sv_uuid or not svu_uuid:
        raise HTTPException(status_code=400, detail="sv_uuid or svu_uuid missing in session file")

    return sv_uuid, svu_uuid


def _validate_con_uuid(con_uuid: str) -> str:
    if not con_uuid:
        raise HTTPException(status_code=400, detail="con_uuid is required")
    if not con_uuid.startswith("con--"):
        raise HTTPException(status_code=400, detail="con_uuid must start with 'con--'")
    try:
        parsed = UUID(con_uuid[5:])
    except ValueError:
        raise HTTPException(status_code=400, detail="con_uuid must include a valid UUID")
    return f"con--{parsed}"


def _resolve_sv_pair_from_session(con_uuid: str) -> tuple[str, str]:
    normalized_con_uuid = _validate_con_uuid(con_uuid)
    working_path = BASE_SAVE_DIR / "workingfiles" / f"{normalized_con_uuid}.json"
    session_path = BASE_SAVE_DIR / "session" / f"{normalized_con_uuid}.json"

    if working_path.exists():
        return _load_sv_pair_from_file(working_path)
    if session_path.exists():
        return _load_sv_pair_from_file(session_path)

    raise HTTPException(status_code=404, detail="Session file not found")


def _resolve_auth_identifiers(
    mode: Optional[str],
    sv_uuid: Optional[str],
    svu_uuid: Optional[str],
    con_uuid: Optional[str],
) -> tuple[str, str]:
    if sv_uuid and svu_uuid:
        return sv_uuid, svu_uuid

    if _is_auth_mode(mode) and con_uuid:
        return _resolve_sv_pair_from_session(con_uuid)

    raise HTTPException(
        status_code=400,
        detail="Provide sv_uuid and svu_uuid, or use mode=authentication with con_uuid",
    )

# --- Endpoints ---


@app.post("/serviceuser/new", tags=["signup"], summary="Create a new top-level user")
async def new_user_api(payload: PubKeyRequest):
    return new_user(payload.pubk)


@app.post("/service/{serviceuuid}/service/new", tags=["signup"], summary="Create a new service (serviceUUID parameter kept for routing)")
async def create_service(serviceuuid: str = FastAPIPath(..., description="service UUID (not used for generation)"), payload: PubKeyRequest = None):
    pubk = payload.pubk if payload else None
    return new_user_service(serviceuuid, pubk)


@app.post("/service/{serviceuuid}/user/new", tags=["signup"], summary="Create a new service user (svu)")
async def new_user_service_user_api(serviceuuid: str = FastAPIPath(..., description="Parent service UUID"), payload: ServiceUserRequest = Body(...)):
    client_pubk_b64 = payload.client_pubk
    otp_pubk = payload.otp_pubK

    # validate base64 for client_pubk
    try:
        client_pubk_bytes = base64.b64decode(client_pubk_b64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="client_pubk must be a valid base64 string")

    # optional: validate client_pubk is a valid public signing key
    try:
        VerifyKey(client_pubk_bytes)
    except Exception:
        raise HTTPException(status_code=400, detail="client_pubk is not a valid signing public key")


    humans = humanInfo()

    result = new_user_service_user(serviceuuid, client_pubk=client_pubk_b64, otp_pubK=otp_pubk)


    # echo keys back so the client saver can persist them
    if isinstance(result, dict):
        result["client_pubk"] = client_pubk_b64
        result["otp_pubK"] = otp_pubk
        return result

    return {"result": result, "client_pubk": client_pubk_b64, "otp_pubK": otp_pubk, "humans": humans}


@app.get("/humans")
async def get_humans():
    humans = humanInfo()
    return humans

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
    working_file = workingfile(sv_uuid, svu_uuid, con_uuid)

    # write to storage/session/<con_uuid>.json, creating directories if needed
    con_uuid_path = BASE_SAVE_DIR / "session" / f"{con_uuid}.json"
    con_uuid_path.parent.mkdir(parents=True, exist_ok=True)
    con_uuid_path.write_text(json.dumps(working_file, indent=2, ensure_ascii=False), encoding="utf-8")

    # also persist under workingfiles for con-uuid based lookups
    workingfile_path = BASE_SAVE_DIR / "workingfiles" / f"{con_uuid}.json"
    workingfile_path.parent.mkdir(parents=True, exist_ok=True)
    workingfile_path.write_text(json.dumps(working_file, indent=2, ensure_ascii=False), encoding="utf-8")

    # Update status and time_of_last_completion for step1
    update_workingfile_status(con_uuid, "requested", "initialise_connection", time.time())

    return working_file

@app.post("/login/{con_uuid}/step/2")
async def svu_step2(con_uuid: str, payload: dict = Body(...)):
    user_pubkey = payload.get("pubkey")

    with open(BASE_SAVE_DIR / "session" / f"{con_uuid}.json", "r") as f:
        data = json.load(f)
        if isinstance(data, dict):
            sv_uuid = data.get("sv_uuid")
            svu_uuid = data.get("svu_uuid")
        elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            sv_uuid = data[0].get("sv_uuid")
            svu_uuid = data[0].get("svu_uuid")
        else:
            raise ValueError("Invalid session file format")
    pubk_result = get_pubk(sv_uuid=sv_uuid, svu_uuid=svu_uuid)

    if pubk_result == user_pubkey:
        update_workingfile_status(con_uuid, "awaiting_webauthn", "keymatch", time.time())
        return {"status": "awaiting_webauthn", "time_of_last_completion": time.time(), "match": True, "time": time.time()}
    else:
        update_workingfile_status(con_uuid, "key_mismatch", "awaiting_webauthn", time.time())
        return {"success": False, "message": "key missmatch", "time": time.time()}



@app.get("/login/{con_uuid}/step/3")
async def svu_step3(con_uuid: str):
    challenge = generate_keypair_challenge()
    # Ensure challenge is a string for JSON serialization
    if isinstance(challenge, bytes):
        challenge = base64.b64encode(challenge).decode("utf-8")
    update_workingfile_status(con_uuid, "challenge_generated", "keypair", time.time())
    return {"challenge": challenge, "time": time.time(), "status": "challenge_generated", "time_of_last_completion": time.time()}



@app.post("/login/{con_uuid}/step/3.5")
async def svu_step3_5(con_uuid: str, payload: Step3_5Payload):
    signature = payload.signature
    challenge = payload.challenge
    logger.info(f"Step 3.5 called with con_uuid={con_uuid}, challenge={challenge}, signature={signature}")
    session_path = BASE_SAVE_DIR / "session" / f"{con_uuid}.json"
    if not session_path.exists():
        logger.error(f"Session file not found: {session_path}")
        raise HTTPException(status_code=404, detail="Session file not found")
    with open(session_path, "r") as f:
        session_data = json.load(f)
        if isinstance(session_data, dict):
            sv_uuid = session_data.get("sv_uuid")
            svu_uuid = session_data.get("svu_uuid")
        elif isinstance(session_data, list) and len(session_data) > 0 and isinstance(session_data[0], dict):
            sv_uuid = session_data[0].get("sv_uuid")
            svu_uuid = session_data[0].get("svu_uuid")
        else:
            logger.error(f"Invalid session file format: {session_data}")
            raise HTTPException(status_code=400, detail="Invalid session file format")
    logger.info(f"Extracted sv_uuid={sv_uuid}, svu_uuid={svu_uuid}")
    if not sv_uuid or not svu_uuid:
        logger.error(f"sv_uuid or svu_uuid missing in session file: sv_uuid={sv_uuid}, svu_uuid={svu_uuid}")
        raise HTTPException(status_code=400, detail="sv_uuid or svu_uuid missing in session file")
    user_path = BASE_SAVE_DIR / "user" / sv_uuid / f"{svu_uuid}.json"
    if not user_path.exists():
        logger.error(f"User file not found: {user_path}")
        raise HTTPException(status_code=404, detail="User file not found")
    with open(user_path, "r") as f:
        user_data = json.load(f)
        keychain = user_data.get("keychain", {})
        client_pubk = keychain.get("client_pubk")
        if not client_pubk:
            logger.error(f"client_pubk not found in user file: {user_path}")
            raise HTTPException(status_code=404, detail="client_pubk not found in user file")
    logger.info(f"Extracted client_pubk={client_pubk}")
    # Decode client_pubk from base64 and validate length
    try:
        client_pubk_bytes = base64.b64decode(client_pubk)
    except Exception as e:
        logger.error(f"client_pubk base64 decode error: {e}")
        raise HTTPException(status_code=400, detail=f"client_pubk must be valid base64: {e}")
    if len(client_pubk_bytes) != 32:
        logger.error(f"client_pubk decoded length is {len(client_pubk_bytes)}, expected 32 bytes")
        raise HTTPException(status_code=400, detail=f"client_pubk must decode to 32 bytes, got {len(client_pubk_bytes)} bytes")
    logger.info(f"Decoded client_pubk_bytes={client_pubk_bytes.hex()}")
    try:
        challenge_bytes = base64.b64decode(challenge)
        signature_bytes = base64.b64decode(signature)
        logger.info(f"Decoded challenge_bytes={challenge_bytes.hex()[:64]}... signature_bytes={signature_bytes.hex()[:64]}...")
    except Exception as e:
        logger.error(f"Base64 decode error: {e}")
        raise HTTPException(status_code=400, detail=f"Challenge or signature must be valid base64: {e}")
    try:
        keypair = verify_client_signature(client_pubk_bytes, challenge_bytes, signature_bytes)
        logger.info(f"Signature verification result: {keypair}")
    except Exception as e:
        logger.error(f"Signature verification error: {e}")
        raise HTTPException(status_code=400, detail=f"Signature verification failed: {e}")

    update_workingfile_status(con_uuid, "keypair_complete", "keypair", time.time())

    return {
            "signature_valid": keypair,

            "time_of_last_completion": time.time(),

            "debug": {
                "con_uuid": con_uuid,
                "sv_uuid": sv_uuid,
                "svu_uuid": svu_uuid,
                "client_pubk": client_pubk,
                "client_pubk_bytes_hex": client_pubk_bytes.hex(),
                "challenge_b64": challenge,
                "signature_b64": signature,
                "challenge_bytes_hex": challenge_bytes.hex(),
                "signature_bytes_hex": signature_bytes.hex()

                }
            }



@app.get("/login/{con_uuid}/step/4")
async def otp(con_uuid: str):
    payload_json = generate_otp_challenge()
    payload = json.loads(payload_json)
    # Keep both raw payload_json and flattened fields for client compatibility.
    return {
        "payload_json": payload_json,
        "challenge": payload.get("challenge"),
        "issued_at": payload.get("issued_at"),
        "challenge_id": payload.get("challenge_id"),
        "con_uuid": con_uuid,
    }



@app.post("/login/{con_uuid}/step/4.5")
async def otp_verify(con_uuid: str, payload: Step4_5Payload):
    payload_json = payload.payload_json
    signature_b64 = payload.signature

    session_path = BASE_SAVE_DIR / "session" / f"{con_uuid}.json"
    if not session_path.exists():
        raise HTTPException(status_code=404, detail="Session file not found")

    with open(session_path, "r") as f:
        session_data = json.load(f)

    if isinstance(session_data, dict):
        sv_uuid = session_data.get("sv_uuid")
        svu_uuid = session_data.get("svu_uuid")
    elif isinstance(session_data, list) and len(session_data) > 0 and isinstance(session_data[0], dict):
        sv_uuid = session_data[0].get("sv_uuid")
        svu_uuid = session_data[0].get("svu_uuid")
    else:
        raise HTTPException(status_code=400, detail="Invalid session file format")

    if not sv_uuid or not svu_uuid:
        raise HTTPException(status_code=400, detail="sv_uuid or svu_uuid missing in session file")

    user_path = BASE_SAVE_DIR / "user" / sv_uuid / f"{svu_uuid}.json"
    if not user_path.exists():
        raise HTTPException(status_code=404, detail="User file not found")

    with open(user_path, "r") as f2:
        user_data = json.load(f2)

    keychain = user_data.get("keychain", {})
    otp_pubk_b64 = keychain.get("otp_pubK")
    if not otp_pubk_b64:
        raise HTTPException(status_code=404, detail="otp_pubK not found in user file")

    try:
        otp_pubk = base64.b64decode(otp_pubk_b64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="otp_pubK must be a valid base64 string")

    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="signature must be a valid base64 string")

    ok = verify_otp_signature(otp_pubk, payload_json, signature)
    if ok == True:
        update_workingfile_status(con_uuid, "otp_complete", "otp", time.time())

    return {"signature_valid": ok, "time_of_last_completion": time.time(), "status": "complete" if ok else "faild"}




# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", include_in_schema=False)
async def index():
    index_path = Path("static") / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="index.html not found")
    return FileResponse(str(index_path), media_type="text/html")

@app.get("/webauth/register/start")
async def reg_start(request: Request, sv_uuid: str, svu_uuid: str):
    return await register_start(sv_uuid, svu_uuid, resolve_webauthn_config(request))

@app.post("/webauth/register/finish")
async def reg_finish(request: Request):
    body = await request.json()
    return await register_finish(body, resolve_webauthn_config(request))

@app.get("/webauth/auth/start")
async def a_start(
    request: Request,
    mode: Optional[str] = None,
    sv_uuid: Optional[str] = None,
    svu_uuid: Optional[str] = None,
    con_uuid: Optional[str] = None,
    con_uuid_query: Optional[str] = Query(default=None, alias="con-uuid"),
):
    logger.info("webauth.auth.start called: mode=%s sv_uuid=%s svu_uuid=%s con_uuid_query=%s", mode, sv_uuid, svu_uuid, con_uuid_query)
    con_uuid_param = con_uuid or con_uuid_query
    resolved_sv_uuid, resolved_svu_uuid = _resolve_auth_identifiers(
        mode,
        sv_uuid,
        svu_uuid,
        con_uuid_param,
    )
    options = await auth_start(resolved_sv_uuid, resolved_svu_uuid, resolve_webauthn_config(request))
    logger.debug("webauth.auth.start resolved sv/svu: %s %s; options keys=%s", resolved_sv_uuid, resolved_svu_uuid, list(options.keys()) if isinstance(options, dict) else None)

    # Include resolved identifiers and steps metadata for clients that log progress
    payload = {
        **options,
        "sv_uuid": resolved_sv_uuid,
        "svu_uuid": resolved_svu_uuid,
    }
    if con_uuid_param:
        payload["con_uuid"] = _validate_con_uuid(con_uuid_param)
    steps_obj = {"webauthn": options}
    payload["steps"] = steps_obj
    return payload

@app.post("/webauth/auth/finish")
async def a_finish(request: Request):
    try:
        body = await request.json()
    except Exception as exc:
        logger.exception("webauth.auth.finish: failed to parse JSON body: %s", exc)
        raise
    logger.info("webauth.auth.finish called; body keys=%s query_params=%s", list(body.keys()) if isinstance(body, dict) else type(body), dict(request.query_params))
    # Let flow.webauthn_flow.auth_finish perform verification and any workingfile updates.
    # First resolve identifiers so auth_finish receives normalized sv/svu when con-uuid mode is used.
    mode = body.get("mode") or request.query_params.get("mode")
    con_uuid = (
        body.get("con_uuid")
        or body.get("con-uuid")
        or request.query_params.get("con_uuid")
        or request.query_params.get("con-uuid")
    )
    resolved_sv_uuid, resolved_svu_uuid = _resolve_auth_identifiers(
        mode,
        body.get("sv_uuid"),
        body.get("svu_uuid"),
        con_uuid,
    )
    body["sv_uuid"] = resolved_sv_uuid
    body["svu_uuid"] = resolved_svu_uuid
    logger.debug("webauth.auth.finish resolved sv/svu: %s %s", resolved_sv_uuid, resolved_svu_uuid)
    result = await auth_finish(body, resolve_webauthn_config(request))
    logger.info("webauth.auth.finish result: %s", result)
    return result

# Ensure /config.json is always available at the root, regardless of subpath or mount
@app.get("/config.json", include_in_schema=False)
def get_config(request: Request):
    ctx = resolve_webauthn_config(request)
    return JSONResponse({"BASE_URL": ctx["origin"]})

# serve favicon if present
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    favicon_path = Path("static") / "favicon.ico"
    if favicon_path.exists():
        return FileResponse(str(favicon_path), media_type="image/x-icon")
    raise HTTPException(status_code=404, detail="favicon not found")


# Add an endpoint that serves `static/index.html` at /index.html
@app.get("/index.html", include_in_schema=False)
async def serve_index():
    index_path = Path("static") / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="index.html not found")
    return FileResponse(str(index_path), media_type="text/html")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


@app.get("/session/{con_uuid}", tags=["debug"])
async def get_session(con_uuid: str):
    """Return the working/session file contents for debugging (checks workingfiles then session)."""
    try:
        normalized = _validate_con_uuid(con_uuid)
    except HTTPException:
        # accept raw input too
        normalized = con_uuid

    working_path = BASE_SAVE_DIR / "workingfiles" / f"{normalized}.json"
    session_path = BASE_SAVE_DIR / "session" / f"{normalized}.json"

    if working_path.exists():
        try:
            return json.loads(working_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Failed to read workingfile: {exc}")
    if session_path.exists():
        try:
            return json.loads(session_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Failed to read session file: {exc}")

    raise HTTPException(status_code=404, detail="Working/session file not found")


@app.get("/webauth/logs", include_in_schema=False)
async def webauthn_logs(lines: int = 200):
    """Return the last `lines` lines from the webauthn log file for debugging (dev-only).
    Example: /webauth/logs?lines=100
    """
    try:
        log_file = BASE_SAVE_DIR / "log" / "webauthn.log"
        if not log_file.exists():
            raise HTTPException(status_code=404, detail="Log file not found")
        # read last N lines efficiently
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read()
        all_lines = data.splitlines()
        selected = all_lines[-lines:]
        return JSONResponse({"lines": selected})
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to read logs: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

@app.get("/webauth/auth/wait")
async def auth_wait(con_uuid: str = Query(..., alias="con-uuid"), timeout: int = Query(60)):
    """Block until the working/session file for `con-uuid` reports webauthn completion or until `timeout` seconds.
    Returns the working/session JSON when complete, otherwise raises 408.
    """
    try:
        validated = _validate_con_uuid(con_uuid)
    except HTTPException:
        validated = con_uuid

    end = time.time() + float(timeout)
    poll_interval = 0.5
    working_path = BASE_SAVE_DIR / "workingfiles" / f"{validated}.json"
    session_path = BASE_SAVE_DIR / "session" / f"{validated}.json"

    logger.info("auth_wait started for %s timeout=%s", validated, timeout)
    while time.time() < end:
        p = None
        if working_path.exists():
            p = working_path
        elif session_path.exists():
            p = session_path

        if p:
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.debug("auth_wait: failed to read json for %s: %s", p, exc)
                await asyncio.sleep(poll_interval)
                continue

            target = None
            if isinstance(data, dict):
                target = data
            elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                target = data[0]

            if target:
                status_val = target.get("status")
                steps = target.get("steps") or {}
                web = steps.get("webauthn") if isinstance(steps, dict) else None
                if status_val == "webauthn_complete":
                    logger.info("auth_wait: found status webauthn_complete for %s", validated)
                    return JSONResponse(target)
                if isinstance(web, dict) and web.get("status") == "complete":
                    logger.info("auth_wait: found steps.webauthn.complete for %s", validated)
                    return JSONResponse(target)
        await asyncio.sleep(poll_interval)

    logger.warning("auth_wait timeout waiting for webauthn completion for %s", validated)
    raise HTTPException(status_code=408, detail="Timeout waiting for webauthn completion")
