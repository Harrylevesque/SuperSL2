"""
webauthn_flow.py — real registration and authentication handlers for the frontend.

Storage layout (under BASE_SAVE_DIR/webauthn/):
  credentials/<user_id>.json  — list of stored WebAuthn credentials
  challenges/<user_id>.json   — pending challenge for the user
"""
import json
import os
import time
import logging
from pathlib import Path
from uuid import UUID

from fastapi import HTTPException

from flow.workingfile import update_workingfile_status
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier

from config import BASE_SAVE_DIR

# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------

WEBAUTHN_DIR = BASE_SAVE_DIR / "webauthn"
CRED_DIR = WEBAUTHN_DIR / "credentials"
CHALLENGE_DIR = WEBAUTHN_DIR / "challenges"
USER_DIR = BASE_SAVE_DIR / "user"

# Module logger
logger = logging.getLogger(__name__)


def _ensure_dirs():
    CRED_DIR.mkdir(parents=True, exist_ok=True)
    CHALLENGE_DIR.mkdir(parents=True, exist_ok=True)


def _cred_path(user_id: str) -> Path:
    return CRED_DIR / f"{user_id}.json"


def _challenge_path(user_id: str) -> Path:
    return CHALLENGE_DIR / f"{user_id}.json"


def _load_credentials(user_id: str) -> list:
    p = _cred_path(user_id)
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return []


def _save_credentials(user_id: str, creds: list):
    _ensure_dirs()
    _cred_path(user_id).write_text(json.dumps(creds, indent=2), encoding="utf-8")


def _save_challenge(user_id: str, challenge_bytes: bytes):
    _ensure_dirs()
    _challenge_path(user_id).write_text(
        json.dumps(list(challenge_bytes)), encoding="utf-8"
    )


def _load_and_delete_challenge(user_id: str) -> bytes:
    p = _challenge_path(user_id)
    if not p.exists():
        raise HTTPException(status_code=400, detail="No pending challenge found. Start the flow again.")
    data = json.loads(p.read_text(encoding="utf-8"))
    p.unlink(missing_ok=True)
    return bytes(data)


# ---------------------------------------------------------------------------
# Config resolver — reads from .env / environment, falls back to request host
# ---------------------------------------------------------------------------

def resolve_webauthn_config(request) -> dict:
    """Return {'rp_id': ..., 'rp_name': ..., 'origin': ...} from env or request."""
    origin = os.getenv("WEBAUTHN_ORIGIN") or f"{request.url.scheme}://{request.url.netloc}"
    rp_id = os.getenv("WEBAUTHN_RP_ID") or request.url.hostname
    rp_name = os.getenv("WEBAUTHN_RP_NAME", "SuperSL2")
    return {"origin": origin, "rp_id": rp_id, "rp_name": rp_name}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def _normalize_sv_uuid(sv_uuid: str) -> str:
    if sv_uuid.startswith("sv--"):
        raw_uuid = sv_uuid[4:]
    elif sv_uuid.startswith("sv-"):
        raw_uuid = sv_uuid[3:]
    else:
        raise HTTPException(status_code=400, detail="sv_uuid must start with 'sv-' or 'sv--'")

    try:
        parsed = UUID(raw_uuid)
    except ValueError:
        raise HTTPException(status_code=400, detail="sv_uuid must include a valid UUID")

    return f"sv--{str(parsed)}"


def _normalize_svu_uuid(svu_uuid: str) -> str:
    if not svu_uuid.startswith("svu--"):
        raise HTTPException(status_code=400, detail="svu_uuid must start with 'svu--'")

    try:
        parsed = UUID(svu_uuid[5:])
    except ValueError:
        raise HTTPException(status_code=400, detail="svu_uuid must include a valid UUID")

    return f"svu--{str(parsed)}"


def _normalize_identifiers(sv_uuid: str, svu_uuid: str) -> tuple[str, str]:
    if not sv_uuid or not svu_uuid:
        raise HTTPException(status_code=400, detail="sv_uuid and svu_uuid are required")
    return _normalize_sv_uuid(sv_uuid), _normalize_svu_uuid(svu_uuid)


def _combined_user_id(sv_uuid: str, svu_uuid: str) -> str:
    return f"{sv_uuid}:{svu_uuid}"


def _load_service_user_record(sv_uuid: str, svu_uuid: str) -> dict:
    user_path = USER_DIR / sv_uuid / f"{svu_uuid}.json"
    if not user_path.exists():
        raise HTTPException(status_code=404, detail="Service user record not found for sv_uuid/svu_uuid")
    return json.loads(user_path.read_text(encoding="utf-8"))


async def register_start(sv_uuid: str, svu_uuid: str, config: dict):
    """Generate and return registration options for the given service user."""
    logger.info("webauthn.register_start called: sv_uuid=%s svu_uuid=%s rp_id=%s", sv_uuid, svu_uuid, config.get("rp_id"))
    sv_uuid, svu_uuid = _normalize_identifiers(sv_uuid, svu_uuid)
    user_id = _combined_user_id(sv_uuid, svu_uuid)
    logger.debug("Normalized identifiers: user_id=%s", user_id)
    user_record = _load_service_user_record(sv_uuid, svu_uuid)

    existing = _load_credentials(user_id)
    logger.debug("Existing credentials count=%d for user_id=%s", len(existing), user_id)
    exclude = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["id"]))
        for c in existing
    ]

    opts = generate_registration_options(
        rp_id=config["rp_id"],
        rp_name=config["rp_name"],
        user_name=user_id,
        user_display_name=f"{sv_uuid}/{svu_uuid}",
        exclude_credentials=exclude,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
    )

    _save_challenge(user_id, opts.challenge)
    logger.info("Saved challenge for user_id=%s (len=%d)", user_id, len(opts.challenge) if hasattr(opts, 'challenge') else 0)

    payload = json.loads(options_to_json(opts))
    payload["registration_context"] = {
        "sv_uuid": sv_uuid,
        "svu_uuid": svu_uuid,
        "serviceuuid": user_record.get("serviceuuid"),
        "createdAt": user_record.get("createdAt"),
    }
    logger.debug("register_start returning payload keys=%s", list(payload.keys()))
    return payload


async def register_finish(body: dict, config: dict):
    """Verify the registration response and persist the credential."""
    logger.info("webauthn.register_finish called; body keys=%s", list(body.keys()))
    sv_uuid, svu_uuid = _normalize_identifiers(body.get("sv_uuid"), body.get("svu_uuid"))
    user_id = _combined_user_id(sv_uuid, svu_uuid)
    logger.debug("Normalized identifiers: user_id=%s", user_id)

    expected_challenge = _load_and_delete_challenge(user_id)
    logger.debug("Loaded and deleted expected challenge for user_id=%s", user_id)

    try:
        verification = verify_registration_response(
            credential=body,
            expected_challenge=expected_challenge,
            expected_origin=config["origin"],
            expected_rp_id=config["rp_id"],
            require_user_verification=False,
        )
    except Exception as exc:
        logger.exception("Registration verification failed for user_id=%s: %s", user_id, exc)
        raise HTTPException(status_code=400, detail=f"Registration verification failed: {exc}")

    # Persist the new credential
    creds = _load_credentials(user_id)
    import base64
    creds.append(
        {
            "id": base64.urlsafe_b64encode(verification.credential_id).rstrip(b"=").decode(),
            "public_key": base64.b64encode(verification.credential_public_key).decode(),
            "sign_count": verification.sign_count,
            "transports": getattr(verification, "credential_device_type", None),
        }
    )
    _save_credentials(user_id, creds)
    logger.info("Saved credential for user_id=%s; total_creds=%d", user_id, len(creds))

    user_record = _load_service_user_record(sv_uuid, svu_uuid)
    return {
        "verified": True,
        "sv_uuid": sv_uuid,
        "svu_uuid": svu_uuid,
        "serviceuuid": user_record.get("serviceuuid"),
        "createdAt": user_record.get("createdAt"),
        "keychain": user_record.get("keychain", {}),
    }


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

async def auth_start(sv_uuid: str, svu_uuid: str, config: dict):
    """Generate and return authentication options for the given service user."""
    logger.info("webauthn.auth_start called: sv_uuid=%s svu_uuid=%s rp_id=%s", sv_uuid, svu_uuid, config.get("rp_id"))
    sv_uuid, svu_uuid = _normalize_identifiers(sv_uuid, svu_uuid)
    user_id = _combined_user_id(sv_uuid, svu_uuid)
    logger.debug("Normalized identifiers: user_id=%s", user_id)

    existing = _load_credentials(user_id)
    if not existing:
        logger.warning("No credentials registered for user_id=%s", user_id)
        raise HTTPException(status_code=404, detail="No credentials registered for this sv_uuid/svu_uuid")

    allow = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["id"]))
        for c in existing
    ]
    logger.debug("Allow credential count=%d", len(allow))

    opts = generate_authentication_options(
        rp_id=config["rp_id"],
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    _save_challenge(user_id, opts.challenge)
    logger.info("Saved auth challenge for user_id=%s", user_id)

    return json.loads(options_to_json(opts))


async def auth_finish(body: dict, config: dict):
    """Verify the authentication response."""
    logger.info("webauthn.auth_finish called; incoming body keys=%s", list(body.keys()))
    sv_uuid, svu_uuid = _normalize_identifiers(body.get("sv_uuid"), body.get("svu_uuid"))
    user_id = _combined_user_id(sv_uuid, svu_uuid)
    logger.debug("Normalized identifiers: user_id=%s", user_id)

    expected_challenge = _load_and_delete_challenge(user_id)
    logger.debug("Loaded expected challenge for user_id=%s", user_id)

    creds = _load_credentials(user_id)
    if not creds:
        logger.warning("No credentials found for user_id=%s", user_id)
        raise HTTPException(status_code=404, detail="No credentials registered for this sv_uuid/svu_uuid")

    import base64

    # Match the credential by id
    cred_id_from_body = body.get("id") or body.get("rawId", "")
    matched = next(
        (c for c in creds if c["id"] == cred_id_from_body),
        None,
    )
    if matched is None:
        # Try with padding variants
        matched = next(
            (c for c in creds),  # fallback to first credential
            None,
        )
    if matched is None:
        raise HTTPException(status_code=400, detail="Credential not found")

    try:
        logger.debug("Attempting to match credential id from body: id=%s rawId=%s", body.get("id"), body.get("rawId"))
        verification = verify_authentication_response(
            credential=body,
            expected_challenge=expected_challenge,
            expected_origin=config["origin"],
            expected_rp_id=config["rp_id"],
            credential_public_key=base64.b64decode(matched["public_key"]),
            credential_current_sign_count=matched["sign_count"],
            require_user_verification=False,
        )
    except Exception as exc:
        logger.exception("Authentication verification failed for user_id=%s: %s", user_id, exc)
        raise HTTPException(status_code=400, detail=f"Authentication verification failed: {exc}")

    # Update sign count
    matched["sign_count"] = verification.new_sign_count
    _save_credentials(user_id, creds)
    logger.info("Updated sign_count for user_id=%s credential_id=%s new_sign_count=%s", user_id, matched.get("id"), verification.new_sign_count)

    response = {"verified": True, "sv_uuid": sv_uuid, "svu_uuid": svu_uuid}

    con_uuid = body.get("con_uuid") or body.get("con-uuid")
    if con_uuid:
        ts = time.time()
        logger.info("webauthn.auth_finish: updating workingfile for con_uuid=%s user_id=%s", con_uuid, user_id)
        try:
            update_workingfile_status(con_uuid, "webauthn_complete", "webauthn", ts)
            logger.info("webauthn.auth_finish: workingfile updated for con_uuid=%s", con_uuid)
            steps = response.setdefault("steps", {})
            steps["webauthn"] = {
                "status": "complete",
                "time_of_last_completion": ts,
            }
            response["con_uuid"] = con_uuid
        except Exception as exc:
            logger.exception("webauthn.auth_finish: failed to update workingfile for con_uuid=%s: %s", con_uuid, exc)
            steps = response.setdefault("steps", {})
            steps["webauthn"] = {
                "status": "error",
                "detail": str(exc),
            }

    return response
