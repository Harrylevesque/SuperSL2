"""
webauthn_flow.py — real registration and authentication handlers for the frontend.

Storage layout (under BASE_SAVE_DIR/webauthn/):
  credentials/<user_id>.json  — list of stored WebAuthn credentials
  challenges/<user_id>.json   — pending challenge for the user
"""
import json
import os
from pathlib import Path

from fastapi import HTTPException

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

async def register_start(user_id: str, config: dict):
    """Generate and return registration options for the given user."""
    existing = _load_credentials(user_id)
    exclude = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["id"]))
        for c in existing
    ]

    opts = generate_registration_options(
        rp_id=config["rp_id"],
        rp_name=config["rp_name"],
        user_name=user_id,
        user_display_name=user_id,
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

    # options_to_json returns a JSON string; parse it so FastAPI serialises it cleanly
    return json.loads(options_to_json(opts))


async def register_finish(body: dict, config: dict):
    """Verify the registration response and persist the credential."""
    user_id = body.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="user_id is required in the request body")

    expected_challenge = _load_and_delete_challenge(user_id)

    try:
        verification = verify_registration_response(
            credential=body,
            expected_challenge=expected_challenge,
            expected_origin=config["origin"],
            expected_rp_id=config["rp_id"],
            require_user_verification=False,
        )
    except Exception as exc:
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

    return {"verified": True}


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

async def auth_start(user_id: str, config: dict):
    """Generate and return authentication options for the given user."""
    existing = _load_credentials(user_id)
    if not existing:
        raise HTTPException(status_code=404, detail="No credentials registered for this user")

    allow = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["id"]))
        for c in existing
    ]

    opts = generate_authentication_options(
        rp_id=config["rp_id"],
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    _save_challenge(user_id, opts.challenge)

    return json.loads(options_to_json(opts))


async def auth_finish(body: dict, config: dict):
    """Verify the authentication response."""
    user_id = body.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="user_id is required in the request body")

    expected_challenge = _load_and_delete_challenge(user_id)

    creds = _load_credentials(user_id)
    if not creds:
        raise HTTPException(status_code=404, detail="No credentials registered for this user")

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
        raise HTTPException(status_code=400, detail=f"Authentication verification failed: {exc}")

    # Update sign count
    matched["sign_count"] = verification.new_sign_count
    _save_credentials(user_id, creds)

    return {"verified": True}
