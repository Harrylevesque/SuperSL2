from webauthn import (
    generate_registration_options, verify_registration_response,
    generate_authentication_options, verify_authentication_response,
    options_to_json
)
from webauthn.helpers.structs import UserVerificationRequirement, RegistrationCredential, AuthenticationCredential, AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor, PublicKeyCredentialType
import json
import os
import logging
import dotenv
from pathlib import Path
from urllib.parse import urlparse
from typing import Any


dotenv.load_dotenv(Path(__file__).resolve().parents[1] / ".env")

RP_NAME = os.getenv("WEBAUTHN_RP_NAME", "SuperSL2")

logger = logging.getLogger(__name__)

credentials_file = '../credentials.json'
CREDENTIALS: dict = {}
if os.path.exists(credentials_file):
    with open(credentials_file, 'r') as f:
        CREDENTIALS = json.load(f)

CHALLENGES: dict = {}


def _origin_from_request(request: Any | None) -> str | None:
    if request is None:
        return None

    forwarded_proto = request.headers.get("x-forwarded-proto")
    forwarded_host = request.headers.get("x-forwarded-host")
    if forwarded_proto and forwarded_host:
        return f"{forwarded_proto}://{forwarded_host}".rstrip("/")

    base_url = str(request.base_url).rstrip("/")
    return base_url or None


def resolve_webauthn_config(request: Any | None = None) -> dict:
    env_origin = os.getenv("WEBAUTHN_ORIGIN") or os.getenv("host")
    request_origin = _origin_from_request(request)
    origin = (env_origin or request_origin or "").rstrip("/")

    env_rp_id = os.getenv("WEBAUTHN_RP_ID")
    rp_id = env_rp_id
    if not rp_id and origin:
        rp_id = urlparse(origin).hostname
    if not rp_id and request_origin:
        rp_id = urlparse(request_origin).hostname

    if not origin or not rp_id:
        raise RuntimeError(
            "WebAuthn config missing. Set WEBAUTHN_ORIGIN/WEBAUTHN_RP_ID (or host in .env)."
        )

    return {
        "rp_id": rp_id,
        "origin": origin,
        "rp_name": RP_NAME,
    }


async def register_start(user_id: str, webauthn_config: dict | None = None):
    try:
        ctx = webauthn_config or resolve_webauthn_config()
        uid = user_id.encode()
        options = generate_registration_options(
            rp_name=ctx["rp_name"],
            rp_id=ctx["rp_id"],
            user_id=uid,
            user_name='Demo User',
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.REQUIRED
            )
        )
        CHALLENGES[user_id] = options.challenge
        options_json = options_to_json(options)
        logger.info(f"Registration options for {user_id}: {options_json}")
        return json.loads(options_json)
    except Exception as e:
        logger.error(f"Error in register_start: {e}", exc_info=True)
        raise


async def register_finish(body: dict, webauthn_config: dict | None = None):
    try:
        ctx = webauthn_config or resolve_webauthn_config()
        user_id = body.get('user_id', 'user1')
        # Build model using parse_raw so incoming camelCase keys (e.g., rawId) are handled
        credential = RegistrationCredential.parse_raw(json.dumps(body))
        challenge = CHALLENGES.get(user_id)
        if not challenge:
            logger.warning(f"No challenge found for user {user_id}")
            return {"verified": False}
        try:
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=challenge,
                expected_origin=ctx["origin"],
                expected_rp_id=ctx["rp_id"]
            )
            CREDENTIALS[user_id] = {
                'public_key': verification.credential_public_key.hex(),
                'sign_count': verification.sign_count
            }
            with open(credentials_file, 'w') as f:
                json.dump(CREDENTIALS, f)
            del CHALLENGES[user_id]
            logger.info(f"Registration successful for {user_id}")
            return {"verified": True}
        except Exception as e:
            logger.error(f"Registration verification failed: {e}", exc_info=True)
            return {"verified": False}
    except Exception as e:
        logger.error(f"Error in register_finish: {e}", exc_info=True)
        return {"verified": False}


async def auth_start(user_id: str, webauthn_config: dict | None = None):
    try:
        ctx = webauthn_config or resolve_webauthn_config()
        allow_credentials = [PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY, id=user_id.encode())]
        options = generate_authentication_options(
            rp_id=ctx["rp_id"],
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.REQUIRED
        )
        CHALLENGES[user_id] = options.challenge
        options_json = options_to_json(options)
        logger.info(f"Authentication options for {user_id}: {options_json}")
        return json.loads(options_json)
    except Exception as e:
        logger.error(f"Error in auth_start: {e}", exc_info=True)
        raise


async def auth_finish(body: dict, webauthn_config: dict | None = None):
    try:
        ctx = webauthn_config or resolve_webauthn_config()
        user_id = body.get('user_id', 'user1')
        # Build model using parse_raw so incoming camelCase keys are handled
        cred = AuthenticationCredential.parse_raw(json.dumps(body))
        challenge = CHALLENGES.get(user_id)
        cred_data = CREDENTIALS.get(user_id)
        if not challenge or not cred_data:
            logger.warning(f"Missing challenge or credentials for user {user_id}")
            return {"verified": False}
        try:
            verification = verify_authentication_response(
                credential=cred,
                expected_challenge=challenge,
                expected_origin=ctx["origin"],
                expected_rp_id=ctx["rp_id"],
                credential_public_key=bytes.fromhex(cred_data['public_key']),
                credential_current_sign_count=cred_data['sign_count']
            )
            CREDENTIALS[user_id]['sign_count'] = verification.new_sign_count
            with open(credentials_file, 'w') as f:
                json.dump(CREDENTIALS, f)
            del CHALLENGES[user_id]
            logger.info(f"Authentication successful for {user_id}")
            return {"verified": True}
        except Exception as e:
            logger.error(f"Authentication verification failed: {e}", exc_info=True)
            return {"verified": False}
    except Exception as e:
        logger.error(f"Error in auth_finish: {e}", exc_info=True)
        return {"verified": False}
