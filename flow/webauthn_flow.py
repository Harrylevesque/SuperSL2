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
from urllib.parse import urlparse


dotenv.load_dotenv()
host_env = os.environ.get("host")
if not host_env:
    raise RuntimeError("host not set in .env")


parsed = urlparse(host_env)
RP_ID = parsed.hostname  # e.g., 'localhost' [code:1]

RP_NAME = 'multi factor authentication ststem in python to replace current systems'
ORIGIN = host_env

logger = logging.getLogger(__name__)

credentials_file = '../credentials.json'
if os.path.exists(credentials_file):
    with open(credentials_file, 'r') as f:
        CREDENTIALS: dict = json.load(f)
else:
    CREDENTIALS = {}

CHALLENGES: dict = {}

async def register_start(user_id: str):
    try:
        uid = user_id.encode()
        options = generate_registration_options(
            rp_name=RP_NAME,
            rp_id=RP_ID,
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

async def register_finish(body: dict):
    try:
        user_id = body.get('user_id', 'user1')
        credential = RegistrationCredential(**body)
        challenge = CHALLENGES.get(user_id)
        if not challenge:
            logger.warning(f"No challenge found for user {user_id}")
            return {"verified": False}
        try:
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=challenge,
                expected_origin=ORIGIN,
                expected_rp_id=RP_ID
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

async def auth_start(user_id: str):
    try:
        allow_credentials = [PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY, id=user_id.encode())]
        options = generate_authentication_options(
            rp_id=RP_ID,
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

async def auth_finish(body: dict):
    try:
        user_id = body.get('user_id', 'user1')
        cred = AuthenticationCredential(**body)
        challenge = CHALLENGES.get(user_id)
        cred_data = CREDENTIALS.get(user_id)
        if not challenge or not cred_data:
            logger.warning(f"Missing challenge or credentials for user {user_id}")
            return {"verified": False}
        try:
            verification = verify_authentication_response(
                credential=cred,
                expected_challenge=challenge,
                expected_origin=ORIGIN,
                expected_rp_id=RP_ID,
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
