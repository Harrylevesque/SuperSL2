from webauthn import (
    generate_registration_options, verify_registration_response,
    generate_authentication_options, verify_authentication_response,
    options_to_json
)
from webauthn.helpers.structs import UserVerificationRequirement, RegistrationCredential, AuthenticationCredential, AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor, PublicKeyCredentialType
import json
import os
import dataclasses
import base64

credentials_file = '../credentials.json'
if os.path.exists(credentials_file):
    with open(credentials_file, 'r') as f:
        CREDENTIALS: dict = json.load(f)
else:
    CREDENTIALS = {}

CHALLENGES: dict = {}

RP_ID = 'https://service.mfaip.harrylevesque.dev/'
RP_NAME = 'WebAuthn Demo'
ORIGIN = 'https://service.mfaip.harrylevesque.dev/'

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def encode_bytes(obj):
    if isinstance(obj, dict):
        return {k: encode_bytes(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [encode_bytes(i) for i in obj]
    elif isinstance(obj, bytes):
        return b64url_encode(obj)
    else:
        return obj

async def register_start(user_id: str):
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
    options_dict = dataclasses.asdict(options)
    return encode_bytes(options_dict)

async def register_finish(body: dict):
    user_id = body.get('user_id', 'user1')
    credential = RegistrationCredential(**body)
    challenge = CHALLENGES.get(user_id)
    if not challenge:
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
        return {"verified": True}
    except Exception:
        return {"verified": False}

async def auth_start(user_id: str):
    allow_credentials = [PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY, id=user_id.encode())]
    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED
    )
    CHALLENGES[user_id] = options.challenge
    options_dict = dataclasses.asdict(options)
    return encode_bytes(options_dict)

async def auth_finish(body: dict):
    user_id = body.get('user_id', 'user1')
    cred = AuthenticationCredential(**body)
    challenge = CHALLENGES.get(user_id)
    cred_data = CREDENTIALS.get(user_id)
    if not challenge or not cred_data:
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
        return {"verified": True}
    except Exception:
        return {"verified": False}
