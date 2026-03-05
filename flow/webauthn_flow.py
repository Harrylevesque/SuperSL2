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
import re
import base64
import inspect
from types import SimpleNamespace


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


def _camel_to_snake_key(key: str) -> str:
    # common WebAuthn camelCase -> snake_case mappings preserved
    # e.g., rawId -> raw_id, clientDataJSON -> client_data_json
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', key)
    s2 = re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()
    return s2


def _transform_keys(obj):
    if isinstance(obj, dict):
        new = {}
        for k, v in obj.items():
            new_k = _camel_to_snake_key(k)
            new[new_k] = _transform_keys(v)
        return new
    elif isinstance(obj, list):
        return [_transform_keys(v) for v in obj]
    else:
        return obj


def _b64url_to_bytes(s: str) -> bytes:
    if s is None:
        return s
    if isinstance(s, bytes):
        return s
    if not isinstance(s, str):
        return s
    # Add padding if missing
    s2 = s.replace('-', '+').replace('_', '/')
    padding = '=' * (-len(s2) % 4)
    try:
        return base64.b64decode(s2 + padding)
    except Exception:
        # fallback to urlsafe_b64decode
        return base64.urlsafe_b64decode(s + padding)


def _normalize_webauthn_credential(d: dict) -> dict:
    # Decode common fields from base64url to bytes where appropriate
    if not isinstance(d, dict):
        return d
    out = dict(d)  # shallow copy
    if 'raw_id' in out and isinstance(out['raw_id'], str):
        out['raw_id'] = _b64url_to_bytes(out['raw_id'])
    # response may contain binary fields
    resp = out.get('response')
    if isinstance(resp, dict):
        r = dict(resp)
        if 'attestation_object' in r and isinstance(r['attestation_object'], str):
            r['attestation_object'] = _b64url_to_bytes(r['attestation_object'])
        if 'client_data_json' in r and isinstance(r['client_data_json'], str):
            r['client_data_json'] = _b64url_to_bytes(r['client_data_json'])
        # authentication response fields
        if 'authenticator_data' in r and isinstance(r['authenticator_data'], str):
            r['authenticator_data'] = _b64url_to_bytes(r['authenticator_data'])
        if 'signature' in r and isinstance(r['signature'], str):
            r['signature'] = _b64url_to_bytes(r['signature'])
        if 'user_handle' in r and isinstance(r['user_handle'], str):
            # user_handle may be base64url or plain; attempt decode
            try:
                r['user_handle'] = _b64url_to_bytes(r['user_handle'])
            except Exception:
                pass
        out['response'] = r
    # allow_credentials: list of descriptors with id base64url
    if 'allow_credentials' in out and isinstance(out['allow_credentials'], list):
        new_list = []
        for item in out['allow_credentials']:
            if isinstance(item, dict) and 'id' in item and isinstance(item['id'], str):
                it = dict(item)
                it['id'] = _b64url_to_bytes(it['id'])
                new_list.append(it)
            else:
                new_list.append(item)
        out['allow_credentials'] = new_list
    return out


def _filter_to_model_fields(model_cls, d: dict) -> dict:
    """Return a copy of d containing only keys accepted by model_cls constructor.
    Attempt to use Pydantic __fields__ when available, otherwise inspect __init__ signature.
    """
    if not isinstance(d, dict):
        return d
    allowed = None
    try:
        if hasattr(model_cls, '__fields__'):
            allowed = set(model_cls.__fields__.keys())
        else:
            sig = inspect.signature(model_cls.__init__)
            allowed = set([p for p in sig.parameters.keys() if p != 'self' and p != 'kwargs' and p != 'cls'])
    except Exception:
        allowed = None
    if allowed:
        return {k: v for k, v in d.items() if k in allowed}
    return d


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
        # log keys shape for debugging (don't log full binary/blobs)
        try:
            keys = list(body.keys()) if isinstance(body, dict) else [type(body).__name__]
            logger.info(f"register_finish called for user_id={user_id}, body_keys={keys}")
        except Exception:
            logger.info("register_finish called, unable to enumerate body keys")
        # Build model by normalizing the incoming body (always use local normalization)
        try:
            transformed = _transform_keys(body)
            transformed = _normalize_webauthn_credential(transformed)
            # Remove browser-only fields the model doesn't expect
            for k in ['client_extension_results', 'authenticator_attachment', 'transports', 'authenticator_attachment']:
                transformed.pop(k, None)
            filtered = _filter_to_model_fields(RegistrationCredential, transformed)
            # Final whitelist fallback to avoid unexpected browser-only keys
            if not filtered or 'response' not in filtered:
                filtered = {k: v for k, v in transformed.items() if k in {'id', 'raw_id', 'response', 'type'}}
                logger.info(f"RegistrationCredential fallback filtered keys: {list(filtered.keys())}")
            else:
                logger.info(f"RegistrationCredential keys after filter: {list(filtered.keys())}")
            # Construct a lightweight credential object ensuring response has attributes
            resp = filtered.get('response')
            if isinstance(resp, dict):
                resp_ns = SimpleNamespace(**resp)
            elif isinstance(resp, SimpleNamespace):
                resp_ns = resp
            else:
                resp_ns = SimpleNamespace()

            # Normalize response fields to bytes for the verifier (handles camelCase & snake_case)
            resp_ns = _ensure_response_bytes(resp_ns)

            cred_kwargs = {
                'id': filtered.get('id'),
                'raw_id': filtered.get('raw_id'),
                'type': filtered.get('type'),
                'response': resp_ns,
            }
            credential = SimpleNamespace(**cred_kwargs)
        except Exception as e:
            logger.error(f"Failed to construct RegistrationCredential: {e}")
            raise
        challenge = CHALLENGES.get(user_id)
        if not challenge:
            logger.warning(f"No challenge found for user {user_id}")
            return {"verified": False}
        try:
            # Debug: log the type of response we're passing into the verifier
            try:
                resp_type = type(getattr(credential, 'response', None))
            except Exception:
                resp_type = None
            logger.info(f"Passing credential.response of type {resp_type} to verify_registration_response")

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
        try:
            keys = list(body.keys()) if isinstance(body, dict) else [type(body).__name__]
            logger.info(f"auth_finish called for user_id={user_id}, body_keys={keys}")
        except Exception:
            logger.info("auth_finish called, unable to enumerate body keys")
        # Build model by normalizing the incoming body (always use local normalization)
        try:
            # Always normalize incoming body into a SimpleNamespace credential
            transformed = _transform_keys(body)
            transformed = _normalize_webauthn_credential(transformed)
            for k in ['client_extension_results', 'authenticator_attachment', 'transports', 'authenticator_attachment']:
                transformed.pop(k, None)
            filtered = _filter_to_model_fields(AuthenticationCredential, transformed)
            if not filtered or 'response' not in filtered:
                filtered = {k: v for k, v in transformed.items() if k in {'id', 'raw_id', 'response', 'type'}}
                logger.info(f"AuthenticationCredential fallback filtered keys: {list(filtered.keys())}")
            else:
                logger.info(f"AuthenticationCredential keys after filter: {list(filtered.keys())}")
            resp = filtered.get('response')
            if isinstance(resp, dict):
                resp_ns = SimpleNamespace(**resp)
            elif isinstance(resp, SimpleNamespace):
                resp_ns = resp
            else:
                resp_ns = SimpleNamespace()
            resp_ns = _ensure_response_bytes(resp_ns)
            cred_kwargs = {
                'id': filtered.get('id'),
                'raw_id': filtered.get('raw_id'),
                'type': filtered.get('type'),
                'response': resp_ns,
            }
            cred = SimpleNamespace(**cred_kwargs)
        except Exception as e:
            logger.error(f"Failed to construct AuthenticationCredential: {e}")
            raise
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
            # Debug: log the type of response we passed into the verifier
            try:
                resp_type = type(getattr(cred, 'response', None))
            except Exception:
                resp_type = None
            logger.info(f"Passed cred.response of type {resp_type} to verify_authentication_response")

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


def _ensure_response_bytes(resp_ns: SimpleNamespace) -> SimpleNamespace:
    """Ensure common WebAuthn response fields are bytes on resp_ns.
    Accepts attributes in snake_case or camelCase and converts dict->bytes (JSON), str->base64url decode.
    """
    if resp_ns is None:
        return resp_ns
    variants = [
        ("client_data_json", "clientDataJSON"),
        ("attestation_object", "attestationObject"),
        ("authenticator_data", "authenticatorData"),
        ("signature", "signature"),
        ("user_handle", "userHandle"),
    ]
    for snake, camel in variants:
        val = None
        if hasattr(resp_ns, snake):
            val = getattr(resp_ns, snake)
            attr_name = snake
        elif hasattr(resp_ns, camel):
            val = getattr(resp_ns, camel)
            attr_name = camel
        else:
            continue
        # convert dict -> bytes(JSON)
        if isinstance(val, dict):
            try:
                b = json.dumps(val, separators=(",", ":")).encode("utf-8")
                setattr(resp_ns, attr_name, b)
                # also set snake name for verifier
                if attr_name != snake:
                    setattr(resp_ns, snake, b)
                continue
            except Exception:
                pass
        # convert str -> base64url decode
        if isinstance(val, str):
            try:
                s2 = val.replace("-", "+").replace("_", "/")
                padding = "=" * (-len(s2) % 4)
                b = base64.b64decode(s2 + padding)
                setattr(resp_ns, attr_name, b)
                if attr_name != snake:
                    setattr(resp_ns, snake, b)
                continue
            except Exception:
                try:
                    b = base64.urlsafe_b64decode(val + ("=" * (-len(val) % 4)))
                    setattr(resp_ns, attr_name, b)
                    if attr_name != snake:
                        setattr(resp_ns, snake, b)
                    continue
                except Exception:
                    pass
        # if bytes, ensure snake name exists
        if isinstance(val, (bytes, bytearray)):
            if attr_name != snake:
                setattr(resp_ns, snake, bytes(val))
            else:
                setattr(resp_ns, snake, bytes(val))
    return resp_ns
