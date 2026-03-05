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

# track ephemeral challenges (persisted to disk) - ensure global is declared before _load_challenges
CHALLENGES: dict = {}

# persist challenges so they survive reloads
_CHALLENGES_FILE = Path(__file__).resolve().parents[1] / 'webauthn_challenges.json'


def _load_challenges() -> dict:
    global CHALLENGES
    try:
        if _CHALLENGES_FILE.exists():
            with open(_CHALLENGES_FILE, 'r') as f:
                CHALLENGES = json.load(f)
    except Exception:
        CHALLENGES = {}
    return CHALLENGES


def _save_challenges() -> None:
    try:
        _CHALLENGES_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_CHALLENGES_FILE, 'w') as f:
            json.dump(CHALLENGES, f)
    except Exception:
        pass

# load persisted challenges at import time
_load_challenges()


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


def _b64url_decode_bytes(s: str) -> bytes:
    if s is None:
        return None
    if isinstance(s, (bytes, bytearray)):
        return bytes(s)
    if not isinstance(s, str):
        return None
    s2 = s.replace('-', '+').replace('_', '/')
    padding = '=' * (-len(s2) % 4)
    try:
        return base64.urlsafe_b64decode(s2 + padding)
    except Exception:
        try:
            return base64.b64decode(s2 + padding)
        except Exception:
            return None


def _normalize_b64url(data) -> str | None:
    """Return a base64url (no padding) string for bytes or base64-like input.
    Accepts bytes, bytearray, or str. Returns None on failure.
    """
    try:
        if data is None:
            return None
        if isinstance(data, (bytes, bytearray)):
            b = bytes(data)
            s = base64.urlsafe_b64encode(b).decode('ascii')
            return s.rstrip('=')
        if isinstance(data, str):
            # if it's already base64url-ish, normalize by decoding then re-encoding
            # try to decode as urlsafe base64
            try:
                b = _b64url_decode_bytes(data)
                if b is None:
                    return None
                s = base64.urlsafe_b64encode(b).decode('ascii')
                return s.rstrip('=')
            except Exception:
                return None
        return None
    except Exception:
        return None


def _find_user_by_challenge(client_challenge) -> tuple[str | None, str | None]:
    """Return (user_id, stored_challenge_str) matching the provided challenge.
    Accepts either bytes (raw challenge bytes) or a base64url string. Compares normalized base64url-no-pad strings.
    """
    if client_challenge is None:
        return (None, None)
    try:
        norm = _normalize_b64url(client_challenge)
        if not norm:
            return (None, None)
    except Exception:
        return (None, None)
    for uid, stored in CHALLENGES.items():
        try:
            if stored == norm:
                return (uid, stored)
        except Exception:
            continue
    return (None, None)


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
        # store normalized base64url (no padding) string for the challenge
        ch_norm = _normalize_b64url(options.challenge)
        CHALLENGES[user_id] = ch_norm if ch_norm else options.challenge
        _save_challenges()
        # Debug: log a sanitized summary of stored challenges
        try:
            summary = {uid: (val[:8] + '...' if isinstance(val, str) and len(val) > 8 else val) for uid, val in CHALLENGES.items()}
            logger.debug(f"Stored CHALLENGES summary: {summary}")
        except Exception:
            pass
        options_json = options_to_json(options)
        logger.info(f"Registration options for {user_id}: {options_json}")
        return json.loads(options_json)
    except Exception as e:
        logger.error(f"Error in register_start: {e}", exc_info=True)
        raise


async def register_finish(body: dict, webauthn_config: dict | None = None):
    try:
        _load_challenges()
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

            # If the caller didn't pass a user_id, try to derive it from the clientDataJSON challenge
            if not user_id or user_id == 'user1':
                try:
                    cdj = getattr(resp_ns, 'client_data_json', None)
                    if isinstance(cdj, (bytes, bytearray)):
                        cdj_obj = json.loads(cdj.decode('utf-8'))
                        chal_field = cdj_obj.get('challenge')
                        # chal_field may be base64url string; match by normalized base64url
                        found_uid, found_chal = _find_user_by_challenge(chal_field)
                        if found_uid:
                            user_id = found_uid
                            logger.info(f"Derived user_id={user_id} from clientDataJSON challenge")
                except Exception:
                    pass

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
        # If we still don't have a challenge, try to locate by parsing clientDataJSON challenge
        if not challenge:
            try:
                cdj = getattr(credential.response, 'client_data_json', None)
                if isinstance(cdj, (bytes, bytearray)):
                    cdj_obj = json.loads(cdj.decode('utf-8'))
                    chal_field = cdj_obj.get('challenge')
                    found_uid, found_chal = _find_user_by_challenge(chal_field)
                    if found_uid:
                        challenge = found_chal
                        user_id = found_uid
                        logger.info(f"Located challenge for user_id={user_id} via clientDataJSON")
            except Exception:
                pass

        if not challenge:
            # Debug: show stored challenges and incoming challenge for diagnosis
            try:
                incoming_chal = None
                try:
                    incoming_chal = getattr(credential.response, 'client_data_json', None)
                    if isinstance(incoming_chal, (bytes, bytearray)):
                        incoming_chal = json.loads(incoming_chal.decode('utf-8')).get('challenge')
                except Exception:
                    pass
                logger.debug(f"Missing challenge. Stored CHALLENGES keys: {list(CHALLENGES.keys())}, incoming_challenge_sample={str(incoming_chal)[:32]}")
            except Exception:
                pass
            logger.warning(f"No challenge found for user {user_id}")
            return {"verified": False}
        try:
            # Ensure expected_challenge is bytes (we may have stored it as a base64url string)
            if isinstance(challenge, (bytes, bytearray)):
                expected_challenge = bytes(challenge)
            else:
                expected_challenge = _b64url_decode_bytes(challenge) if isinstance(challenge, str) else None
            if expected_challenge is None:
                logger.warning(f"Unable to decode expected challenge for user {user_id}")
                return {"verified": False}
            # --- DEBUG: sanitized summary of filtered & response ---
            try:
                resp = getattr(credential, 'response', None)
                resp_summary = {}
                for name in ('client_data_json', 'clientDataJSON', 'attestation_object', 'attestationObject', 'authenticator_data', 'authenticatorData', 'signature', 'user_handle', 'userHandle'):
                    val = None
                    if hasattr(resp, name):
                        val = getattr(resp, name)
                    if isinstance(val, (bytes, bytearray)):
                        resp_summary[name] = f"bytes(len={len(val)})"
                    elif isinstance(val, str):
                        resp_summary[name] = f"str(len={len(val)})"
                    elif isinstance(val, dict):
                        resp_summary[name] = f"dict(keys={list(val.keys())})"
                    else:
                        resp_summary[name] = type(val).__name__
                logger.debug(f"Registration pre-verify: filtered_keys={list(filtered.keys())}, response_summary={resp_summary}")
            except Exception:
                logger.debug("Registration pre-verify: failed to build response summary", exc_info=True)
             verification = verify_registration_response(
                 credential=credential,
                 expected_challenge=expected_challenge,
                 expected_origin=ctx["origin"],
                 expected_rp_id=ctx["rp_id"]
             )
            # store public key, sign count and credential id (raw_id hex) for later lookup
            raw_id_bytes = None
            try:
                raw_id_bytes = getattr(credential, 'raw_id', None)
                if isinstance(raw_id_bytes, (bytes, bytearray)):
                    raw_hex = raw_id_bytes.hex()
                elif isinstance(raw_id_bytes, str):
                    # if it's a base64-like string, try to decode
                    rbytes = _b64url_decode_bytes(raw_id_bytes)
                    raw_hex = rbytes.hex() if rbytes else None
                else:
                    raw_hex = None
            except Exception:
                raw_hex = None

            CREDENTIALS[user_id] = {
                'public_key': verification.credential_public_key.hex(),
                'sign_count': verification.sign_count,
                'cred_id': raw_hex,
            }
            with open(credentials_file, 'w') as f:
                json.dump(CREDENTIALS, f)
            # remove challenge mapping
            try:
                del CHALLENGES[user_id]
                _save_challenges()
            except Exception:
                pass
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
        _save_challenges()
        options_json = options_to_json(options)
        logger.info(f"Authentication options for {user_id}: {options_json}")
        return json.loads(options_json)
    except Exception as e:
        logger.error(f"Error in auth_start: {e}", exc_info=True)
        raise


async def auth_finish(body: dict, webauthn_config: dict | None = None):
    try:
        _load_challenges()
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
        # If no challenge found for provided user_id, try to derive user by matching incoming raw_id to stored cred_id
        if not (challenge and user_id in CHALLENGES):
            try:
                incoming_raw = getattr(cred, 'raw_id', None)
                incoming_bytes = None
                if isinstance(incoming_raw, (bytes, bytearray)):
                    incoming_bytes = bytes(incoming_raw)
                elif isinstance(incoming_raw, str):
                    incoming_bytes = _b64url_decode_bytes(incoming_raw)
                if incoming_bytes:
                    incoming_hex = incoming_bytes.hex()
                    for uid, data in CREDENTIALS.items():
                        if data.get('cred_id') == incoming_hex:
                            user_id = uid
                            logger.info(f"Resolved user_id={user_id} from credential raw_id")
                            break
            except Exception:
                pass
        cred_data = CREDENTIALS.get(user_id)
        if not challenge or not cred_data:
            try:
                cred_summary = {uid: (data.get('cred_id')[:8] + '...' if data.get('cred_id') and len(data.get('cred_id')) > 8 else data.get('cred_id')) for uid, data in CREDENTIALS.items()}
                logger.debug(f"Stored credentials summary: {cred_summary}")
            except Exception:
                pass
            logger.warning(f"Missing challenge or credentials for user {user_id}")
            return {"verified": False}
        try:
            # Ensure expected_challenge is bytes
            if isinstance(challenge, (bytes, bytearray)):
                expected_challenge = bytes(challenge)
            else:
                expected_challenge = _b64url_decode_bytes(challenge) if isinstance(challenge, str) else None
            if expected_challenge is None:
                logger.warning(f"Unable to decode expected challenge for user {user_id} during auth")
                return {"verified": False}
            # --- DEBUG: sanitized summary of filtered & response for auth ---
            try:
                resp = getattr(cred, 'response', None)
                resp_summary = {}
                for name in ('client_data_json', 'clientDataJSON', 'authenticator_data', 'authenticatorData', 'signature', 'attestation_object', 'user_handle', 'userHandle'):
                    val = None
                    if hasattr(resp, name):
                        val = getattr(resp, name)
                    if isinstance(val, (bytes, bytearray)):
                        resp_summary[name] = f"bytes(len={len(val)})"
                    elif isinstance(val, str):
                        resp_summary[name] = f"str(len={len(val)})"
                    elif isinstance(val, dict):
                        resp_summary[name] = f"dict(keys={list(val.keys())})"
                    else:
                        resp_summary[name] = type(val).__name__
                logger.debug(f"Auth pre-verify: filtered_keys={list(filtered.keys())}, response_summary={resp_summary}")
            except Exception:
                logger.debug("Auth pre-verify: failed to build response summary", exc_info=True)
             verification = verify_authentication_response(
                 credential=cred,
                 expected_challenge=expected_challenge,
                 expected_origin=ctx["origin"],
                 expected_rp_id=ctx["rp_id"],
                 credential_public_key=bytes.fromhex(cred_data['public_key']),
                 credential_current_sign_count=cred_data['sign_count']
             )
            # update stored sign count for the credential
            cred_data['sign_count'] = verification.sign_count
            with open(credentials_file, 'w') as f:
                json.dump(CREDENTIALS, f)
            # remove challenge mapping
            try:
                del CHALLENGES[user_id]
                _save_challenges()
            except Exception:
                pass
            logger.info(f"Authentication successful for {user_id}")
            return {"verified": True}
        except Exception as e:
            logger.error(f"Authentication verification failed: {e}", exc_info=True)
            return {"verified": False}
    except Exception as e:
        logger.error(f"Error in auth_finish: {e}", exc_info=True)
        return {"verified": False}

