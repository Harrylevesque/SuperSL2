# python
import time
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import typer

# === CONFIGURABLE PARAMETERS ===
INTERVAL = 5      # seconds per time bucket
TOLERANCE = 2       # ±bucket tolerance

def server_verify_single_use_otp(
    nonce: str,
    pk_hex: str,
    sig_hex: str,
    interval: int = INTERVAL,
    tolerance: int = TOLERANCE,
):
    """
    Verifies a single-use OTP using the public key.

    Args:
        nonce (str): received nonce from client (hex or plain)
        pk_hex (str): public key as hex string (32 bytes -> 64 hex chars)
        sig_hex (str): signature as hex string (64 bytes -> 128 hex chars)
        interval (int): seconds per bucket
        tolerance (int): ±bucket tolerance

    Returns:
        bool: True if valid, False otherwise (also prints result)
    """
    # Convert hex inputs to bytes, handle invalid hex
    try:
        pk_bytes = bytes.fromhex(pk_hex)
    except ValueError:
        typer.echo("invalid: public key is not valid hex")
        raise typer.Exit(code=2)

    try:
        signature = bytes.fromhex(sig_hex)
    except ValueError:
        typer.echo("invalid: signature is not valid hex")
        raise typer.Exit(code=2)

    if len(pk_bytes) != 32:
        typer.echo(f"invalid: public key length {len(pk_bytes)} != 32")
        raise typer.Exit(code=2)
    if len(signature) not in (64,):  # ed25519 signatures are 64 bytes
        typer.echo(f"invalid: signature length {len(signature)} != 64")
        raise typer.Exit(code=2)

    # Reconstruct public key from bytes
    pk = ed25519.Ed25519PublicKey.from_public_bytes(pk_bytes)

    now = int(time.time()) // interval
    for bucket in range(now - tolerance, now + tolerance + 1):
        msg = f"{bucket}:{nonce}".encode()
        try:
            pk.verify(signature, msg)
            typer.echo("valid")
            return True
        except InvalidSignature:
            continue

    typer.echo("invalid")
    return False