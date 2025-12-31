# python
import typer
import base64
import json
import hashlib
import os
from pathlib import Path

cryptstage = ["hex", "hexbase64", "hexbase64sha256"]

app = typer.Typer()

def write_pubk_to_workingfile(
        con_uuid: str,
        pubkey: str,
):

    base_dir = Path("../storage/session")
    file_path = base_dir / f"{con_uuid}.json"

    with open(file_path, "r") as f:
        data = json.load(f)

    data["template"]["context"]["pubk"] = pubkey

    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)


@app.command()
def pubkcheck(con_uuid: str, sv_uuid: str, svu_uuid: str, stage: str, user_stored_pubk: str):

    """Encode-only pipeline: hex -> base64 -> sha256; hexbase64 -> sha256; hexbase64sha256 -> nothing."""
    if not user_stored_pubk:
        result = {"status": "invalid", "reason": "empty public key"}
        typer.echo(json.dumps(result))
        return result

    if stage not in cryptstage:
        result = {"status": "invalid", "reason": "unknown stage"}
        typer.echo(json.dumps(result))
        return result

    result = {"status": "valid", "stage": stage, "pubk": user_stored_pubk}

    if stage == "hex":
        # do NOT decode the hex string; treat as literal text
        hex_text = user_stored_pubk
        # base64-encode the hex string bytes
        hexbase64_bytes = base64.b64encode(hex_text.encode("utf-8"))
        hexbase64 = hexbase64_bytes.decode("ascii")
        # sha256 over the base64 bytes
        hexbase64sha256 = hashlib.sha256(hexbase64_bytes).hexdigest()
        finalpubk = hexbase64sha256

        fresh_stored_pubk = get_pubk(sv_uuid=sv_uuid, svu_uuid=svu_uuid)
        if not fresh_stored_pubk:
            result.update({"match": "no stored pubk", "reason": "stored public key not found"})
            typer.echo(json.dumps(result))
            return result

        stored_pubk = hashlib.sha256(base64.b64encode(fresh_stored_pubk.encode("utf-8"))).hexdigest()

        match = "match" if stored_pubk == finalpubk else "no match"

        result.update({
            "hex": hex_text,
            "hexbase64": hexbase64,
            "hexbase64sha256": hexbase64sha256,
            "match": match
        })

        write_pubk_to_workingfile(con_uuid, hexbase64sha256)


    elif stage == "hexbase64":
        # input is a base64 string; do NOT decode it, just sha256 its bytes
        hexbase64 = user_stored_pubk
        hexbase64sha256 = hashlib.sha256(hexbase64.encode("utf-8")).hexdigest()
        finalpubk = hexbase64sha256

        stored_pubk = get_pubk(sv_uuid=sv_uuid, svu_uuid=svu_uuid)
        if not stored_pubk:
            result = {"status": "invalid", "reason": "stored public key not found"}
            typer.echo(json.dumps(result))
            return result

        match = "match" if stored_pubk == finalpubk else "no match"
        result.update({
            "hexbase64": hexbase64,
            "hexbase64sha256": hexbase64sha256,
            "match": match
        })

        write_pubk_to_workingfile(con_uuid, hexbase64sha256)


    elif stage == "hexbase64sha256":
        # assume input is already the sha256 hex digest; do nothing
        hexbase64sha256 = user_stored_pubk
        finalpubk = hexbase64sha256

        stored_pubk = get_pubk(sv_uuid=sv_uuid, svu_uuid=svu_uuid)
        if not stored_pubk:
            result = {"status": "invalid", "reason": "stored public key not found"}
            typer.echo(json.dumps(result))
            return result

        match = "match" if stored_pubk == finalpubk else "no match"
        result.update({
            "hexbase64sha256": hexbase64sha256,
            "match": match
        })

        write_pubk_to_workingfile(con_uuid, hexbase64sha256)


    typer.echo(json.dumps(result))
    return result


def get_pubk(sv_uuid: str, svu_uuid: str):
    path = os.path.join('..', 'storage', 'user', f"{sv_uuid}", f'{svu_uuid}.json')

    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"File not found: {path}")
        return None
    except json.JSONDecodeError:
        print(f"Invalid JSON in: {path}")
        return None

    pubk = data.get('keychain', {}).get('pubk')
    if pubk is None:
        print("`keychain.pubk` not found in the JSON.")
        return None

    # return the stored public key string
    return pubk




if __name__ == "__main__":
    app()