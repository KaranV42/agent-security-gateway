import json
import sys
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from asg.auth import get_current_principal
from asg.idp import idp

ISSUER = "https://idp.asg-prototype.local"
AUDIENCE = "https://api.asg-prototype.local"


def private_key_pem(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def encode_fixture(private_key, issuer=ISSUER, expiration=4102444800):
    return jwt.encode(
        {
            "sub": "golden-principal",
            "iss": issuer,
            "aud": AUDIENCE,
            "exp": expiration,
        },
        private_key_pem(private_key),
        algorithm="RS256",
    )


def outcome(token):
    try:
        get_current_principal(token)
    except HTTPException:
        return {"valid": False}

    claims = jwt.decode(
        token,
        idp.get_public_key_pem(),
        algorithms=["RS256"],
        issuer=ISSUER,
        audience=AUDIENCE,
    )
    return {"valid": True, "claims": claims}


if __name__ == "__main__":
    idp_private_key = idp._private_key
    wrong_signature_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    fixtures = {
        "valid": encode_fixture(idp_private_key),
        "expired": encode_fixture(idp_private_key, expiration=1),
        "wrong_signature": encode_fixture(wrong_signature_key),
        "wrong_issuer": encode_fixture(
            idp_private_key, issuer="https://invalid-idp.example"
        ),
    }
    results = {name: outcome(token) for name, token in fixtures.items()}
    output = json.dumps(results, indent=2, sort_keys=True) + "\n"
    (ROOT / "golden" / "jwt.json").write_text(output, encoding="utf-8")
