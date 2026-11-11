import os
import re
import threading
import time
from typing import Any

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

FIREBASE_CERTIFICATES_URL = (
    "https://www.googleapis.com/robot/v1/metadata/x509/"
    "securetoken@system.gserviceaccount.com"
)
FIREBASE_PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID", "").strip()
if not FIREBASE_PROJECT_ID:
    raise RuntimeError("FIREBASE_PROJECT_ID must be set")

FIREBASE_ISSUER = f"https://securetoken.google.com/{FIREBASE_PROJECT_ID}"
FIREBASE_AUDIENCE = FIREBASE_PROJECT_ID
_CERTIFICATE_CACHE_MAX_AGE = 3600
_UNKNOWN_KID_REFRESH_INTERVAL = 60

_certificate_lock = threading.Lock()
_certificates: dict[str, rsa.RSAPublicKey] = {}
_certificates_expire_at = 0.0
_last_certificate_fetch_at = 0.0


class FirebaseCertificateError(ValueError):
    pass


def _read_certificates() -> tuple[dict[str, rsa.RSAPublicKey], int]:
    response = requests.get(
        FIREBASE_CERTIFICATES_URL,
        timeout=(3.05, 5),
        allow_redirects=False,
    )
    if response.status_code != 200:
        raise FirebaseCertificateError(
            f"Firebase certificate endpoint returned HTTP {response.status_code}"
        )

    try:
        certificate_pems = response.json()
    except requests.exceptions.JSONDecodeError as error:
        raise FirebaseCertificateError(
            "Firebase certificate endpoint returned invalid JSON"
        ) from error

    if not isinstance(certificate_pems, dict) or not certificate_pems:
        raise FirebaseCertificateError(
            "Firebase certificate endpoint returned no certificates"
        )

    now = time.time()
    parsed_certificates: dict[str, rsa.RSAPublicKey] = {}
    for key_id, certificate_pem in certificate_pems.items():
        if not isinstance(key_id, str) or not isinstance(certificate_pem, str):
            raise FirebaseCertificateError(
                "Firebase certificate response has an invalid entry"
            )
        try:
            certificate = x509.load_pem_x509_certificate(
                certificate_pem.encode("ascii")
            )
            public_key = certificate.public_key()
        except (UnicodeEncodeError, ValueError) as error:
            raise FirebaseCertificateError(
                "Firebase certificate response contains an invalid x509 certificate"
            ) from error
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise FirebaseCertificateError(
                "Firebase signing certificate does not contain an RSA key"
            )
        if not (
            certificate.not_valid_before_utc.timestamp()
            <= now
            <= certificate.not_valid_after_utc.timestamp()
        ):
            continue
        parsed_certificates[key_id] = public_key

    if not parsed_certificates:
        raise FirebaseCertificateError(
            "Firebase certificate response contains no currently valid certificates"
        )

    cache_control = response.headers.get("Cache-Control", "")
    max_age_match = re.search(r"(?:^|,)\s*max-age=(\d+)", cache_control, re.I)
    max_age = (
        min(int(max_age_match.group(1)), _CERTIFICATE_CACHE_MAX_AGE)
        if max_age_match
        else 300
    )
    return parsed_certificates, max_age


def _get_certificate(key_id: str) -> rsa.RSAPublicKey:
    global _certificates, _certificates_expire_at, _last_certificate_fetch_at

    now = time.monotonic()
    with _certificate_lock:
        refresh_due = not _certificates or now >= _certificates_expire_at
        if (
            not refresh_due
            and key_id not in _certificates
            and now - _last_certificate_fetch_at >= _UNKNOWN_KID_REFRESH_INTERVAL
        ):
            refresh_due = True
        if refresh_due:
            _certificates, max_age = _read_certificates()
            _last_certificate_fetch_at = now
            _certificates_expire_at = now + max_age

        public_key = _certificates.get(key_id)
        if public_key is None:
            raise jwt.InvalidKeyError("No matching Firebase signing certificate")
        return public_key


def get_current_principal(token: str = Depends(oauth2_scheme)) -> str:
    """Validate a Firebase ID token and return its verified subject."""
    try:
        header: dict[str, Any] = jwt.get_unverified_header(token)
        key_id = header.get("kid")
        if header.get("alg") != "RS256" or not isinstance(key_id, str) or not key_id:
            raise jwt.InvalidTokenError("Unsupported Firebase token header")
    except jwt.PyJWTError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or malformed token",
        ) from error

    try:
        public_key = _get_certificate(key_id)
    except requests.RequestException as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Firebase signing certificates are unavailable",
        ) from error
    except FirebaseCertificateError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Firebase signing certificates are invalid",
        ) from error
    except jwt.PyJWTError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or malformed token",
        ) from error

    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=FIREBASE_ISSUER,
            audience=FIREBASE_AUDIENCE,
            options={"require": ["auth_time", "exp", "iat", "sub"]},
        )
    except jwt.ExpiredSignatureError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        ) from error
    except jwt.InvalidIssuerError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token issuer",
        ) from error
    except jwt.InvalidAudienceError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token audience",
        ) from error
    except jwt.PyJWTError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or malformed token",
        ) from error

    principal_id = payload.get("sub")
    if not isinstance(principal_id, str) or not principal_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload: missing 'sub' claim",
        )
    return principal_id
