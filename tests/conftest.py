import datetime
import os

import jwt
import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

os.environ["FIREBASE_PROJECT_ID"] = "asg-test-project"

PROJECT_ID = "asg-test-project"
KEY_ID = "firebase-test-key"
CERTIFICATES_URL = (
    "https://www.googleapis.com/robot/v1/metadata/x509/"
    "securetoken@system.gserviceaccount.com"
)


@pytest.fixture(scope="session")
def firebase_signing_material():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Firebase test key")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    certificate_pem = certificate.public_bytes(
        encoding=Encoding.PEM
    ).decode("ascii")
    return private_key, certificate_pem


@pytest.fixture(autouse=True)
def mock_firebase_certificates(monkeypatch, firebase_signing_material):
    _, certificate_pem = firebase_signing_material

    class MockResponse:
        status_code = 200
        headers = {"Cache-Control": "public, max-age=3600"}

        def json(self):
            return {KEY_ID: certificate_pem}

    def mock_get(url, **kwargs):
        if url != CERTIFICATES_URL:
            raise AssertionError(f"Unexpected certificate URL: {url}")
        if kwargs.get("allow_redirects") is not False:
            raise AssertionError("Certificate requests must not follow redirects")
        return MockResponse()

    monkeypatch.setattr(requests, "get", mock_get)


@pytest.fixture
def firebase_token(firebase_signing_material):
    private_key, _ = firebase_signing_material

    def _create(
        *,
        subject="firebase-user-123",
        issuer=f"https://securetoken.google.com/{PROJECT_ID}",
        audience=PROJECT_ID,
        expiration=None,
    ):
        issued_at = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        if expiration is None:
            expiration = (
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(hours=1)
            )
        return jwt.encode(
            {
                "sub": subject,
                "iss": issuer,
                "aud": audience,
                "iat": issued_at,
                "auth_time": issued_at,
                "exp": expiration,
            },
            private_key,
            algorithm="RS256",
            headers={"kid": KEY_ID},
        )

    return _create
