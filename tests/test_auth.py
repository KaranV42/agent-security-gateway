import datetime
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

from asg.auth import get_current_principal


def test_valid_firebase_token_returns_subject(firebase_token):
    assert get_current_principal(firebase_token()) == "firebase-user-123"


def test_expired_firebase_token_is_rejected(firebase_token):
    token = firebase_token(
        expiration=datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(seconds=1)
    )

    with pytest.raises(HTTPException) as error:
        get_current_principal(token)

    assert error.value.status_code == 401
    assert error.value.detail == "Token has expired"


def test_wrong_firebase_audience_is_rejected(firebase_token):
    token = firebase_token(audience="another-project")

    with pytest.raises(HTTPException) as error:
        get_current_principal(token)

    assert error.value.status_code == 401
    assert error.value.detail == "Invalid token audience"


def test_tampered_firebase_signature_is_rejected(firebase_token):
    token = firebase_token()
    header, payload, signature = token.split(".")
    replacement = "A" if signature[0] != "A" else "B"
    tampered_token = f"{header}.{payload}.{replacement}{signature[1:]}"

    with pytest.raises(HTTPException) as error:
        get_current_principal(tampered_token)

    assert error.value.status_code == 401
    assert error.value.detail == "Invalid or malformed token"


def test_missing_firebase_project_id_fails_startup():
    environment = os.environ.copy()
    environment.pop("FIREBASE_PROJECT_ID", None)
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")

    result = subprocess.run(
        [sys.executable, "-c", "import asg.auth"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "FIREBASE_PROJECT_ID must be set" in result.stderr
