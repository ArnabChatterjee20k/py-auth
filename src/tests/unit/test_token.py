import pytest
import jwt
import time
from datetime import datetime, timedelta
from src.pyauth.models import Token

SECRET = "mysecret"


@pytest.fixture
def token_util():
    return Token(secret=SECRET)


def test_create_and_extract(token_util):
    payload = {"user_id": 123}
    expires = datetime.now() + timedelta(hours=1)
    not_before = datetime.now() - timedelta(minutes=5)

    token = token_util.create(payload, expires_at=expires, not_before=not_before)
    decoded = token_util.extract(token)

    assert decoded["user_id"] == 123
    assert "iat" in decoded
    assert "exp" in decoded
    assert "nbf" in decoded


def test_refresh(token_util):
    payload = {"role": "admin"}
    expires = datetime.now() + timedelta(minutes=30)
    token = token_util.create(payload, expires_at=expires)

    decoded_old = token_util.extract(token)
    old_iat = decoded_old["iat"]

    new_expires = datetime.now() + timedelta(hours=1)
    time.sleep(0.001)
    refreshed = token_util.refresh(token, expires_at=new_expires)
    decoded_new = token_util.extract(refreshed)

    assert decoded_new["role"] == "admin"
    assert decoded_new["iat"] != old_iat  # refreshed has new iat
    assert decoded_new["exp"] == new_expires.timestamp()


def test_expired_token(token_util):
    payload = {"user": "alice"}
    expired = datetime.now() - timedelta(seconds=1)
    token = token_util.create(payload, expires_at=expired)

    with pytest.raises(jwt.ExpiredSignatureError):
        token_util.extract(token)


def test_helpers(token_util):
    d = token_util.days(1)
    h = token_util.hours(1)
    s = token_util.seconds(10)

    now = datetime.now()
    assert (d - now).days == 1
    assert (h - now).seconds // 3600 == 1
    assert abs((s - now).seconds - 10) <= 1  # allow 1 sec drift
