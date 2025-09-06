import jwt
from datetime import datetime, timedelta
from typing import Optional


class Token:
    def __init__(
        self,
        secret: str,
    ):
        self._secret = secret
        self._algo = "HS256"

    def create(
        self,
        payload: dict,
        expires_at: Optional[datetime] = None,
        not_before: Optional[datetime] = None,
    ):
        claims = payload.copy()
        if not_before:
            claims["nbf"] = int(not_before.timestamp())
        if expires_at:
            claims["exp"] = int(expires_at.timestamp())
        # issues_at
        claims["iat"] = int(datetime.now().timestamp())
        return jwt.encode(claims, self._secret, algorithm=self._algo)

    def extract(self, token: str) -> dict:
        return jwt.decode(
            token,
            self._secret,
            algorithms=[self._algo],
            options={
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
            },
        )

    def refresh(
        self,
        token: str,
        expires_at: Optional[datetime] = None,
        not_before: Optional[datetime] = None,
    ):
        claims = self.extract(token)
        claims.pop("iat", None)
        claims.pop("nbf", None)
        claims.pop("exp", None)

        return self.create(claims, expires_at, not_before)

    @staticmethod
    def days(after: int):
        return datetime.now() + timedelta(days=after)

    @staticmethod
    def hours(after: int):
        return datetime.now() + timedelta(hours=after)

    @staticmethod
    def seconds(after: int):
        datetime.now + timedelta(seconds=after)
