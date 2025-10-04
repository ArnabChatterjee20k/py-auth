from ..payload import Payload
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class OAuthPayload(Payload):
    """Base OAuth payload class"""

    access_token: str | None = None
    refresh_token: str | None = None
    expires_in: int | None = None
    token_type: str | None = None
    scope: str | None = None
    metadata: dict = field(default_factory=dict)

    def validate(self) -> None:
        if not self.access_token:
            raise ValueError("Access token is required")


@dataclass
class GitHubPayload(OAuthPayload):
    """GitHub OAuth payload"""

    github_id: str | None = None
    login: str | None = None
    email: str | None = None
    name: str | None = None
    avatar_url: str | None = None
    bio: str | None = None
    company: str | None = None
    location: str | None = None
    blog: str | None = None
    twitter_username: str | None = None
    public_repos: int | None = None
    public_gists: int | None = None
    followers: int | None = None
    following: int | None = None
    created_at: str | None = None
    updated_at: str | None = None

    def validate(self) -> None:
        super().validate()
        if not self.github_id:
            raise ValueError("GitHub ID is required")


@dataclass
class GooglePayload(OAuthPayload):
    """Google OAuth payload"""

    google_id: str | None = None
    email: str | None = None
    name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    picture: str | None = None
    locale: str | None = None
    verified_email: bool | None = None
    hd: str | None = None  # hosted domain

    def validate(self) -> None:
        super().validate()
        if not self.google_id:
            raise ValueError("Google ID is required")
