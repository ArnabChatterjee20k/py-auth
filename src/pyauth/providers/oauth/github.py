import urllib.parse
from typing import Dict, Any
from .oauth_provider import OAuthProvider
from .payload import GitHubPayload
from ...models import Account


class GitHubProvider(OAuthProvider):
    """GitHub OAuth provider implementation"""

    AUTHORIZATION_URL = "https://github.com/login/oauth/authorize"
    TOKEN_URL = "https://github.com/login/oauth/access_token"
    USER_INFO_URL = "https://api.github.com/user"
    USER_EMAILS_URL = "https://api.github.com/user/emails"

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        super().__init__(client_id, client_secret, redirect_uri)

    def get_authorization_url(self, state: str = None) -> str:
        """Generate GitHub OAuth authorization URL"""
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "read:user user:email",
        }
        if state:
            params["state"] = state

        return f"{self.AUTHORIZATION_URL}?{urllib.parse.urlencode(params)}"

    async def exchange_code_for_token(self, code: str) -> Dict[str, Any]:
        """Exchange authorization code for access token"""
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
        }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        return await self._make_request(self.TOKEN_URL, headers=headers, data=data)

    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from GitHub API"""
        headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json",
        }
        user_info = await self._make_request(self.USER_INFO_URL, headers=headers)

        # Some GitHub accounts have private emails, fetch from /user/emails as fallback
        email = user_info.get("email")
        if not email:
            try:
                emails = await self._make_request(self.USER_EMAILS_URL, headers=headers)
                if isinstance(emails, list) and emails:
                    primary_verified = next(
                        (e for e in emails if e.get("primary") and e.get("verified")),
                        None,
                    )
                    verified_any = next((e for e in emails if e.get("verified")), None)
                    chosen = primary_verified or verified_any or emails[0]
                    user_info["email"] = chosen.get("email")
            except Exception:
                # If email fetch fails, keep email as None
                pass

        return user_info

    def _get_provider_id_field(self) -> str:
        return "github_id"

    def _get_prefixed_uid(self, payload: GitHubPayload) -> str:
        """Return the prefixed UID for the GitHub account"""
        return f"github_{payload.github_id}"

    def _get_account_from_oauth_data(self, payload: GitHubPayload) -> Account:
        """Create Account object from GitHub OAuth data"""
        # Use GitHub ID as the primary identifier
        uid = f"github_{payload.github_id}"

        # Build metadata with GitHub-specific information including name and email
        metadata = {
            "provider": "github",
            "github_id": payload.github_id,
            "name": payload.name,
            "email": payload.email,
            "login": payload.login,
            "avatar_url": payload.avatar_url,
            "bio": payload.bio,
            "company": payload.company,
            "location": payload.location,
            "blog": payload.blog,
            "twitter_username": payload.twitter_username,
            "public_repos": payload.public_repos,
            "public_gists": payload.public_gists,
            "followers": payload.followers,
            "following": payload.following,
            "created_at": payload.created_at,
            "updated_at": payload.updated_at,
            "access_token": payload.access_token,
            "refresh_token": payload.refresh_token,
            "expires_in": payload.expires_in,
            "token_type": payload.token_type,
            "scope": payload.scope,
        }

        # Merge with any additional metadata from payload
        metadata.update(payload.metadata)

        return Account(
            uid=uid,
            metadata=metadata,
            permissions=payload.permissions,
        )

    def validate_payload(self, payload: GitHubPayload) -> bool:
        """Validate GitHub OAuth payload"""
        try:
            payload.validate()
            return True
        except ValueError:
            return False

    async def authenticate(self, code: str) -> Account:
        """Complete OAuth flow and return Account object"""
        # Skip OAuth flow in admin mode - just return None or handle differently
        if self._admin_operation:
            # In admin mode, we can't complete OAuth flow without user interaction
            # This method should not be called in admin mode
            raise ValueError("OAuth authentication cannot be performed in admin mode")

        # Exchange code for token
        token_data = await self.exchange_code_for_token(code)

        # Get user info
        user_info = await self.get_user_info(token_data["access_token"])

        # Create payload
        payload = GitHubPayload(
            access_token=token_data["access_token"],
            refresh_token=token_data.get("refresh_token"),
            expires_in=token_data.get("expires_in"),
            token_type=token_data.get("token_type"),
            scope=token_data.get("scope"),
            github_id=str(user_info["id"]),
            login=user_info.get("login"),
            email=user_info.get("email"),
            name=user_info.get("name"),
            avatar_url=user_info.get("avatar_url"),
            bio=user_info.get("bio"),
            company=user_info.get("company"),
            location=user_info.get("location"),
            blog=user_info.get("blog"),
            twitter_username=user_info.get("twitter_username"),
            public_repos=user_info.get("public_repos"),
            public_gists=user_info.get("public_gists"),
            followers=user_info.get("followers"),
            following=user_info.get("following"),
            created_at=user_info.get("created_at"),
            updated_at=user_info.get("updated_at"),
        )

        # Check if account exists
        existing_account = await self.get(payload)
        if existing_account:
            # Update existing account
            return await self.update(payload, existing_account)
        else:
            # Create new account
            return await self.create(payload)
