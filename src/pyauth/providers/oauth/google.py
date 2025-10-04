import urllib.parse
from typing import Dict, Any
from .oauth_provider import OAuthProvider
from .payload import GooglePayload
from ...models import Account


class GoogleProvider(OAuthProvider):
    """Google OAuth provider implementation"""

    AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USER_INFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        super().__init__(client_id, client_secret, redirect_uri)

    def get_authorization_url(self, state: str = None) -> str:
        """Generate Google OAuth authorization URL"""
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "prompt": "consent",
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
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
        }

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        return await self._make_request(self.TOKEN_URL, headers=headers, data=data)

    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from Google API"""
        headers = {
            "Authorization": f"Bearer {access_token}",
        }

        return await self._make_request(self.USER_INFO_URL, headers=headers)

    def _get_provider_id_field(self) -> str:
        return "google_id"

    def _get_prefixed_uid(self, payload: GooglePayload) -> str:
        """Return the prefixed UID for the Google account"""
        return f"google_{payload.google_id}"

    def _get_account_from_oauth_data(self, payload: GooglePayload) -> Account:
        """Create Account object from Google OAuth data"""
        # Use Google ID as the primary identifier
        uid = f"google_{payload.google_id}"

        # Build metadata with Google-specific information including name and email
        metadata = {
            "provider": "google",
            "google_id": payload.google_id,
            "name": payload.name,
            "email": payload.email,
            "given_name": payload.given_name,
            "family_name": payload.family_name,
            "picture": payload.picture,
            "locale": payload.locale,
            "verified_email": payload.verified_email,
            "hd": payload.hd,
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

    def validate_payload(self, payload: GooglePayload) -> bool:
        """Validate Google OAuth payload"""
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
        payload = GooglePayload(
            access_token=token_data["access_token"],
            refresh_token=token_data.get("refresh_token"),
            expires_in=token_data.get("expires_in"),
            token_type=token_data.get("token_type"),
            scope=token_data.get("scope"),
            google_id=user_info["id"],
            email=user_info.get("email"),
            name=user_info.get("name"),
            given_name=user_info.get("given_name"),
            family_name=user_info.get("family_name"),
            picture=user_info.get("picture"),
            locale=user_info.get("locale"),
            verified_email=user_info.get("verified_email"),
            hd=user_info.get("hd"),
        )

        # Check if account exists
        existing_account = await self.get(payload)
        if existing_account:
            # Update existing account
            return await self.update(payload, existing_account)
        else:
            # Create new account
            return await self.create(payload)
