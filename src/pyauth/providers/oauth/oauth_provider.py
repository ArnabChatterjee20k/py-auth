from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime
import aiohttp
import asyncio
from ..provider import Provider, InvalidAccount
from ..payload import Payload
from ...models import Account


class OAuthProvider(Provider, ABC):
    """Base OAuth provider class with common OAuth functionality"""

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

    @abstractmethod
    def get_authorization_url(self, state: str = None) -> str:
        """Generate the OAuth authorization URL"""
        pass

    @abstractmethod
    async def exchange_code_for_token(self, code: str) -> Dict[str, Any]:
        """Exchange authorization code for access token"""
        pass

    @abstractmethod
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from the OAuth provider"""
        pass

    async def create(self, payload: Payload) -> Account:
        """Create account from OAuth payload"""
        self.validate_payload(payload)
        account = self._get_account_from_oauth_data(payload)
        storage = self.get_storage_session()
        return await storage.create(account)

    async def get(self, payload: Payload) -> Account | None:
        """Get account by OAuth provider ID"""
        self.validate_payload(payload)
        storage = self.get_storage_session()

        # Use the prefixed UID for filtering instead of provider ID field
        uid = self._get_prefixed_uid(payload)
        account = await storage.get(Account, filters={"uid": uid})

        if not account:
            return None

        # In admin mode, skip any OAuth-specific verification
        # Just return the account if found
        if self._admin_operation:
            return account

        # For non-admin mode, we could add additional verification here
        # For now, just return the account
        return account

    async def update(self, payload: Payload, account: Account) -> Account:
        """Update account with new OAuth data"""
        # Skip user verification in admin mode
        if not self._admin_operation:
            # Verify the account exists and is valid
            existing_account = await self.get(payload)
            if not existing_account:
                raise InvalidAccount("Account not found")

        storage = self.get_storage_session()
        updates = self._get_account_updates(payload, account)
        updated_account = await storage.update(Account, {"uid": account.uid}, updates)
        return updated_account

    async def delete(self, payload: Payload) -> bool:
        """Delete account"""
        # Skip account verification in admin mode
        if not self._admin_operation:
            account = await self.get(payload)
            if not account:
                raise InvalidAccount("Account not found")
        else:
            # In admin mode, get account directly by prefixed UID
            storage = self.get_storage_session()
            uid = self._get_prefixed_uid(payload)
            account = await storage.get(Account, filters={"uid": uid})
            if not account:
                raise InvalidAccount("Account not found")

        storage = self.get_storage_session()
        result = await storage.delete(Account, {"uid": account.uid})
        return bool(result)

    @abstractmethod
    def _get_provider_id_field(self) -> str:
        """Return the field name for the provider-specific ID"""
        pass

    @abstractmethod
    def _get_prefixed_uid(self, payload: Payload) -> str:
        """Return the prefixed UID for the account (e.g., 'github_12345')"""
        pass

    @abstractmethod
    def _get_account_from_oauth_data(self, payload: Payload) -> Account:
        """Create Account object from OAuth payload"""
        pass

    def _get_account_updates(
        self, payload: Payload, account: Account
    ) -> Dict[str, Any]:
        """Get account updates from OAuth payload and provided Account object.
        Prioritize explicit fields on the provided Account (timestamps, flags),
        and merge OAuth-derived metadata fields for profile data.
        """
        # Start with updates from the provided Account object (excluding immutable keys)
        updates: Dict[str, Any] = {}

        if isinstance(account, Account):
            base = account.to_dict(exclude=["uid", "created_at"]) or {}
            # Ensure updated_at is bumped
            base["updated_at"] = datetime.now()
            updates.update(base)

        metadata: Dict[str, Any] = {}
        if isinstance(account, Account) and account.metadata:
            metadata.update(account.metadata)

        # If payload carries a metadata dict, merge it in directly
        if hasattr(payload, "metadata") and getattr(payload, "metadata") is not None:
            metadata.update(getattr(payload, "metadata"))
        else:
            # Derive useful profile fields from the payload attributes
            for key in (
                "name",
                "email",
                "login",
                "avatar_url",
                "bio",
                "company",
                "location",
                "blog",
                "twitter_username",
                "public_repos",
                "public_gists",
                "followers",
                "following",
                "created_at",
                "updated_at",
            ):
                if hasattr(payload, key) and getattr(payload, key) is not None:
                    metadata[key] = getattr(payload, key)

            # Include provider-specific id field
            provider_id_field = self._get_provider_id_field()
            if hasattr(payload, provider_id_field):
                metadata[provider_id_field] = getattr(payload, provider_id_field)

        if metadata:
            updates["metadata"] = metadata

        return updates

    async def _make_request(
        self, url: str, headers: Dict[str, str] = None, data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Make HTTP request to OAuth provider"""
        async with aiohttp.ClientSession() as session:
            if data:
                async with session.post(url, headers=headers, data=data) as response:
                    response.raise_for_status()
                    return await response.json()
            else:
                async with session.get(url, headers=headers) as response:
                    response.raise_for_status()
                    return await response.json()
