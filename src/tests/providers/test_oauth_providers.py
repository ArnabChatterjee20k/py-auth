"""
Tests for OAuth providers (GitHub and Google)
"""

import pytest
from unittest.mock import AsyncMock, patch
from src.pyauth.providers.oauth import (
    GitHubProvider,
    GoogleProvider,
    GitHubPayload,
    GooglePayload,
)
from src.pyauth.models import Account


class TestGitHubProvider:
    """Test GitHub OAuth provider"""

    def setup_method(self):
        self.provider = GitHubProvider(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="http://localhost:8000/callback",
        )

    def test_authorization_url_generation(self):
        """Test GitHub authorization URL generation"""
        url = self.provider.get_authorization_url(state="test_state")
        assert "github.com/login/oauth/authorize" in url
        assert "client_id=test_client_id" in url
        assert "redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback" in url
        assert "state=test_state" in url

    def test_github_payload_validation(self):
        """Test GitHub payload validation"""
        # Valid payload
        valid_payload = GitHubPayload(
            access_token="test_token",
            github_id="12345",
            login="testuser",
            email="test@example.com",
        )
        assert self.provider.validate_payload(valid_payload) is True

        # Invalid payload - missing access token
        invalid_payload = GitHubPayload(
            github_id="12345", login="testuser", email="test@example.com"
        )
        assert self.provider.validate_payload(invalid_payload) is False

        # Invalid payload - missing GitHub ID
        invalid_payload2 = GitHubPayload(
            access_token="test_token", login="testuser", email="test@example.com"
        )
        assert self.provider.validate_payload(invalid_payload2) is False

    @pytest.mark.asyncio
    async def test_exchange_code_for_token(self):
        """Test exchanging authorization code for access token"""
        mock_response = {
            "access_token": "test_access_token",
            "token_type": "bearer",
            "scope": "user:email",
        }

        with patch.object(self.provider, "_make_request", return_value=mock_response):
            result = await self.provider.exchange_code_for_token("test_code")
            assert result == mock_response

    @pytest.mark.asyncio
    async def test_get_user_info(self):
        """Test getting user information from GitHub API"""
        mock_response = {
            "id": 12345,
            "login": "testuser",
            "name": "Test User",
            "email": "test@example.com",
            "avatar_url": "https://avatars.githubusercontent.com/u/12345",
        }

        with patch.object(self.provider, "_make_request", return_value=mock_response):
            result = await self.provider.get_user_info("test_access_token")
            assert result == mock_response

    def test_get_account_from_oauth_data(self):
        """Test creating Account from GitHub OAuth data"""
        payload = GitHubPayload(
            access_token="test_token",
            github_id="12345",
            login="testuser",
            email="test@example.com",
            name="Test User",
            avatar_url="https://avatars.githubusercontent.com/u/12345",
        )

        account = self.provider._get_account_from_oauth_data(payload)

        assert isinstance(account, Account)
        assert account.uid == "github_12345"
        assert account.metadata["name"] == "Test User"
        assert account.metadata["email"] == "test@example.com"
        assert account.metadata["provider"] == "github"
        assert account.metadata["github_id"] == "12345"
        assert account.metadata["login"] == "testuser"


class TestGoogleProvider:
    """Test Google OAuth provider"""

    def setup_method(self):
        self.provider = GoogleProvider(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="http://localhost:8000/callback",
        )

    def test_authorization_url_generation(self):
        """Test Google authorization URL generation"""
        url = self.provider.get_authorization_url(state="test_state")
        assert "accounts.google.com/o/oauth2/v2/auth" in url
        assert "client_id=test_client_id" in url
        assert "redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback" in url
        assert "scope=openid+email+profile" in url
        assert "response_type=code" in url
        assert "state=test_state" in url

    def test_google_payload_validation(self):
        """Test Google payload validation"""
        # Valid payload
        valid_payload = GooglePayload(
            access_token="test_token",
            google_id="12345",
            email="test@example.com",
            name="Test User",
        )
        assert self.provider.validate_payload(valid_payload) is True

        # Invalid payload - missing access token
        invalid_payload = GooglePayload(
            google_id="12345", email="test@example.com", name="Test User"
        )
        assert self.provider.validate_payload(invalid_payload) is False

        # Invalid payload - missing Google ID
        invalid_payload2 = GooglePayload(
            access_token="test_token", email="test@example.com", name="Test User"
        )
        assert self.provider.validate_payload(invalid_payload2) is False

    @pytest.mark.asyncio
    async def test_exchange_code_for_token(self):
        """Test exchanging authorization code for access token"""
        mock_response = {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        with patch.object(self.provider, "_make_request", return_value=mock_response):
            result = await self.provider.exchange_code_for_token("test_code")
            assert result == mock_response

    @pytest.mark.asyncio
    async def test_get_user_info(self):
        """Test getting user information from Google API"""
        mock_response = {
            "id": "12345",
            "email": "test@example.com",
            "name": "Test User",
            "given_name": "Test",
            "family_name": "User",
            "picture": "https://lh3.googleusercontent.com/a/test",
            "verified_email": True,
        }

        with patch.object(self.provider, "_make_request", return_value=mock_response):
            result = await self.provider.get_user_info("test_access_token")
            assert result == mock_response

    def test_get_account_from_oauth_data(self):
        """Test creating Account from Google OAuth data"""
        payload = GooglePayload(
            access_token="test_token",
            google_id="12345",
            email="test@example.com",
            name="Test User",
            given_name="Test",
            family_name="User",
            picture="https://lh3.googleusercontent.com/a/test",
        )

        account = self.provider._get_account_from_oauth_data(payload)

        assert isinstance(account, Account)
        assert account.uid == "google_12345"
        assert account.metadata["name"] == "Test User"
        assert account.metadata["email"] == "test@example.com"
        assert account.metadata["provider"] == "google"
        assert account.metadata["google_id"] == "12345"
        assert account.metadata["given_name"] == "Test"
        assert account.metadata["family_name"] == "User"
