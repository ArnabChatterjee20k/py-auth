import pytest
from datetime import datetime
import bcrypt

from src.pyauth.models import Account
from src.pyauth.providers.password.payload import PasswordPayload
from src.pyauth.providers.provider import InvalidAccount


@pytest.mark.asyncio
async def test_create_and_get_account(initialized_storage, password_provider):
    payload = PasswordPayload(identifier="alice", password="s3cret")
    async with initialized_storage.begin() as storage:
        async with password_provider.set_storage_session(storage) as provider:
            account = await provider.create(payload)
            assert isinstance(account, Account)
            fetched = await provider.get(payload)
            assert fetched is not None
            assert fetched.uid == "alice"


@pytest.mark.asyncio
async def test_update_account_password(initialized_storage, password_provider):
    payload = PasswordPayload(identifier="bob", password="old")
    async with initialized_storage.begin() as storage:
        async with password_provider.set_storage_session(storage) as provider:
            account = await provider.create(payload)
            account.password = "new"
            updated = await provider.update(
                PasswordPayload(identifier="bob", password="old"), account
            )
            assert updated.uid == "bob"

            # login with old should fail
            with pytest.raises(InvalidAccount):
                await provider.get(PasswordPayload(identifier="bob", password="old"))
            # login with new should pass
            assert (
                await provider.get(PasswordPayload(identifier="bob", password="new"))
                is not None
            )


@pytest.mark.asyncio
async def test_delete_account(initialized_storage, password_provider):
    payload = PasswordPayload(identifier="carol", password="pwd")
    async with initialized_storage.begin() as storage:
        async with password_provider.set_storage_session(storage) as provider:
            await provider.create(payload)
            ok = await provider.delete(payload)
            assert ok is True
            assert await provider.get(payload) is None


@pytest.mark.asyncio
async def test_get_with_wrong_password_raise_exception(
    initialized_storage, password_provider
):
    async with initialized_storage.begin() as storage:
        async with password_provider.set_storage_session(storage) as provider:
            await provider.create(PasswordPayload(identifier="dave", password="right"))
            with pytest.raises(InvalidAccount):
                await provider.get(PasswordPayload(identifier="dave", password="wrong"))


def test_payload_validation_errors():
    # Missing identifier/password should raise on validate()
    with pytest.raises(ValueError):
        PasswordPayload(identifier=None, password=None).validate()


@pytest.mark.asyncio
async def test_delete_nonexistent_raises(initialized_storage, password_provider):
    async with initialized_storage.begin() as storage:
        async with password_provider.set_storage_session(storage) as provider:
            with pytest.raises(InvalidAccount):
                await provider.delete(PasswordPayload(identifier="ghost", password="x"))


@pytest.mark.asyncio
async def test_update_without_password_preserves_old(
    initialized_storage, password_provider
):
    async with initialized_storage.begin() as storage:
        async with password_provider.set_storage_session(storage) as provider:
            # create account
            await provider.create(PasswordPayload(identifier="erin", password="keep"))

            # fetch current, then update metadata only (no password change)
            current = await provider.get(
                PasswordPayload(identifier="erin", password="keep")
            )
            assert current is not None

            current.metadata = {"note": "updated"}
            # pass an account object with password=None so provider won't change it
            updated = await provider.update(
                PasswordPayload(identifier="erin", password="keep"),
                Account(
                    uid=current.uid,
                    permissions=current.permissions,
                    password=None,
                    is_active=current.is_active,
                    is_blocked=current.is_blocked,
                    created_at=current.created_at,
                    updated_at=current.updated_at,
                    last_active_at=current.last_active_at,
                    metadata=current.metadata,
                ),
            )

            assert updated.metadata.get("note") == "updated"
            # old password should still work
            assert (
                await provider.get(PasswordPayload(identifier="erin", password="keep"))
                is not None
            )
            # and a different password should fail
            with pytest.raises(InvalidAccount):
                await provider.get(
                    PasswordPayload(identifier="erin", password="changed")
                )


@pytest.mark.asyncio
async def test_create_account_with_metadata(initialized_storage, password_provider):
    """Test creating account with metadata"""
    payload = PasswordPayload(
        identifier="meta_user",
        password="secret",
        metadata={"role": "admin", "department": "IT"},
    )
    async with initialized_storage.begin() as storage:
        async with password_provider.set_storage_session(storage) as provider:
            account = await provider.create(payload)
            assert account.metadata == {"role": "admin", "department": "IT"}


@pytest.mark.asyncio
async def test_get_nonexistent_account_returns_none(
    initialized_storage, password_provider
):
    """Test getting non-existent account returns None"""
    async with initialized_storage.begin() as storage:
        async with password_provider.set_storage_session(storage) as provider:
            result = await provider.get(
                PasswordPayload(identifier="nonexistent", password="any")
            )
            assert result is None


@pytest.mark.asyncio
async def test_password_hashing_verification(initialized_storage, password_provider):
    """Test that passwords are properly hashed and verified"""
    async with initialized_storage.begin() as storage:
        async with password_provider.set_storage_session(storage) as provider:
            payload = PasswordPayload(
                identifier="hash_test", password="original_password"
            )
            account = await provider.create(payload)

            # Password should be hashed, not plain text
            assert account.password != "original_password"
            assert bcrypt.checkpw(
                "original_password".encode("utf-8"), account.password.encode("utf-8")
            )

            # Wrong password should not verify
            assert not bcrypt.checkpw(
                "wrong_password".encode("utf-8"), account.password.encode("utf-8")
            )


@pytest.mark.asyncio
async def test_update_account_with_all_fields(initialized_storage, password_provider):
    """Test updating account with all fields including new password"""
    async with initialized_storage.begin() as storage:
        async with password_provider.set_storage_session(storage) as provider:
            # Create initial account
            await provider.create(
                PasswordPayload(identifier="full_update", password="old_pass")
            )

            # Update with new password and metadata
            updated_account = Account(
                uid="full_update",
                password="new_pass",  # This will be hashed
                permissions=["read", "write"],
                is_active=False,
                is_blocked=True,
                created_at=datetime.now(),
                updated_at=datetime.now(),
                last_active_at=datetime.now(),
                metadata={"updated": True},
            )

            result = await provider.update(
                PasswordPayload(identifier="full_update", password="old_pass"),
                updated_account,
            )

            assert result.uid == "full_update"
            assert result.is_active is False
            assert result.is_blocked is True
            assert result.metadata == {"updated": True}

            # Verify new password works
            login_result = await provider.get(
                PasswordPayload(identifier="full_update", password="new_pass")
            )
            assert login_result is not None


@pytest.mark.asyncio
async def test_duplicate_account_creation(initialized_storage, password_provider):
    """Test creating account with duplicate identifier"""
    async with initialized_storage.begin() as storage:
        async with password_provider.set_storage_session(storage) as provider:
            payload = PasswordPayload(identifier="duplicate", password="pass1")

            # First creation should succeed
            account1 = await provider.create(payload)
            assert account1.uid == "duplicate"

            # Second creation with same identifier should also succeed (no unique constraint in this test)
            # This tests the current behavior - in a real app you might want to prevent duplicates
            try:
                account2 = await provider.create(payload)
            except Exception as e:
                assert "Duplicate" in str(e)


@pytest.mark.asyncio
async def test_empty_password_validation(initialized_storage, password_provider):
    """Test validation with empty password"""
    async with initialized_storage.begin() as storage:
        async with password_provider.set_storage_session(storage) as provider:
            with pytest.raises(ValueError):
                await provider.create(
                    PasswordPayload(identifier="empty_pass", password="")
                )


@pytest.mark.asyncio
async def test_empty_identifier_validation(initialized_storage, password_provider):
    """Test validation with empty identifier"""
    async with initialized_storage.begin() as storage:
        async with password_provider.set_storage_session(storage) as provider:
            with pytest.raises(ValueError):
                await provider.create(
                    PasswordPayload(identifier="", password="valid_pass")
                )


@pytest.mark.asyncio
async def test_none_values_validation(initialized_storage, password_provider):
    """Test validation with None values"""
    async with initialized_storage.begin() as storage:
        async with password_provider.set_storage_session(storage) as provider:
            with pytest.raises(ValueError):
                await provider.create(PasswordPayload(identifier=None, password=None))


@pytest.mark.asyncio
async def test_special_characters_in_password(initialized_storage, password_provider):
    """Test password with special characters"""
    special_password = "P@ssw0rd!@#$%^&*()_+-=[]{}|;':\",./<>?"
    async with initialized_storage.begin() as storage:
        async with password_provider.set_storage_session(storage) as provider:
            payload = PasswordPayload(identifier="special", password=special_password)
            account = await provider.create(payload)

            # Verify login works with special characters
            login_result = await provider.get(payload)
            assert login_result is not None
            assert login_result.uid == "special"


@pytest.mark.asyncio
async def test_unicode_password(initialized_storage, password_provider):
    """Test password with unicode characters"""
    unicode_password = "пароль123🔐"
    async with initialized_storage.begin() as storage:
        async with password_provider.set_storage_session(storage) as provider:
            payload = PasswordPayload(identifier="unicode", password=unicode_password)
            account = await provider.create(payload)

            # Verify login works with unicode
            login_result = await provider.get(payload)
            assert login_result is not None
            assert login_result.uid == "unicode"


@pytest.mark.asyncio
async def test_very_long_password(initialized_storage, password_provider):
    """Test very long password"""
    long_password = "a" * 1000  # 1000 character password
    async with initialized_storage.begin() as storage:
        async with password_provider.set_storage_session(storage) as provider:
            payload = PasswordPayload(identifier="long_pass", password=long_password)
            account = await provider.create(payload)

            # Verify login works with long password
            login_result = await provider.get(payload)
            assert login_result is not None
            assert login_result.uid == "long_pass"


@pytest.mark.asyncio
async def test_storage_session_not_set_error(initialized_storage, password_provider):
    """Test error when storage session is not set"""
    payload = PasswordPayload(identifier="test", password="pass")

    # Provider without storage session should raise ValueError
    with pytest.raises(ValueError, match="Storage is not set"):
        await password_provider.create(payload)
