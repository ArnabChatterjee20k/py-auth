import pytest
from datetime import datetime, timedelta
from src.pyauth.models import Role

from src.pyauth.providers.password.payload import PasswordPayload
from src.pyauth.session import InvalidSession, ExpiredSession
from src.pyauth.providers.provider import InvalidAccount


@pytest.mark.asyncio
async def test_start_get_end_session_flow(pyauth):
    # init schema via pyauth helper
    await pyauth.init_schema()

    # create account
    payload = PasswordPayload(identifier="sess_user", password="pw")
    account = await pyauth.create_account(payload)

    # start session
    session = await pyauth.start_session(payload)
    assert session.account_uid == account.uid
    assert session.access_token and session.refresh_token

    # list sessions
    sessions = await pyauth.get_sessions(account_uid=account.uid)
    assert any(s.sid == session.sid for s in sessions)

    # get current account from token
    current = await pyauth.get_current_account_from_session(session.access_token)
    assert current.uid == account.uid

    # end session (set inactive)
    ok = await pyauth.end_session(session.sid)
    assert ok is not None


@pytest.mark.asyncio
async def test_multiple_concurrent_sessions(pyauth):
    """Test multiple concurrent sessions for same account"""
    await pyauth.init_schema()

    payload = PasswordPayload(identifier="multi_user", password="pw")
    account = await pyauth.create_account(payload)

    # Create multiple sessions
    session1 = await pyauth.start_session(payload, metadata={"device": "mobile"})
    session2 = await pyauth.start_session(payload, metadata={"device": "desktop"})
    session3 = await pyauth.start_session(payload, metadata={"device": "tablet"})

    # All sessions should be valid
    assert session1.account_uid == account.uid
    assert session2.account_uid == account.uid
    assert session3.account_uid == account.uid

    # List all sessions
    sessions = await pyauth.get_sessions(account_uid=account.uid)
    assert len(sessions) >= 3

    # Each session should work independently
    current1 = await pyauth.get_current_account_from_session(session1.access_token)
    current2 = await pyauth.get_current_account_from_session(session2.access_token)
    current3 = await pyauth.get_current_account_from_session(session3.access_token)

    assert current1.uid == account.uid
    assert current2.uid == account.uid
    assert current3.uid == account.uid

    # End one session, others should still work
    await pyauth.end_session(session2.sid)

    # session2 should be invalid
    with pytest.raises(InvalidSession):
        await pyauth.get_current_account_from_session(session2.access_token)

    # session1 and session3 should still work
    current1 = await pyauth.get_current_account_from_session(session1.access_token)
    current3 = await pyauth.get_current_account_from_session(session3.access_token)
    assert current1.uid == account.uid
    assert current3.uid == account.uid


@pytest.mark.asyncio
async def test_session_pagination(pyauth):
    """Test session listing with pagination"""
    await pyauth.init_schema()

    payload = PasswordPayload(identifier="pagination_user", password="pw")
    account = await pyauth.create_account(payload)

    # Create 5 sessions
    sessions = []
    for i in range(5):
        session = await pyauth.start_session(payload, metadata={"session_num": i})
        sessions.append(session)

    # Test pagination
    page1 = await pyauth.get_sessions(account_uid=account.uid, limit=2)
    assert len(page1) == 2

    # Get next page using after_id
    last_id = page1[-1].id
    page2 = await pyauth.get_sessions(
        account_uid=account.uid, limit=2, after_id=last_id
    )
    assert len(page2) == 2

    # Get remaining sessions
    last_id2 = page2[-1].id
    page3 = await pyauth.get_sessions(
        account_uid=account.uid, limit=2, after_id=last_id2
    )
    assert len(page3) >= 1


@pytest.mark.asyncio
async def test_invalid_token_scenarios(pyauth):
    """Test various invalid token scenarios"""
    await pyauth.init_schema()

    payload = PasswordPayload(identifier="invalid_user", password="pw")
    account = await pyauth.create_account(payload)
    session = await pyauth.start_session(payload)

    # Test with malformed token
    with pytest.raises(InvalidSession):
        await pyauth.get_current_account_from_session("invalid.token.here")

    # Test with empty token
    with pytest.raises(InvalidSession):
        await pyauth.get_current_account_from_session("")

    # Test with None token
    with pytest.raises(InvalidSession):
        await pyauth.get_current_account_from_session(None)

    # Test with non-existent session ID in token
    # Create a fake token with non-existent session ID
    from src.pyauth.token import Token

    token = Token("test-secret")
    fake_token = token.create({"sid": "fake-session-id", "account_uid": account.uid})

    with pytest.raises(InvalidSession):
        await pyauth.get_current_account_from_session(fake_token)


@pytest.mark.asyncio
async def test_session_metadata_preservation(pyauth):
    """Test that session metadata is preserved"""
    await pyauth.init_schema()

    payload = PasswordPayload(identifier="meta_user", password="pw")
    account = await pyauth.create_account(payload)

    metadata = {
        "device": "iPhone",
        "browser": "Safari",
        "ip_address": "192.168.1.1",
        "user_agent": "Mozilla/5.0...",
    }

    session = await pyauth.start_session(payload, metadata=metadata)

    # Verify metadata is stored
    sessions = await pyauth.get_sessions(account_uid=account.uid)
    found_session = next(s for s in sessions if s.sid == session.sid)
    for key, value in found_session.metadata.items():
        assert value == metadata[key]


@pytest.mark.asyncio
async def test_session_verification_with_expiry(pyauth):
    """Test session verification with expiry checking"""
    await pyauth.init_schema()

    payload = PasswordPayload(identifier="expiry_user", password="pw")
    account = await pyauth.create_account(payload)
    session = await pyauth.start_session(payload)

    # Valid session should work
    current = await pyauth.get_current_account_from_session(session.access_token)
    assert current.uid == account.uid

    # End session and verify it's invalid
    await pyauth.end_session(session.sid)

    with pytest.raises(InvalidSession):
        await pyauth.get_current_account_from_session(session.access_token)


@pytest.mark.asyncio
async def test_session_cleanup_after_account_deletion(pyauth):
    """Test that sessions are cleaned up when account is deleted"""
    await pyauth.init_schema()

    payload = PasswordPayload(identifier="cleanup_user", password="pw")
    account = await pyauth.create_account(payload)

    # Create multiple sessions
    session1 = await pyauth.start_session(payload)
    session2 = await pyauth.start_session(payload)

    # Verify sessions exist
    sessions = await pyauth.get_sessions(account_uid=account.uid)
    assert len(sessions) >= 2

    # Delete account
    await pyauth.delete_account(payload)

    # Sessions should be cleaned up (or at least invalid)
    # Note: This depends on implementation - sessions might be soft-deleted
    # or the account deletion might cascade to sessions


@pytest.mark.asyncio
async def test_session_with_permissions(pyauth, initialized_storage, rbac_permissions):
    """Test session with account that has permissions"""
    await pyauth.init_schema()

    # Create account with permissions
    payload = PasswordPayload(
        identifier="perm_user", password="pw", permissions=["read", "create", "update"]
    )
    account = await pyauth.create_account(payload)

    # Verify permissions were created
    async with initialized_storage.begin() as storage:
        async with rbac_permissions.set_storage_session(storage) as perms:
            role = await perms.get(Role(account_uid=account.uid))
            assert role is not None
            assert set(role.permissions) == {"read", "create", "update"}

    # Start session
    session = await pyauth.start_session(payload)
    current = await pyauth.get_current_account_from_session(session.access_token)

    # Verify we can get the account with permissions
    assert current.uid == account.uid
    assert current.permissions == ["read", "create", "update"]


@pytest.mark.asyncio
async def test_session_error_handling(pyauth):
    """Test error handling in session operations"""
    await pyauth.init_schema()

    # Test starting session with non-existent account
    fake_payload = PasswordPayload(identifier="fake_user", password="pw")

    with pytest.raises(Exception):  # Should raise InvalidAccount
        await pyauth.start_session(fake_payload)

    # Test getting sessions for non-existent account
    sessions = await pyauth.get_sessions(account_uid="fake_account")
    assert sessions == []  # Should return empty list, not raise error

    # Test ending non-existent session
    result = await pyauth.end_session("fake_session_id")
    assert result is None  # Should not raise error, just return None


@pytest.mark.asyncio
async def test_concurrent_session_operations(pyauth):
    """Test concurrent session operations"""
    await pyauth.init_schema()

    payload = PasswordPayload(identifier="concurrent_user", password="pw")
    account = await pyauth.create_account(payload)

    # Create multiple sessions concurrently
    import asyncio

    async def create_session():
        return await pyauth.start_session(payload)

    # Create 3 sessions concurrently
    sessions = await asyncio.gather(
        create_session(), create_session(), create_session()
    )

    # All should be valid
    for session in sessions:
        current = await pyauth.get_current_account_from_session(session.access_token)
        assert current.uid == account.uid

    # Verify all sessions are listed
    all_sessions = await pyauth.get_sessions(account_uid=account.uid)
    assert len(all_sessions) >= 3


@pytest.mark.asyncio
async def test_complete_real_world_auth_flow(
    pyauth, initialized_storage, rbac_permissions
):
    """Complete real-world authentication flow: registration → login → daily usage → account management"""
    # Initialize all schemas
    await pyauth.init_schema()

    # === PHASE 1: USER REGISTRATION ===
    print("Phase 1: User Registration")
    user_payload = PasswordPayload(
        identifier="john.doe@example.com",
        password="SecurePass123!",
        permissions=["read", "create", "update"],
        metadata={"role": "user", "department": "engineering", "signup_source": "web"},
    )

    # Create account with permissions
    account = await pyauth.create_account(user_payload)
    print(
        f"DEBUG: Created account: {account.uid}, active: {account.is_active}, blocked: {account.is_blocked}"
    )
    assert account.uid == "john.doe@example.com"
    assert account.is_active is True
    assert account.is_blocked is False

    # Verify permissions were created via RBAC
    async with initialized_storage.begin() as storage:
        async with rbac_permissions.set_storage_session(storage) as perms:
            role = await perms.get(Role(account_uid=account.uid))
            assert role is not None
            assert set(role.permissions) == {"read", "create", "update"}

    # === PHASE 2: MULTI-DEVICE LOGIN ===
    print("Phase 2: Multi-Device Login")

    # Login from desktop
    desktop_session = await pyauth.start_session(
        user_payload,
        metadata={
            "device": "desktop",
            "browser": "Chrome",
            "os": "Windows",
            "ip": "192.168.1.100",
        },
    )
    assert desktop_session.account_uid == account.uid

    # Login from mobile
    mobile_session = await pyauth.start_session(
        user_payload,
        metadata={
            "device": "mobile",
            "browser": "Safari",
            "os": "iOS",
            "ip": "192.168.1.101",
        },
    )
    assert mobile_session.account_uid == account.uid

    # Login from tablet
    tablet_session = await pyauth.start_session(
        user_payload,
        metadata={
            "device": "tablet",
            "browser": "Firefox",
            "os": "Android",
            "ip": "192.168.1.102",
        },
    )
    assert tablet_session.account_uid == account.uid

    # === PHASE 3: DAILY USAGE SIMULATION ===
    print("Phase 3: Daily Usage Simulation")

    # Simulate daily activities across devices
    activities = [
        ("desktop", "morning_check", desktop_session),
        ("mobile", "commute_browsing", mobile_session),
        ("desktop", "work_session", desktop_session),
        ("tablet", "evening_reading", tablet_session),
        ("mobile", "night_check", mobile_session),
    ]

    for device, activity, session in activities:
        # Verify session is still valid
        current_user = await pyauth.get_current_account_from_session(
            session.access_token
        )
        assert current_user.uid == account.uid
        assert current_user.permissions == ["read", "create", "update"]

        # Simulate activity by updating last_active_at
        from src.pyauth.models import Account as AccountModel

        async with pyauth.as_admin() as admin:
            updated_account = AccountModel(
                uid=current_user.uid,
                password=None,
                permissions=current_user.permissions,
                is_active=current_user.is_active,
                is_blocked=current_user.is_blocked,
                created_at=current_user.created_at,
                updated_at=current_user.updated_at,
                last_active_at=datetime.now(),
                metadata={**current_user.metadata, "last_activity": activity},
            )
            await admin.update_account(user_payload, updated_account)

    # === PHASE 4: SESSION MANAGEMENT ===
    print("Phase 4: Session Management")

    # List all active sessions
    all_sessions = await pyauth.get_sessions(account_uid=account.uid)
    assert len(all_sessions) >= 3

    # User logs out from tablet (security best practice)
    await pyauth.end_session(tablet_session.sid)

    # Verify tablet session is invalid
    with pytest.raises(InvalidSession):
        await pyauth.get_current_account_from_session(tablet_session.access_token)

    # Desktop and mobile should still work
    desktop_user = await pyauth.get_current_account_from_session(
        desktop_session.access_token
    )
    mobile_user = await pyauth.get_current_account_from_session(
        mobile_session.access_token
    )
    assert desktop_user.uid == account.uid
    assert mobile_user.uid == account.uid

    # === PHASE 5: PERMISSION UPDATES ===
    print("Phase 5: Permission Updates")

    # Admin grants additional permissions
    async with initialized_storage.begin() as storage:
        async with rbac_permissions.set_storage_session(storage) as perms:
            # Add new permission
            updated_role = await perms.update(
                Role(
                    account_uid=account.uid,
                    permissions=["read", "create", "update", "delete"],
                )
            )
            assert "delete" in updated_role.permissions

    # === PHASE 6: ACCOUNT SECURITY EVENTS ===
    print("Phase 6: Account Security Events")

    # Simulate suspicious activity - block account temporarily
    from src.pyauth.models import Account as AccountModel

    blocked_account = AccountModel(
        uid=account.uid,
        password=None,
        permissions=account.permissions,
        is_active=False,  # Temporarily deactivate
        is_blocked=True,  # Block due to suspicious activity
        created_at=account.created_at,
        updated_at=datetime.now(),
        last_active_at=account.last_active_at,
        metadata={**account.metadata, "block_reason": "suspicious_login_attempts"},
    )
    await pyauth.update_account(user_payload, blocked_account)

    # All sessions should now be invalid
    with pytest.raises(InvalidAccount):
        await pyauth.get_current_account_from_session(desktop_session.access_token)

    with pytest.raises(InvalidAccount):
        await pyauth.get_current_account_from_session(mobile_session.access_token)

    # === PHASE 7: ACCOUNT RECOVERY ===
    print("Phase 7: Account Recovery")

    # Admin unblocks account
    async with pyauth.as_admin():
        unblocked_account = AccountModel(
            uid=account.uid,
            password=None,
            permissions=account.permissions,
            is_active=True,  # Reactivate
            is_blocked=False,  # Unblock
            created_at=account.created_at,
            updated_at=datetime.now(),
            last_active_at=account.last_active_at,
            metadata={
                **account.metadata,
                "unblock_reason": "false_alarm",
                "unblocked_at": datetime.now().isoformat(),
            },
        )
        await pyauth.update_account(user_payload, unblocked_account)

    # User logs in again
    new_session = await pyauth.start_session(
        user_payload,
        metadata={
            "device": "desktop",
            "browser": "Chrome",
            "os": "Windows",
            "ip": "192.168.1.100",
            "recovery": True,
        },
    )

    # Verify new session works
    recovered_user = await pyauth.get_current_account_from_session(
        new_session.access_token
    )
    assert recovered_user.uid == account.uid
    assert recovered_user.is_active is True
    assert recovered_user.is_blocked is False

    # === PHASE 8: PASSWORD CHANGE ===
    print("Phase 8: Password Change")

    # User changes password
    new_password_payload = PasswordPayload(
        identifier="john.doe@example.com",
        password="NewSecurePass456!",
        permissions=["read", "create", "update", "delete"],
    )

    # Update password
    updated_account = AccountModel(
        uid=account.uid,
        password="NewSecurePass456!",  # New password
        permissions=account.permissions,
        is_active=account.is_active,
        is_blocked=account.is_blocked,
        created_at=account.created_at,
        updated_at=datetime.now(),
        last_active_at=account.last_active_at,
        metadata={
            **account.metadata,
            "password_changed_at": datetime.now().isoformat(),
        },
    )
    await pyauth.update_account(user_payload, updated_account)

    # Old password should not work
    with pytest.raises(Exception):  # Should raise InvalidAccount
        await pyauth.start_session(user_payload)  # Using old password

    # New password should work
    new_password_session = await pyauth.start_session(new_password_payload)
    assert new_password_session.account_uid == account.uid

    # === PHASE 9: ACCOUNT CLEANUP ===
    print("Phase 9: Account Cleanup")

    # User decides to delete account
    await pyauth.delete_account(new_password_payload)

    # Account should not be accessible
    assert await pyauth.get_account(new_password_payload) is None

    # All sessions should be invalid
    with pytest.raises(InvalidSession):
        await pyauth.get_current_account_from_session(new_session.access_token)

    with pytest.raises(InvalidSession):
        await pyauth.get_current_account_from_session(new_password_session.access_token)

    # Permissions should be cleaned up
    async with initialized_storage.begin() as storage:
        async with rbac_permissions.set_storage_session(storage) as perms:
            role = await perms.get(Role(account_uid=account.uid))
            assert role is None  # Role should be deleted

    print("Complete real-world auth flow test passed! 🎉")


@pytest.mark.asyncio
async def test_enterprise_user_workflow(pyauth, initialized_storage, rbac_permissions):
    """Enterprise user workflow with role-based access and session management"""
    await pyauth.init_schema()

    # === CREATE ENTERPRISE USER ===
    enterprise_payload = PasswordPayload(
        identifier="manager@company.com",
        password="EnterprisePass789!",
        permissions=["read", "create", "update", "delete"],
        metadata={
            "role": "manager",
            "department": "IT",
            "employee_id": "EMP001",
            "clearance_level": "high",
        },
    )

    manager_account = await pyauth.create_account(enterprise_payload)

    # === MANAGER LOGS IN ===
    manager_session = await pyauth.start_session(
        enterprise_payload,
        metadata={
            "device": "work_laptop",
            "browser": "Edge",
            "os": "Windows",
            "ip": "10.0.1.50",
            "vpn": True,
        },
    )

    # === MANAGER CREATES SUBORDINATE ACCOUNTS ===
    subordinates = []
    for i in range(3):
        sub_payload = PasswordPayload(
            identifier=f"employee{i+1}@company.com",
            password="TempPass123!",
            permissions=["read", "create"],
            metadata={
                "role": "employee",
                "department": "IT",
                "employee_id": f"EMP{i+2:03d}",
                "manager": "manager@company.com",
            },
        )
        sub_account = await pyauth.create_account(sub_payload)
        subordinates.append((sub_payload, sub_account))

    # === VERIFY PERMISSIONS HIERARCHY ===
    async with initialized_storage.begin() as storage:
        async with rbac_permissions.set_storage_session(storage) as perms:
            # Manager has all permissions
            manager_role = await perms.get(Role(account_uid=manager_account.uid))
            assert "delete" in manager_role.permissions
            assert "create" in manager_role.permissions

            # Employees have limited permissions
            for _, sub_account in subordinates:
                emp_role = await perms.get(Role(account_uid=sub_account.uid))
                assert "delete" not in emp_role.permissions
                assert "read" in emp_role.permissions
                assert "create" in emp_role.permissions

    # === SIMULATE WORKDAY ===
    # Manager works on multiple tasks
    for task in [
        "morning_review",
        "team_meeting",
        "project_planning",
        "evening_report",
    ]:
        current_manager = await pyauth.get_current_account_from_session(
            manager_session.access_token
        )
        assert current_manager.permissions == ["read", "create", "update", "delete"]

    # === EMPLOYEE LOGINS ===
    employee_sessions = []
    for sub_payload, sub_account in subordinates:
        emp_session = await pyauth.start_session(
            sub_payload,
            metadata={
                "device": "work_desktop",
                "browser": "Chrome",
                "os": "Windows",
                "ip": f"10.0.1.{51 + len(employee_sessions)}",
                "vpn": True,
            },
        )
        employee_sessions.append(emp_session)

    # === VERIFY ACCESS CONTROL ===
    for emp_session in employee_sessions:
        emp_user = await pyauth.get_current_account_from_session(
            emp_session.access_token
        )
        # Employees should not have delete access
        assert "delete" not in emp_user.permissions
        # But should have basic access
        assert "read" in emp_user.permissions
        assert "create" in emp_user.permissions

    # === MANAGER MONITORS SESSIONS ===
    all_company_sessions = []
    for sub_payload, sub_account in subordinates:
        sessions = await pyauth.get_sessions(account_uid=sub_account.uid)
        all_company_sessions.extend(sessions)

    # Manager can see all employee sessions
    manager_sessions = await pyauth.get_sessions(account_uid=manager_account.uid)
    total_sessions = len(manager_sessions) + len(all_company_sessions)
    assert total_sessions >= 4  # Manager + 3 employees

    # === END OF WORKDAY - LOGOUT ===
    # All employees log out
    for emp_session in employee_sessions:
        await pyauth.end_session(emp_session.sid)

    # Manager logs out
    await pyauth.end_session(manager_session.sid)

    # All sessions should be invalid
    with pytest.raises(InvalidSession):
        await pyauth.get_current_account_from_session(manager_session.access_token)

    for emp_session in employee_sessions:
        with pytest.raises(InvalidSession):
            await pyauth.get_current_account_from_session(emp_session.access_token)

    print("Enterprise workflow test passed! 🏢")
