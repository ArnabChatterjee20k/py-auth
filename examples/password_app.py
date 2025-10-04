#!/usr/bin/env python3
"""
Flask Password Authentication Example with py-auth
Demonstrates password-based authentication using py-auth library
"""

import asyncio
import os
from datetime import datetime
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    jsonify,
    render_template_string,
    make_response,
)
from src.pyauth import Pyauth
from src.pyauth.providers import Password
from src.pyauth.storage import SQLite as SQLiteStorage
from src.pyauth.permissions import RBAC
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)

# Initialize py-auth components
storage = SQLiteStorage("password_example.db")
password_provider = Password()

# Initialize py-auth with password provider
pyauth = Pyauth(provider=password_provider, storage=storage, permissions=RBAC())

# Cookie configuration
COOKIE_NAME = "pyauth_session"
COOKIE_MAX_AGE = 7 * 24 * 60 * 60  # 7 days in seconds
COOKIE_SECURE = False  # Set to True in production with HTTPS
COOKIE_HTTPONLY = True
COOKIE_SAMESITE = "Lax"


def set_auth_cookie(response, token):
    """Set authentication cookie with user data"""
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=COOKIE_MAX_AGE,
        secure=COOKIE_SECURE,
        httponly=COOKIE_HTTPONLY,
        samesite=COOKIE_SAMESITE,
    )
    return response


def get_auth_cookie():
    """Get authentication data from cookie"""
    data = request.cookies.get(COOKIE_NAME)
    if not data:
        return None
    return data


def clear_auth_cookie(response):
    """Clear authentication cookie"""
    response.set_cookie(
        COOKIE_NAME,
        "",
        expires=0,
        secure=COOKIE_SECURE,
        httponly=COOKIE_HTTPONLY,
        samesite=COOKIE_SAMESITE,
    )
    return response


def get_current_user():
    """Get current user from session token"""
    token = get_auth_cookie()
    if not token:
        return None

    async def get_user():
        try:
            return await pyauth.get_current_account_from_session(token)
        except Exception:
            return None

    return asyncio.run(get_user())


# HTML Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Py-Auth Password Example</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .auth-section { margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .user-info { background: #f0f8ff; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .error { color: red; }
        .success { color: green; }
        .admin-section { background: #fff3cd; padding: 15px; border-radius: 5px; margin: 10px 0; }
        button { padding: 10px 15px; margin: 5px; cursor: pointer; }
        .logout { background: #dc3545; color: white; border: none; }
        .admin { background: #6c757d; color: white; border: none; }
        .primary { background: #007bff; color: white; border: none; }
        #result { margin-top: 20px; padding: 10px; background: #f8f9fa; border-radius: 5px; }
        .form-group { margin: 10px 0; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        .form-group input[type="email"], .form-group input[type="password"] { max-width: 300px; }
        .hidden { display: none; }
    </style>
</head>
<body>
    <h1>Py-Auth Password Authentication Example</h1>
    
    {% if user %}
    <div class="user-info">
        <h3>Welcome, {{ user.metadata.name if user.metadata and user.metadata.name else user.uid }}!</h3>
        <p><strong>Email:</strong> {{ user.uid }}</p>
        <p><strong>Active:</strong> {{ user.is_active }}</p>
        <p><strong>Created:</strong> {{ user.created_at.strftime('%Y-%m-%d %H:%M:%S') if user.created_at else 'Unknown' }}</p>
        {% if user.metadata %}
        <details>
            <summary>Full Metadata</summary>
            <pre>{{ user.metadata | tojson(indent=2) }}</pre>
        </details>
        {% endif %}
        <button onclick="logout()" class="logout">Logout</button>
    </div>
    {% else %}
    <div class="auth-section">
        <h3>Authentication</h3>
        <div id="login-form">
            <h4>Login</h4>
            <div class="form-group">
                <label for="login-email">Email:</label>
                <input type="email" id="login-email" placeholder="Enter your email">
            </div>
            <div class="form-group">
                <label for="login-password">Password:</label>
                <input type="password" id="login-password" placeholder="Enter your password">
            </div>
            <button onclick="login()" class="primary">Login</button>
            <button onclick="showRegister()" class="admin">Register Instead</button>
        </div>
        
        <div id="register-form" class="hidden">
            <h4>Register</h4>
            <div class="form-group">
                <label for="reg-email">Email:</label>
                <input type="email" id="reg-email" placeholder="Enter your email">
            </div>
            <div class="form-group">
                <label for="reg-password">Password:</label>
                <input type="password" id="reg-password" placeholder="Enter your password">
            </div>
            <div class="form-group">
                <label for="reg-name">Name (optional):</label>
                <input type="text" id="reg-name" placeholder="Enter your name">
            </div>
            <button onclick="register()" class="primary">Register</button>
            <button onclick="showLogin()" class="admin">Login Instead</button>
        </div>
    </div>
    {% endif %}
    
    {% if user %}
    <div class="admin-section">
        <h3>Session Management</h3>
        <p>Manage user sessions using py-auth methods.</p>
        <button onclick="listSessions()" class="admin">List Sessions</button>
        <button onclick="startNewSession()" class="admin">Start New Session</button>
        <button onclick="endCurrentSession()" class="admin">End Current Session</button>
        <button onclick="getCurrentAccount()" class="admin">Get Current Account</button>
    </div>
    
    <div class="admin-section">
        <h3>Account Management</h3>
        <p>Manage your account information.</p>
        <button onclick="updateAccount()" class="admin">Update Account</button>
        <button onclick="changePassword()" class="admin">Change Password</button>
        <button onclick="deleteAccount()" class="admin">Delete Account</button>
    </div>
    {% endif %}
    
    <div id="result"></div>

    <script>
        function showLogin() {
            document.getElementById('login-form').classList.remove('hidden');
            document.getElementById('register-form').classList.add('hidden');
        }
        
        function showRegister() {
            document.getElementById('login-form').classList.add('hidden');
            document.getElementById('register-form').classList.remove('hidden');
        }
        
        async function login() {
            const email = document.getElementById('login-email').value;
            const password = document.getElementById('login-password').value;
            
            if (!email || !password) {
                document.getElementById('result').innerHTML = '<div class="error">Please enter both email and password</div>';
                return;
            }
            
            try {
                const result = await fetch('/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({email: email, password: password})
                });
                const data = await result.json();
                
                if (data.success) {
                    window.location.reload();
                } else {
                    document.getElementById('result').innerHTML = '<div class="error">' + data.error + '</div>';
                }
            } catch (error) {
                document.getElementById('result').innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
        }
        
        async function register() {
            const email = document.getElementById('reg-email').value;
            const password = document.getElementById('reg-password').value;
            const name = document.getElementById('reg-name').value;
            
            if (!email || !password) {
                document.getElementById('result').innerHTML = '<div class="error">Please enter both email and password</div>';
                return;
            }
            
            try {
                const result = await fetch('/register', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        email: email, 
                        password: password, 
                        name: name || null
                    })
                });
                const data = await result.json();
                
                if (data.success) {
                    window.location.reload();
                } else {
                    document.getElementById('result').innerHTML = '<div class="error">' + data.error + '</div>';
                }
            } catch (error) {
                document.getElementById('result').innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
        }
        
        function logout() {
            window.location.href = '/logout';
        }
        
        async function listSessions() {
            try {
                const result = await fetch('/sessions');
                const data = await result.json();
                document.getElementById('result').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
            } catch (error) {
                document.getElementById('result').innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
        }
        
        async function startNewSession() {
            try {
                const result = await fetch('/start-session', {method: 'POST'});
                const data = await result.json();
                document.getElementById('result').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
            } catch (error) {
                document.getElementById('result').innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
        }
        
        async function endCurrentSession() {
            try {
                const result = await fetch('/end-session', {method: 'POST'});
                const data = await result.json();
                document.getElementById('result').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                if (data.success) {
                    setTimeout(() => window.location.reload(), 1000);
                }
            } catch (error) {
                document.getElementById('result').innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
        }
        
        async function getCurrentAccount() {
            try {
                const result = await fetch('/current-account', {method: 'POST'});
                const data = await result.json();
                document.getElementById('result').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
            } catch (error) {
                document.getElementById('result').innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
        }
        
        async function updateAccount() {
            const newName = prompt('Enter new name (or leave empty to keep current):');
            if (newName === null) return; // User cancelled
            
            try {
                const result = await fetch('/update-account', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({name: newName})
                });
                const data = await result.json();
                document.getElementById('result').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                if (data.success) {
                    setTimeout(() => window.location.reload(), 1000);
                }
            } catch (error) {
                document.getElementById('result').innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
        }
        
        async function changePassword() {
            const currentPassword = prompt('Enter current password:');
            if (!currentPassword) return;
            
            const newPassword = prompt('Enter new password:');
            if (!newPassword) return;
            
            const confirmPassword = prompt('Confirm new password:');
            if (newPassword !== confirmPassword) {
                document.getElementById('result').innerHTML = '<div class="error">Passwords do not match</div>';
                return;
            }
            
            try {
                const result = await fetch('/change-password', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        current_password: currentPassword,
                        new_password: newPassword
                    })
                });
                const data = await result.json();
                document.getElementById('result').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
            } catch (error) {
                document.getElementById('result').innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
        }
        
        async function deleteAccount() {
            if (!confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
                return;
            }
            
            const password = prompt('Enter your password to confirm account deletion:');
            if (!password) return;
            
            try {
                const result = await fetch('/delete-account', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({password: password})
                });
                const data = await result.json();
                document.getElementById('result').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                if (data.success) {
                    setTimeout(() => window.location.reload(), 1000);
                }
            } catch (error) {
                document.getElementById('result').innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
        }
    </script>
</body>
</html>
"""


async def init_database():
    """Initialize the database schema"""
    await pyauth.init_schema()


@app.route("/")
def index():
    """Main page"""
    user = get_current_user()
    return render_template_string(HTML_TEMPLATE, user=user)


@app.route("/register", methods=["POST"])
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
        name = data.get("name")

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        # Create password payload
        from src.pyauth.providers.password.payload import PasswordPayload

        payload = PasswordPayload(
            identifier=email, password=password, metadata={"name": name} if name else {}
        )

        # Create account using py-auth
        async def create_account():
            account = await pyauth.create_account(payload)
            return account

        account = asyncio.run(create_account())

        # Start session after successful registration
        async def start_session():
            session = await pyauth.start_session(
                payload, metadata={"created_via": "registration"}
            )
            return session

        session = asyncio.run(start_session())

        # Create response with cookie
        response = make_response(
            jsonify(
                {
                    "success": True,
                    "message": "Account created and logged in successfully",
                    "account": {
                        "uid": account.uid,
                        "name": (
                            account.metadata.get("name") if account.metadata else None
                        ),
                        "is_active": account.is_active,
                    },
                }
            )
        )
        response = set_auth_cookie(response, session.access_token)
        return response

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/login", methods=["POST"])
def login():
    """Login user"""
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        # Create password payload
        from src.pyauth.providers.password.payload import PasswordPayload

        payload = PasswordPayload(identifier=email, password=password)

        # Check if account exists and verify password
        async def verify_and_login():
            # First check if account exists
            account = await pyauth.get_account(payload)
            if not account:
                return None, None

            # Start session
            session = await pyauth.start_session(
                payload, metadata={"created_via": "login"}
            )
            return account, session

        account, session = asyncio.run(verify_and_login())

        if not account:
            return jsonify({"error": "Invalid email or password"}), 401

        # Create response with cookie
        response = make_response(
            jsonify(
                {
                    "success": True,
                    "message": "Logged in successfully",
                    "account": {
                        "uid": account.uid,
                        "name": (
                            account.metadata.get("name") if account.metadata else None
                        ),
                        "is_active": account.is_active,
                    },
                }
            )
        )
        response = set_auth_cookie(response, session.access_token)
        return response

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/logout")
def logout():
    """Logout user"""
    try:
        token = get_auth_cookie()
        if token:

            async def end_session():
                try:
                    session = await pyauth.get_current_session(token)
                    if session:
                        await pyauth.end_session(session.sid)
                except Exception:
                    pass  # Session might already be ended

            asyncio.run(end_session())

        # Clear cookie
        response = make_response(redirect(url_for("index")))
        response = clear_auth_cookie(response)
        return response
    except Exception as e:
        # Even if there's an error ending the session, clear the cookie
        response = make_response(redirect(url_for("index")))
        response = clear_auth_cookie(response)
        return response


@app.route("/sessions")
def list_sessions():
    """List user sessions using py-auth"""
    try:
        user = get_current_user()
        if not user:
            return jsonify({"error": "No user authenticated"}), 401

        # Get sessions using py-auth
        async def get_sessions():
            sessions = await pyauth.get_sessions(user.uid)
            return sessions

        sessions = asyncio.run(get_sessions())

        return jsonify(
            {
                "success": True,
                "sessions": [
                    {
                        "sid": s.sid,
                        "account_uid": s.account_uid,
                        "is_active": s.is_active,
                        "is_blocked": s.is_blocked,
                        "created_at": (
                            s.created_at.isoformat() if s.created_at else None
                        ),
                        "updated_at": (
                            s.updated_at.isoformat() if s.updated_at else None
                        ),
                        "expires_at": (
                            s.expires_at.isoformat() if s.expires_at else None
                        ),
                        "metadata": s.metadata,
                    }
                    for s in sessions
                ],
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/start-session", methods=["POST"])
def start_session():
    """Start a new session using py-auth"""
    try:
        user = get_current_user()
        if not user:
            return jsonify({"error": "No user authenticated"}), 401

        # Create payload for session creation
        from src.pyauth.providers.password.payload import PasswordPayload

        # We need the password to start a new session, but we don't store it
        # So we'll use a special admin bypass for this operation
        payload = PasswordPayload(
            identifier=user.uid,
            password="session_creation_bypass",  # This won't work for normal auth
        )

        # Start session using py-auth in admin mode
        async def start_new_session():
            async with pyauth.as_admin():
                new_session = await pyauth.start_session(
                    payload, metadata={"created_via": "flask_app"}
                )
                return new_session

        new_session = asyncio.run(start_new_session())

        return jsonify(
            {
                "success": True,
                "message": "New session started",
                "session": {
                    "sid": new_session.sid,
                    "account_uid": new_session.account_uid,
                    "is_active": new_session.is_active,
                    "is_blocked": new_session.is_blocked,
                    "created_at": (
                        new_session.created_at.isoformat()
                        if new_session.created_at
                        else None
                    ),
                    "updated_at": (
                        new_session.updated_at.isoformat()
                        if new_session.updated_at
                        else None
                    ),
                    "expires_at": (
                        new_session.expires_at.isoformat()
                        if new_session.expires_at
                        else None
                    ),
                    "metadata": new_session.metadata,
                },
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/end-session", methods=["POST"])
def end_session():
    """End the current session using py-auth"""
    try:
        token = get_auth_cookie()
        if not token:
            return jsonify({"error": "No active session"}), 400

        # Get the current session and end it
        async def end_user_session():
            cur_session = await pyauth.get_current_session(token)
            if not cur_session:
                return {"error": "No sessions found"}
            success = await pyauth.end_session(cur_session.sid)
            return {"success": success, "session_id": cur_session.sid}

        result = asyncio.run(end_user_session())

        if result.get("success"):
            result["message"] = "Session ended successfully"

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/current-account", methods=["POST"])
def get_current_account():
    """Get current account information"""
    try:
        user = get_current_user()
        if not user:
            return jsonify({"error": "No user authenticated"}), 401

        return jsonify(
            {
                "success": True,
                "message": "Current account retrieved",
                "account": {
                    "uid": user.uid,
                    "name": user.metadata.get("name") if user.metadata else None,
                    "email": user.uid,  # In password auth, uid is the email
                    "is_active": user.is_active,
                    "is_blocked": user.is_blocked,
                    "permissions": user.permissions,
                    "created_at": (
                        user.created_at.isoformat() if user.created_at else None
                    ),
                    "updated_at": (
                        user.updated_at.isoformat() if user.updated_at else None
                    ),
                    "last_active_at": (
                        user.last_active_at.isoformat() if user.last_active_at else None
                    ),
                    "metadata": user.metadata,
                },
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/update-account", methods=["POST"])
def update_account():
    """Update account information"""
    try:
        user = get_current_user()
        if not user:
            return jsonify({"error": "No user authenticated"}), 401

        data = request.get_json()
        new_name = data.get("name")

        if not new_name:
            return jsonify({"error": "Name is required"}), 400

        # Create payload for update
        from src.pyauth.providers.password.payload import PasswordPayload
        from src.pyauth.models import Account
        from datetime import datetime

        payload = PasswordPayload(
            identifier=user.uid, password="update_bypass"  # We'll use admin mode
        )

        # Create updated account
        updated_metadata = user.metadata.copy() if user.metadata else {}
        updated_metadata["name"] = new_name

        updated_account = Account(
            uid=user.uid,
            is_active=user.is_active,
            is_blocked=user.is_blocked,
            created_at=user.created_at,
            updated_at=datetime.now(),
            last_active_at=datetime.now(),
            metadata=updated_metadata,
            permissions=user.permissions,
        )

        # Update account using admin mode
        async def update_user_account():
            async with pyauth.as_admin():
                account = await pyauth.update_account(payload, updated_account)
                return account

        account = asyncio.run(update_user_account())

        return jsonify(
            {
                "success": True,
                "message": "Account updated successfully",
                "account": {
                    "uid": account.uid,
                    "name": account.metadata.get("name") if account.metadata else None,
                    "email": account.uid,
                    "is_active": account.is_active,
                    "updated_at": account.updated_at.isoformat(),
                },
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/change-password", methods=["POST"])
def change_password():
    """Change user password"""
    try:
        user = get_current_user()
        if not user:
            return jsonify({"error": "No user authenticated"}), 401

        data = request.get_json()
        current_password = data.get("current_password")
        new_password = data.get("new_password")

        if not current_password or not new_password:
            return (
                jsonify({"error": "Current password and new password are required"}),
                400,
            )

        # Verify current password
        from src.pyauth.providers.password.payload import PasswordPayload

        verify_payload = PasswordPayload(identifier=user.uid, password=current_password)

        async def verify_current_password():
            try:
                account = await pyauth.get_account(verify_payload)
                return account is not None
            except Exception:
                return False

        if not asyncio.run(verify_current_password()):
            return jsonify({"error": "Current password is incorrect"}), 401

        # Update password using admin mode
        from src.pyauth.models import Account
        from datetime import datetime

        update_payload = PasswordPayload(
            identifier=user.uid, password="password_update_bypass"
        )

        updated_account = Account(
            uid=user.uid,
            password=new_password,  # This will be hashed by the provider
            is_active=user.is_active,
            is_blocked=user.is_blocked,
            created_at=user.created_at,
            updated_at=datetime.now(),
            last_active_at=datetime.now(),
            metadata=user.metadata,
            permissions=user.permissions,
        )

        async def update_password():
            async with pyauth.as_admin():
                account = await pyauth.update_account(update_payload, updated_account)
                return account

        account = asyncio.run(update_password())

        return jsonify({"success": True, "message": "Password changed successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/delete-account", methods=["POST"])
def delete_account():
    """Delete user account"""
    try:
        user = get_current_user()
        if not user:
            return jsonify({"error": "No user authenticated"}), 401

        data = request.get_json()
        password = data.get("password")

        if not password:
            return jsonify({"error": "Password is required to delete account"}), 400

        # Verify password before deletion
        from src.pyauth.providers.password.payload import PasswordPayload

        verify_payload = PasswordPayload(identifier=user.uid, password=password)

        async def verify_password():
            try:
                account = await pyauth.get_account(verify_payload)
                return account is not None
            except Exception:
                return False

        if not asyncio.run(verify_password()):
            return jsonify({"error": "Password is incorrect"}), 401

        # Delete account using admin mode
        delete_payload = PasswordPayload(identifier=user.uid, password="delete_bypass")

        async def delete_user_account():
            async with pyauth.as_admin():
                await pyauth.delete_account(delete_payload)
                return True

        asyncio.run(delete_user_account())

        # Clear cookie
        response = make_response(
            jsonify({"success": True, "message": "Account deleted successfully"})
        )
        response = clear_auth_cookie(response)
        return response
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    # Initialize database
    asyncio.run(init_database())

    print("Flask Password Authentication Example with py-auth")
    print("=" * 50)
    print("1. The app uses email/password authentication")
    print("2. Users can register, login, and manage their accounts")
    print("3. All passwords are securely hashed using bcrypt")
    print("4. Session management with JWT tokens")
    print("5. Run: python password_app.py")
    print("6. Visit: http://localhost:5000")
    print("=" * 50)

    app.run(debug=True, host="0.0.0.0", port=5000)
