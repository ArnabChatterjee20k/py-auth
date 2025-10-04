#!/usr/bin/env python3
"""
Flask OAuth Example with py-auth
Demonstrates GitHub OAuth integration using py-auth library
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
from src.pyauth.providers.oauth.github import GitHubProvider
from src.pyauth.storage import SQLite as SQLiteStorage
from src.pyauth.permissions import RBAC
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)

# OAuth Configuration
GITHUB_CLIENT_ID = "Ov23li650lRDdrwVhrQn"
GITHUB_CLIENT_SECRET = "8f9d9a78279aedec8c01c3fcf2e2dc897762a190"

# Initialize py-auth components
storage = SQLiteStorage("oauth_example.db")
github_provider = GitHubProvider(
    client_id=GITHUB_CLIENT_ID,
    client_secret=GITHUB_CLIENT_SECRET,
    redirect_uri="http://localhost:5000/auth/github/callback",
)

# Initialize py-auth with GitHub provider (we'll switch providers as needed)
pyauth = Pyauth(provider=github_provider, storage=storage, permissions=RBAC())

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
    <title>Py-Auth OAuth Example</title>
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
        #result { margin-top: 20px; padding: 10px; background: #f8f9fa; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Py-Auth OAuth Example</h1>
    
    {% if user %}
    <div class="user-info">
        <h3>Welcome, {{ user.metadata.name if user.metadata and user.metadata.name else user.uid }}!</h3>
        <p><strong>UID:</strong> {{ user.uid }}</p>
        <p><strong>Email:</strong> {{ user.metadata.email if user.metadata else 'Not provided' }}</p>
        <p><strong>Provider:</strong> GitHub</p>
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
        <h3>Login with GitHub OAuth</h3>
        <button onclick="loginGitHub()">Login with GitHub</button>
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
        <h3>Admin Operations</h3>
        <p>Admin operations bypass OAuth verification and can manage accounts directly.</p>
        <button onclick="adminGetAccount()" class="admin">Get Account (Admin)</button>
        <button onclick="adminUpdateAccount()" class="admin">Update Account (Admin)</button>
        <button onclick="adminDeleteAccount()" class="admin">Delete Account (Admin)</button>
    </div>
    {% endif %}
    
    <div id="result"></div>

    <script>
        function loginGitHub() {
            window.location.href = '/auth/github';
        }
        
        function logout() {
            window.location.href = '/logout';
        }
        
        async function adminGetAccount() {
            try {
                const result = await fetch('/admin/get-account', {method: 'POST'});
                const data = await result.json();
                document.getElementById('result').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
            } catch (error) {
                document.getElementById('result').innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
        }
        
        async function adminUpdateAccount() {
            try {
                const result = await fetch('/admin/update-account', {method: 'POST'});
                const data = await result.json();
                document.getElementById('result').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                if (data.success) {
                    setTimeout(() => window.location.reload(), 1000);
                }
            } catch (error) {
                document.getElementById('result').innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
        }
        
        async function adminDeleteAccount() {
            try {
                const result = await fetch('/admin/delete-account', {method: 'POST'});
                const data = await result.json();
                document.getElementById('result').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                if (data.success) {
                    setTimeout(() => window.location.reload(), 1000);
                }
            } catch (error) {
                document.getElementById('result').innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
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


@app.route("/auth/github")
def github_auth():
    try:
        auth_url = github_provider.get_authorization_url()
        return redirect(auth_url)
    except Exception as e:
        return f"Error initiating GitHub OAuth: {str(e)}", 500


@app.route("/auth/github/callback")
def github_callback():
    """Handle GitHub OAuth callback"""
    try:
        code = request.args.get("code")
        if not code:
            return "Authorization code not provided", 400

        # Complete OAuth flow using py-auth methods
        async def complete_oauth():
            # Step 1: Exchange code for token and get user info
            token_data = await github_provider.exchange_code_for_token(code)
            user_info = await github_provider.get_user_info(token_data["access_token"])

            # Step 2: Create GitHub payload
            from src.pyauth.providers.oauth.payload import GitHubPayload

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

            # Step 3: Use py-auth to check if account exists
            existing_account = await pyauth.get_account(payload)

            if existing_account:
                # Step 4: Update existing account using py-auth
                # Create updated account with new metadata
                from src.pyauth.models import Account
                from datetime import datetime

                updated_metadata = (
                    existing_account.metadata.copy()
                    if existing_account.metadata
                    else {}
                )
                updated_metadata.update(
                    {
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
                )

                updated_account = Account(
                    uid=existing_account.uid,
                    is_active=existing_account.is_active,
                    is_blocked=existing_account.is_blocked,
                    created_at=existing_account.created_at,
                    updated_at=datetime.now(),
                    last_active_at=datetime.now(),
                    metadata=updated_metadata,
                    permissions=existing_account.permissions,
                )

                account = await pyauth.update_account(payload, updated_account)
            else:
                # Step 5: Create new account using py-auth
                account = await pyauth.create_account(payload)

            # Step 6: Create a py-auth session and get JWT access token
            pyauth_session = await pyauth.start_session(
                payload, metadata={"oauth_provider": "github"}
            )

            return account, pyauth_session

        account, pyauth_session = asyncio.run(complete_oauth())

        # Create response with cookie
        response = make_response(redirect(url_for("index")))
        response = set_auth_cookie(response, pyauth_session.access_token)
        return response
    except Exception as e:
        return f"GitHub OAuth error: {str(e)}", 500


@app.route("/logout")
def logout():
    """Logout user"""
    try:
        token = get_auth_cookie()

        async def end():
            user = await pyauth.get_current_session(token)
            await pyauth.end_session(user.sid)

        asyncio.run(end())

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
        token = get_auth_cookie()

        async def get_current_user():
            return await pyauth.get_current_account_from_session(token)

        user = asyncio.run(get_current_user())
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
        from src.pyauth.providers.oauth.payload import GitHubPayload

        # Safely get metadata with fallback
        metadata = user.metadata or {}

        payload = GitHubPayload(
            github_id=metadata.get("github_id"),
            access_token="session_creation",
            name=metadata.get("name"),
            email=metadata.get("email"),
            login=metadata.get("login"),
            avatar_url=metadata.get("avatar_url"),
        )

        # Start session using py-auth
        async def start_new_session():
            # Use the standard py-auth start_session method
            # This will handle account verification and session creation
            new_session = await pyauth.start_session(
                payload,
                metadata={"created_via": "flask_app", "oauth_provider": "github"},
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
    # try:
    token = get_auth_cookie()

    # Get the most recent session for the user
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
    # except Exception as e:
    #     return jsonify({'error': str(e)}), 500


@app.route("/current-account", methods=["POST"])
def get_current_account_from_session():
    """Get current account using py-auth get_current_account with JWT token"""
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
                    "email": user.metadata.get("email") if user.metadata else None,
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


# Admin operations using py-auth admin functionality
@app.route("/admin/get-account", methods=["POST"])
def admin_get_account():
    """Admin operation: Get account without OAuth verification"""
    try:
        user = get_current_user()
        if not user:
            return jsonify({"error": "No user authenticated"}), 401

        # Create a mock payload for admin operations (GitHub only)
        from src.pyauth.providers.oauth.payload import GitHubPayload

        # Safely get metadata with fallback
        metadata = user.metadata or {}

        payload = GitHubPayload(
            github_id=metadata.get("github_id"),
            access_token="admin_bypass",
            name=metadata.get("name"),
            email=metadata.get("email"),
            login=metadata.get("login"),
            avatar_url=metadata.get("avatar_url"),
        )

        # Use admin mode to bypass verification
        async def admin_operation():
            async with pyauth.as_admin():
                account = await pyauth.get_account(payload)
                return account

        account = asyncio.run(admin_operation())

        if not account:
            return jsonify({"error": "Account not found"}), 404

        return jsonify(
            {
                "success": True,
                "message": "Account retrieved in admin mode",
                "account": {
                    "uid": account.uid,
                    "name": account.metadata.get("name") if account.metadata else None,
                    "email": (
                        account.metadata.get("email") if account.metadata else None
                    ),
                    "is_active": account.is_active,
                    "metadata": account.metadata,
                },
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/update-account", methods=["POST"])
def admin_update_account():
    """Admin operation: Update account without OAuth verification"""
    try:
        user = get_current_user()
        if not user:
            return jsonify({"error": "No user authenticated"}), 401

        # Create a mock payload for admin operations
        from src.pyauth.providers.oauth.payload import GitHubPayload
        from src.pyauth.models import Account
        from datetime import datetime

        # Safely get metadata with fallback
        metadata = user.metadata or {}

        payload = GitHubPayload(
            github_id=metadata.get("github_id"),
            access_token="admin_bypass",
            name=metadata.get("name"),
            email=metadata.get("email"),
            login=metadata.get("login"),
            avatar_url=metadata.get("avatar_url"),
        )

        # Create updated account with name in metadata
        updated_metadata = metadata.copy() if metadata else {}
        updated_metadata["name"] = f"{metadata.get('name', 'User')} (Updated by Admin)"

        updated_account = Account(
            uid=user.uid,
            is_active=user.is_active,
            is_blocked=False,
            created_at=user.created_at,
            updated_at=datetime.now(),
            last_active_at=datetime.now(),
            metadata=updated_metadata,
        )

        # Use admin mode to bypass verification
        async def admin_operation():
            async with pyauth.as_admin():
                account = await pyauth.update_account(payload, updated_account)
                return account

        account = asyncio.run(admin_operation())

        response = make_response(
            jsonify(
                {
                    "success": True,
                    "message": "Account updated in admin mode",
                    "account": {
                        "uid": account.uid,
                        "name": (
                            account.metadata.get("name") if account.metadata else None
                        ),
                        "email": (
                            account.metadata.get("email") if account.metadata else None
                        ),
                        "is_active": account.is_active,
                        "updated_at": account.updated_at.isoformat(),
                    },
                }
            )
        )

        return response
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/delete-account", methods=["POST"])
def admin_delete_account():
    """Admin operation: Delete account without OAuth verification"""
    try:
        user = get_current_user()
        if not user:
            return jsonify({"error": "No user authenticated"}), 401

        # Create a mock payload for admin operations (GitHub only)
        from src.pyauth.providers.oauth.payload import GitHubPayload

        # Safely get metadata with fallback
        metadata = user.metadata or {}

        payload = GitHubPayload(
            github_id=metadata.get("github_id"),
            access_token="admin_bypass",
            name=metadata.get("name"),
            email=metadata.get("email"),
            login=metadata.get("login"),
            avatar_url=metadata.get("avatar_url"),
        )

        # Use admin mode to bypass verification
        async def admin_operation():
            async with pyauth.as_admin():
                await pyauth.delete_account(payload)
                return True

        success = asyncio.run(admin_operation())

        # Clear cookie
        response = make_response(
            jsonify({"success": True, "message": "Account deleted in admin mode"})
        )
        response = clear_auth_cookie(response)
        return response
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    # Initialize database
    asyncio.run(init_database())

    print("Flask OAuth Example with py-auth")
    print("=" * 40)
    print("1. Set up OAuth credentials:")
    print("   - GitHub: https://github.com/settings/applications/new")
    print("2. Set environment variables:")
    print("   export GITHUB_CLIENT_ID='your_github_client_id'")
    print("   export GITHUB_CLIENT_SECRET='your_github_client_secret'")
    print("3. Run: python github_app.py")
    print("4. Visit: http://localhost:5000")
    print("=" * 40)

    app.run(debug=True, host="0.0.0.0", port=5000)
