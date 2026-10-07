import os
import shutil
import sqlite3
import secrets
import hashlib
import json
import base64
from datetime import datetime, timezone
from functools import wraps
from cryptography.fernet import Fernet, InvalidToken
from flask import g
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response, g
from dotenv import load_dotenv
from urllib.parse import quote, urlencode

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key-change-in-production")

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_APP_CLIENT_ID = os.getenv("GA_CLIENT_ID") or os.getenv("GITHUB_APP_CLIENT_ID")
GITHUB_APP_CLIENT_SECRET = os.getenv("GA_CLIENT_SECRET") or os.getenv("GITHUB_APP_CLIENT_SECRET")
EXTERNAL_BASE_URL = os.getenv("EXTERNAL_BASE_URL", "").rstrip("/")
GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_URL = "https://api.github.com"

# Public URL exposed through the Cloudflare Worker.
# The deployment workflow sets EXTERNAL_BASE_URL automatically after the
# Worker is deployed. No server IP/port is used for OAuth callbacks.


def get_external_url(path="/"):
    """Build an externally reachable URL using the Cloudflare Worker URL."""
    base = get_external_base_url()
    if not path.startswith("/"):
        path = "/" + path
    return f"{base}{path}"


# In-memory fast cache for concluded CI statuses (SHA -> dict)
CI_CACHE = {}


# ---------------------------------------------------------------------------
# Application access tokens
# ---------------------------------------------------------------------------
# These are NOT GitHub PATs. They are scoped credentials for this Git Manager.
# A generated token is shown only once. Only a SHA-256 hash is stored.
TOKEN_DB_PATH = os.getenv(
    "APP_TOKEN_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "access_tokens.db"),
)
TOKEN_ENCRYPTION_SECRET = os.getenv("APP_TOKEN_ENCRYPTION_SECRET", "")
if not TOKEN_ENCRYPTION_SECRET:
    # Stable across workers/restarts as long as FLASK_SECRET_KEY remains stable.
    TOKEN_ENCRYPTION_SECRET = app.secret_key
TOKEN_FERNET_KEY = base64.urlsafe_b64encode(
    hashlib.sha256(("git-manager-token:" + TOKEN_ENCRYPTION_SECRET).encode("utf-8")).digest()
)
TOKEN_CIPHER = Fernet(TOKEN_FERNET_KEY)
TOKEN_PREFIX = "gm_"

TOKEN_PERMISSION_GROUPS = {
    "Repository": {
        "metadata:read": "View repository metadata and basic information",
        "repos:read": "View repositories, branches and repository data",
        "repos:settings": "Edit repository description, visibility and settings",
        "repos:delete": "Delete repositories",
        "branches:read": "View branches and branch information",
        "branches:write": "Create, rename and manage branches",
    },
    "Contents": {
        "files:read": "Read file contents and download repositories",
        "files:write": "Create, upload and edit files/folders",
        "files:delete": "Delete repository files",
    },
    "Issues": {
        "issues:read": "View issues, labels, milestones and comments",
        "issues:write": "Create, edit and close issues and comments",
    },
    "Pull Requests": {
        "pulls:read": "View pull requests, reviews and comments",
        "pulls:write": "Create, edit, merge and close pull requests",
    },
    "Commits": {
        "commits:read": "View commits and commit details",
        "commits:write": "Create, restore and manage commits",
    },
    "Actions": {
        "actions:read": "View workflows, runs and artifacts",
        "actions:write": "Run, cancel and manage workflow runs",
    },
    "Releases": {
        "releases:read": "View releases and release assets",
        "releases:write": "Create, edit and delete releases",
    },
    "Webhooks": {
        "webhooks:read": "View repository webhooks",
        "webhooks:write": "Create, edit and delete repository webhooks",
    },
    "Administration": {
        "collaborators:read": "View repository collaborators and access",
        "collaborators:write": "Manage repository collaborators and access",
        "deployments:read": "View deployments and deployment status",
        "deployments:write": "Create and manage deployments",
    },
}

TOKEN_PERMISSIONS = {
    key: description
    for group in TOKEN_PERMISSION_GROUPS.values()
    for key, description in group.items()
}

def _token_db():
    os.makedirs(os.path.dirname(TOKEN_DB_PATH) or ".", exist_ok=True)
    db = sqlite3.connect(TOKEN_DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("""
        CREATE TABLE IF NOT EXISTS access_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            token_prefix TEXT NOT NULL,
            token_type TEXT NOT NULL DEFAULT 'normal',
            permissions TEXT NOT NULL,
            github_token TEXT NOT NULL,
            github_login TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            revoked_at TEXT,
            expires_at TEXT
        )
    """)
    # Backward-compatible migration for databases created before token types.
    columns = {row[1] for row in db.execute("PRAGMA table_info(access_tokens)").fetchall()}
    if "token_type" not in columns:
        db.execute("ALTER TABLE access_tokens ADD COLUMN token_type TEXT NOT NULL DEFAULT 'normal'")
    if "expires_at" not in columns:
        db.execute("ALTER TABLE access_tokens ADD COLUMN expires_at TEXT")
    db.commit()
    return db

def _token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def _get_bearer_token():
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None

def _resolve_token(token):
    # Accept both legacy Git Manager tokens (gm_*) and GitHub-issued scoped
    # user tokens (ghu_*) created through the GitHub API below.
    if not token:
        return None
    db = _token_db()
    try:
        row = db.execute(
            "SELECT * FROM access_tokens WHERE token_hash = ? AND revoked_at IS NULL",
            (_token_hash(token),),
        ).fetchone()
        if not row:
            return None
        try:
            github_token = TOKEN_CIPHER.decrypt(row["github_token"].encode()).decode()
        except (InvalidToken, ValueError):
            return None
        db.execute(
            "UPDATE access_tokens SET last_used_at = ? WHERE id = ?",
            (_now_iso(), row["id"]),
        )
        db.commit()
        return {
            "type": "token",
            "id": row["id"],
            "name": row["name"],
            "token_type": row["token_type"] or "normal",
            "login": row["github_login"],
            "permissions": set(json.loads(row["permissions"])),
            "github_token": github_token,
        }
    finally:
        db.close()

def current_auth():
    auth = getattr(g, "auth_context", None)
    if auth:
        return auth
    bearer = _get_bearer_token()
    if bearer:
        auth = _resolve_token(bearer)
        if auth:
            g.auth_context = auth
            return auth
        return None
    if session.get("access_token"):
        auth = {
            "type": "session",
            "login": (session.get("user") or {}).get("login", ""),
            "permissions": set(TOKEN_PERMISSIONS.keys()),
            "github_token": session.get("access_token"),
        }
        g.auth_context = auth
        return auth
    return None

def get_auth_github_token():
    auth = current_auth()
    return auth.get("github_token") if auth else None

def require_permission(permission):
    """Allow normal logged-in browser sessions fully; scope generated tokens."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            auth = current_auth()
            if not auth:
                if request.path.startswith("/api/") or request.is_json:
                    return jsonify({"success": False, "error": "Unauthorized"}), 401
                return redirect(url_for("index"))
            if auth["type"] == "token" and permission not in auth["permissions"]:
                return jsonify({
                    "success": False,
                    "error": f"Token does not have the required permission: {permission}"
                }), 403
            return view(*args, **kwargs)
        return wrapped
    return decorator

def require_session(view):
    """Token administration is intentionally limited to the interactive GitHub login."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("access_token"):
            if request.path.startswith("/api/") or request.is_json:
                return jsonify({"success": False, "error": "Unauthorized"}), 401
            return redirect(url_for("index"))
        return view(*args, **kwargs)
    return wrapped

def _token_list():
    db = _token_db()
    try:
        rows = db.execute(
            """SELECT id, name, token_prefix, token_type, permissions, github_login,
                      created_at, last_used_at, revoked_at, expires_at
               FROM access_tokens ORDER BY id DESC"""
        ).fetchall()
        return [dict(r) | {"permissions": json.loads(r["permissions"])} for r in rows]
    finally:
        db.close()



def get_headers():
    token = get_auth_github_token()
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "GitHub-Commit-Manager",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def compute_accurate_ci_status(owner, repo, sha, headers):
    """
    Computes accurate CI workflow status (like 3/3 or 1/3) by deduplicating job runs
    and correctly handling skipped, neutral, and matrix jobs.
    """
    if sha in CI_CACHE and not CI_CACHE[sha].get("is_running"):
        return CI_CACHE[sha]

    ci_status = None
    try:
        # 1. Primary: Check Runs API (used by GitHub Actions)
        cr_res = requests.get(
            f"{GITHUB_API_URL}/repos/{owner}/{repo}/commits/{sha}/check-runs",
            headers=headers,
            params={"per_page": 50},
            timeout=2.0
        )
        if cr_res.status_code == 200:
            cr_data = cr_res.json()
            raw_runs = cr_data.get("check_runs", [])

            if raw_runs:
                # Deduplicate by job name (keep latest attempt)
                latest_by_name = {}
                for r in sorted(raw_runs, key=lambda x: x.get("id", 0)):
                    latest_by_name[r.get("name")] = r

                total = len(latest_by_name)
                # Success includes 'success', 'neutral', and 'skipped' (standard GitHub passing conclusions)
                success_count = sum(1 for r in latest_by_name.values() if r.get("conclusion") in ["success", "neutral", "skipped"])
                has_failure = any(r.get("conclusion") in ["failure", "timed_out", "cancelled"] for r in latest_by_name.values())
                is_running = any(r.get("status") in ["in_progress", "queued"] for r in latest_by_name.values())

                if has_failure:
                    status_type = "danger"
                elif is_running:
                    status_type = "warning"
                elif success_count == total and total > 0:
                    status_type = "success"
                else:
                    status_type = "secondary"

                ci_status = {
                    "total": total,
                    "success": success_count,
                    "display": f"{success_count}/{total}",
                    "status": status_type,
                    "is_running": is_running,
                }

        # 2. Secondary fallback: Combined Commit Status API
        if not ci_status:
            st_res = requests.get(
                f"{GITHUB_API_URL}/repos/{owner}/{repo}/commits/{sha}/status",
                headers=headers,
                timeout=1.8
            )
            if st_res.status_code == 200:
                st_data = st_res.json()
                statuses = st_data.get("statuses", [])
                if statuses:
                    latest_by_ctx = {}
                    for s in sorted(statuses, key=lambda x: x.get("id", 0)):
                        latest_by_ctx[s.get("context")] = s

                    total = len(latest_by_ctx)
                    success_count = sum(1 for s in latest_by_ctx.values() if s.get("state") == "success")
                    state = st_data.get("state")
                    status_type = "success" if state == "success" else ("danger" if state in ["failure", "error"] else "warning")
                    is_running = state == "pending"
                    ci_status = {
                        "total": total,
                        "success": success_count,
                        "display": f"{success_count}/{total}",
                        "status": status_type,
                        "is_running": is_running
                    }

    except Exception:
        pass

    if ci_status and not ci_status.get("is_running"):
        CI_CACHE[sha] = ci_status

    return ci_status



def get_external_base_url():
    """Return the public base URL used for GitHub OAuth callbacks."""
    if EXTERNAL_BASE_URL:
        return EXTERNAL_BASE_URL.rstrip("/")

    # Respect reverse-proxy headers when no explicit public URL is configured.
    proto = request.headers.get("X-Forwarded-Proto", request.scheme).split(",")[0].strip()
    host = request.headers.get("X-Forwarded-Host", request.host).split(",")[0].strip()
    return f"{proto}://{host}"

def get_callback_url():
    return f"{get_external_base_url()}/callback"


@app.route("/")
def index():
    if "access_token" in session:
        return redirect(url_for("list_repos"))
    return render_template("index.html", client_id=GITHUB_CLIENT_ID)



@app.route("/login-token", methods=["POST"])
def login_token():
    """
    Allows ANY user to connect their GitHub account instantly using a Personal Access Token (PAT),
    supporting both Classic Tokens (ghp_...) and Fine-grained Tokens (github_pat_...).
    """
    token = (request.form.get("pat_token") or "").strip()
    if not token:
        flash("Please enter a GitHub Personal Access Token.", "warning")
        return redirect(url_for("index"))

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "GitHub-Commit-Manager",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        # Step 1: Try /user endpoint (works for all Classic PATs)
        user_res = requests.get(f"{GITHUB_API_URL}/user", headers=headers, timeout=6)
        user_data = None

        if user_res.status_code == 200:
            user_data = user_res.json()
        elif user_res.status_code == 403:
            # Fine-grained PATs might not have /user scope but have /user/repos
            repo_res = requests.get(f"{GITHUB_API_URL}/user/repos?per_page=1", headers=headers, timeout=6)
            if repo_res.status_code == 200:
                sample = repo_res.json()
                owner_login = sample[0]["owner"]["login"] if sample else "GitHub User"
                owner_avatar = sample[0]["owner"]["avatar_url"] if sample else ""
                user_data = {"login": owner_login, "avatar_url": owner_avatar}
            else:
                err_msg = user_res.json().get("message", "Access denied. Ensure token has 'repo' scope.")
                flash(f"GitHub connection failed: {err_msg}", "danger")
                return redirect(url_for("index"))
        elif user_res.status_code == 401:
            flash("GitHub rejected this token: Bad credentials (token may be expired, mistyped, or revoked).", "danger")
            return redirect(url_for("index"))
        else:
            err_msg = user_res.json().get("message", user_res.text)
            flash(f"GitHub API returned error: {err_msg}", "danger")
            return redirect(url_for("index"))

        session["access_token"] = token
        session["user"] = user_data
        session["auth_type"] = "pat"
        flash(f"Connected successfully as {user_data.get('login', 'User')}!", "success")
        return redirect(url_for("list_repos"))

    except requests.exceptions.Timeout:
        flash("Connection timed out reaching api.github.com. Please check your internet connection.", "danger")
        return redirect(url_for("index"))
    except Exception as e:
        flash(f"Connection error: {str(e)}", "danger")
        return redirect(url_for("index"))

@app.route("/login")
def login():
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        flash("GitHub App OAuth is not configured.", "danger")
        return redirect(url_for("index"))

    callback_url = get_external_url("/callback")

    # The GitHub App controls the actual permissions. The OAuth request
    # supplies the public callback URL exposed by the Cloudflare Worker.
    from urllib.parse import urlencode
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": callback_url,
    }

    auth_redirect = f"{GITHUB_AUTH_URL}?{urlencode(params)}"
    return redirect(auth_redirect)


@app.route("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        flash("Authorization failed or was denied.", "danger")
        return redirect(url_for("index"))

    response = requests.post(
        GITHUB_TOKEN_URL,
        headers={"Accept": "application/json"},
        data={
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": get_external_url("/callback"),
        },
    )
    data = response.json()
    token = data.get("access_token")

    if token:
        session["access_token"] = token
        user_res = requests.get(f"{GITHUB_API_URL}/user", headers={"Authorization": f"Bearer {token}"})
        if user_res.status_code == 200:
            session["user"] = user_res.json()
        return redirect(url_for("list_repos"))

    flash(f"Failed to obtain access token: {data.get('error_description')}", "danger")
    return redirect(url_for("index"))



@app.route("/github-app/connect")
@require_session
def github_app_connect():
    if not GITHUB_APP_CLIENT_ID or not GITHUB_APP_CLIENT_SECRET:
        flash("GitHub App is not configured. Set GA_CLIENT_ID and GA_CLIENT_SECRET.", "danger")
        return redirect(url_for("manage_tokens"))

    state = secrets.token_urlsafe(32)
    session["github_app_oauth_state"] = state
    callback_url = get_external_url("/github-app/callback")
    params = {
        "client_id": GITHUB_APP_CLIENT_ID,
        "redirect_uri": callback_url,
        "state": state,
    }
    return redirect(f"{GITHUB_AUTH_URL}?{urlencode(params)}")


@app.route("/github-app/callback")
@require_session
def github_app_callback():
    expected_state = session.pop("github_app_oauth_state", None)
    state = request.args.get("state")
    if not expected_state or not state or not secrets.compare_digest(expected_state, state):
        flash("GitHub App authorization failed: invalid state.", "danger")
        return redirect(url_for("manage_tokens"))

    code = request.args.get("code")
    if not code:
        flash("GitHub App authorization was denied or failed.", "danger")
        return redirect(url_for("manage_tokens"))
    if not GITHUB_APP_CLIENT_ID or not GITHUB_APP_CLIENT_SECRET:
        flash("GitHub App is not configured. Set GA_CLIENT_ID and GA_CLIENT_SECRET.", "danger")
        return redirect(url_for("manage_tokens"))

    callback_url = get_external_url("/github-app/callback")
    response = requests.post(
        GITHUB_TOKEN_URL,
        headers={"Accept": "application/json"},
        data={
            "client_id": GITHUB_APP_CLIENT_ID,
            "client_secret": GITHUB_APP_CLIENT_SECRET,
            "code": code,
            "redirect_uri": callback_url,
        },
        timeout=20,
    )
    try:
        data = response.json()
    except Exception:
        data = {}
    token = data.get("access_token")
    if not token:
        flash(f"GitHub App authorization failed: {data.get('error_description') or data.get('error') or 'no access token returned'}", "danger")
        return redirect(url_for("manage_tokens"))

    session["github_app_access_token"] = token
    user_res = requests.get(
        f"{GITHUB_API_URL}/user",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        timeout=20,
    )
    if user_res.ok:
        session["github_app_user"] = user_res.json()

    flash("GitHub App connected successfully. You can now generate GitHub scoped tokens.", "success")
    return redirect(url_for("manage_tokens"))


@app.route("/github-app/disconnect", methods=["POST"])
@require_session
def github_app_disconnect():
    session.pop("github_app_access_token", None)
    session.pop("github_app_user", None)
    flash("GitHub App disconnected.", "success")
    return redirect(url_for("manage_tokens"))


@app.route("/tokens")
@require_session
def manage_tokens():
    repos = []
    token = get_auth_github_token()
    if token:
        try:
            r = requests.get(
                f"{GITHUB_API_URL}/user/repos?per_page=100&sort=updated",
                headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
                timeout=15,
            )
            if r.ok:
                repos = r.json()
        except requests.RequestException:
            pass
    app_user = session.get("github_app_user") or {}
    return render_template(
        "tokens.html",
        tokens=_token_list(),
        permissions=TOKEN_PERMISSIONS,
        permission_groups=TOKEN_PERMISSION_GROUPS,
        repositories=repos,
        github_app_configured=bool(GITHUB_APP_CLIENT_ID and GITHUB_APP_CLIENT_SECRET),
        github_app_connected=bool(session.get("github_app_access_token")),
        github_app_login=app_user.get("login", ""),
    )

GITHUB_PERMISSION_MAP = {
    "metadata:read": ("metadata", "read"),
    "repos:read": ("metadata", "read"),
    "repos:settings": ("administration", "write"),
    "repos:delete": ("administration", "write"),
    "branches:read": ("contents", "read"),
    "branches:write": ("contents", "write"),
    "files:read": ("contents", "read"),
    "files:write": ("contents", "write"),
    "files:delete": ("contents", "write"),
    "issues:read": ("issues", "read"),
    "issues:write": ("issues", "write"),
    "pulls:read": ("pull_requests", "read"),
    "pulls:write": ("pull_requests", "write"),
    "commits:read": ("contents", "read"),
    "commits:write": ("contents", "write"),
    "actions:read": ("actions", "read"),
    "actions:write": ("actions", "write"),
    "releases:read": ("contents", "read"),
    "releases:write": ("contents", "write"),
    "webhooks:read": ("repository_hooks", "read"),
    "webhooks:write": ("repository_hooks", "write"),
    "collaborators:read": ("administration", "read"),
    "collaborators:write": ("administration", "write"),
    "deployments:read": ("deployments", "read"),
    "deployments:write": ("deployments", "write"),
}

def _github_scoped_permissions(permissions):
    result = {}
    for key in permissions:
        mapped = GITHUB_PERMISSION_MAP.get(key)
        if not mapped:
            continue
        name, level = mapped
        previous = result.get(name)
        if previous == "write" or level == previous:
            continue
        result[name] = level
    return result

def _github_create_scoped_token(user_token, target, repositories, permissions):
    if not GITHUB_APP_CLIENT_ID or not GITHUB_APP_CLIENT_SECRET:
        raise RuntimeError("GitHub App is not configured. Set GA_CLIENT_ID and GA_CLIENT_SECRET")
    if not user_token or not user_token.startswith("ghu_"):
        raise RuntimeError("Connect the GitHub App first; a GitHub App user access token (ghu_...) is required")
    payload = {
        "access_token": user_token,
        "target": target,
        "permissions": permissions,
    }
    if repositories:
        payload["repositories"] = repositories
    response = requests.post(
        f"{GITHUB_API_URL}/applications/{GITHUB_APP_CLIENT_ID}/token/scoped",
        auth=(GITHUB_APP_CLIENT_ID, GITHUB_APP_CLIENT_SECRET),
        headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10"},
        json=payload,
        timeout=20,
    )
    if response.status_code != 200:
        try:
            detail = response.json().get("message") or response.json().get("error")
        except Exception:
            detail = None
        raise RuntimeError(detail or f"GitHub returned HTTP {response.status_code}")
    data = response.json()
    if not data.get("token"):
        raise RuntimeError("GitHub did not return an access token")
    return data

@app.route("/tokens/create", methods=["POST"])
@require_session
def create_app_token():
    name = (request.form.get("name") or "").strip()
    token_type = (request.form.get("token_type") or "normal").strip().lower()
    raw_permissions = request.form.getlist("permissions")
    permissions = [p for p in raw_permissions if p in TOKEN_PERMISSIONS]
    repositories = [r.strip() for r in request.form.getlist("repositories") if r.strip()]
    if not name:
        flash("Token name is required.", "warning")
        return redirect(url_for("manage_tokens"))
    if not permissions:
        flash("Select at least one permission.", "warning")
        return redirect(url_for("manage_tokens"))

    auth = current_auth()
    if not auth or not auth.get("github_token"):
        flash("A valid GitHub login is required to create a token.", "danger")
        return redirect(url_for("index"))

    if token_type == "classic":
        flash("GitHub Classic PATs cannot be created programmatically. Use GitHub's Classic PAT page to create one, then import/use it here.", "warning")
        return redirect("https://github.com/settings/tokens")
    token_type = "github_scoped"

    try:
        github_permissions = _github_scoped_permissions(permissions)
        app_user_token = session.get("github_app_access_token")
        app_user = session.get("github_app_user") or {}
        if not app_user_token:
            session["pending_token_form"] = {
                "name": name,
                "token_type": token_type,
                "permissions": permissions,
                "repositories": repositories,
            }
            flash("Connect your GitHub App first. After authorization, submit Generate GitHub Token again.", "warning")
            return redirect(url_for("github_app_connect"))
        data = _github_create_scoped_token(
            app_user_token,
            app_user.get("login") or auth.get("login") or (session.get("user") or {}).get("login"),
            repositories,
            github_permissions,
        )
    except Exception as exc:
        flash(f"GitHub token creation failed: {exc}", "danger")
        return redirect(url_for("manage_tokens"))

    token = data["token"]
    expires_at = data.get("expires_at")
    db = _token_db()
    try:
        # Keep the GitHub-issued token encrypted locally so Git Manager can
        # use it for API calls. The raw token is never shown again after this response.
        db.execute(
            """INSERT INTO access_tokens
               (name, token_hash, token_prefix, token_type, permissions, github_token,
                github_login, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                name, _token_hash(token), token[:14] + "…", token_type,
                json.dumps(permissions), TOKEN_CIPHER.encrypt(token.encode()).decode(),
                (session.get("github_app_user") or {}).get("login") or auth.get("login") or (session.get("user") or {}).get("login", "GitHub User"),
                _now_iso(),
                expires_at,
            ),
        )
        db.commit()
    finally:
        db.close()

    return render_template(
        "token_created.html",
        token=token,
        name=name,
        token_type=token_type,
        permissions=[TOKEN_PERMISSIONS[p] for p in permissions],
        expires_at=expires_at,
        github_issued=True,
    )

@app.route("/tokens/<int:token_id>/revoke", methods=["POST"])
@require_permission("repos:read")
def revoke_app_token(token_id):
    db = _token_db()
    try:
        row = db.execute("SELECT * FROM access_tokens WHERE id = ? AND revoked_at IS NULL", (token_id,)).fetchone()
        if not row:
            flash("Token not found or already revoked.", "warning")
            return redirect(url_for("manage_tokens"))
        try:
            raw = TOKEN_CIPHER.decrypt(row["github_token"].encode()).decode()
            if row["token_type"] == "github_scoped" and GITHUB_APP_CLIENT_ID and GITHUB_APP_CLIENT_SECRET:
                requests.delete(
                    f"{GITHUB_API_URL}/applications/{GITHUB_APP_CLIENT_ID}/token",
                    auth=(GITHUB_APP_CLIENT_ID, GITHUB_APP_CLIENT_SECRET),
                    headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10"},
                    json={"access_token": raw}, timeout=20,
                )
        except Exception:
            pass
        db.execute(
            "UPDATE access_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (_now_iso(), token_id),
        )
        db.commit()
    finally:
        db.close()
    flash("Token revoked successfully.", "success")
    return redirect(url_for("manage_tokens"))

@app.route("/logout")
def logout():
    session.clear()
    flash("Successfully logged out.", "info")
    return redirect(url_for("index"))


@app.route("/repos")
@require_permission("repos:read")
def list_repos():
    if not current_auth():
        return redirect(url_for("index"))

    repos = []
    page = 1
    headers = get_headers()

    while True:
        res = requests.get(
            f"{GITHUB_API_URL}/user/repos",
            headers=headers,
            params={"type": "all", "sort": "updated", "per_page": 100, "page": page},
        )
        
        # 1. Handle expired or invalid token
        if res.status_code == 401:
            session.clear()
            flash("Your GitHub session has expired. Please sign in again.", "warning")
            return redirect(url_for("login"))

        # 2. Handle GitHub rate limit
        if res.status_code == 403:
            reset_ts = res.headers.get("x-ratelimit-reset")
            msg = "GitHub API rate limit temporarily reached."
            if reset_ts:
                try:
                    import datetime
                    reset_time = datetime.datetime.fromtimestamp(int(reset_ts)).strftime("%I:%M %p")
                    msg += f" Rate limit resets at {reset_time}."
                except Exception:
                    pass
            flash(msg + " Please sign out and re-login, or wait a few minutes.", "warning")
            break

        # 3. Handle other API errors
        if res.status_code != 200:
            err_detail = res.json().get("message", res.text) if res.text else f"Status {res.status_code}"
            flash(f"Error fetching repositories from GitHub: {err_detail}", "danger")
            break

        batch = res.json()
        if not batch:
            break
        repos.extend(batch)
        page += 1
        if len(batch) < 100:
            break

    return render_template("repos.html", repos=repos, user=session.get("user"))



def github_error_message(res, fallback="GitHub API request failed"):
    try:
        data = res.json()
        return data.get("message") or fallback
    except Exception:
        return res.text or fallback


def get_commit_author_config(data=None):
    """Return the selected author identity for Contents API commits."""
    data = data or {}
    user = session.get("user", {}) or {}
    mode = (data.get("author_mode") or "account").strip().lower()
    account_name = (user.get("name") or user.get("login") or "GitHub User").strip()
    account_email = (user.get("email") or "").strip()
    if not account_email and user.get("id") and user.get("login"):
        account_email = f'{user["id"]}+{user["login"]}@users.noreply.github.com'
    if not account_email and user.get("login"):
        account_email = f'{user["login"]}@users.noreply.github.com'

    if mode == "manual":
        name = (data.get("author_name") or "").strip()
        email = (data.get("author_email") or "").strip()
        if not name:
            raise ValueError("Manual author name is required")
        if not email:
            email = account_email
        return name, email

    return account_name, account_email


@app.route("/repo/<owner>/<repo>/manage")
@require_permission("repos:read")
def manage_repo(owner, repo):
    if not current_auth():
        return redirect(url_for("index"))

    headers = get_headers()
    repo_res = requests.get(f"{GITHUB_API_URL}/repos/{owner}/{repo}", headers=headers, timeout=8)
    if repo_res.status_code != 200:
        flash(f"Unable to open repository: {github_error_message(repo_res)}", "danger")
        return redirect(url_for("list_repos"))
    repo_info = repo_res.json()

    branches_res = requests.get(f"{GITHUB_API_URL}/repos/{owner}/{repo}/branches", headers=headers, params={"per_page": 100}, timeout=8)
    branches = branches_res.json() if branches_res.status_code == 200 else []
    branch = request.args.get("branch") or repo_info.get("default_branch", "main")
    tree_res = requests.get(
        f"{GITHUB_API_URL}/repos/{owner}/{repo}/git/trees/{quote(branch, safe='')}",
        headers=headers,
        params={"recursive": "1"},
        timeout=10,
    )
    tree = tree_res.json() if tree_res.status_code == 200 else {"tree": []}
    entries = []
    for item in tree.get("tree", []):
        if item.get("type") in ("blob", "tree"):
            entries.append({
                "path": item.get("path", ""),
                "type": "file" if item.get("type") == "blob" else "folder",
                "sha": item.get("sha", ""),
                "size": item.get("size", 0),
            })

    entries.sort(key=lambda x: (x["type"] != "folder", x["path"].lower()))
    return render_template(
        "repo_manager.html",
        owner=owner,
        repo=repo,
        repo_info=repo_info,
        branch=branch,
        entries=entries,
        branches=branches,
        author_default_name=(session.get("user", {}) or {}).get("name") or (session.get("user", {}) or {}).get("login", "GitHub User"),
        author_default_email=(session.get("user", {}) or {}).get("email") or ((session.get("user", {}) or {}).get("login", "") + "@users.noreply.github.com"),
    )


@app.route("/repo/<owner>/<repo>/settings", methods=["POST"])
@require_permission("repos:settings")
def update_repo_settings(owner, repo):
    if not current_auth():
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.get_json() or {}
    description = data.get("description")
    if description is None:
        return jsonify({"success": False, "error": "Description is required"}), 400
    description = str(description).strip()
    if len(description) > 350:
        return jsonify({"success": False, "error": "Description must be 350 characters or less"}), 400

    res = requests.patch(
        f"{GITHUB_API_URL}/repos/{owner}/{repo}",
        headers=get_headers(),
        json={"description": description},
        timeout=8,
    )
    if res.status_code != 200:
        return jsonify({"success": False, "error": github_error_message(res, "Could not update repository description")}), res.status_code
    return jsonify({"success": True, "description": res.json().get("description") or ""})


@app.route("/repo/<owner>/<repo>/delete", methods=["POST"])
@require_permission("repos:delete")
def delete_repo(owner, repo):
    if not current_auth():
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.get_json() or {}
    confirmation = (data.get("confirmation") or "").strip()
    expected = f"{owner}/{repo}"
    if confirmation != expected:
        return jsonify({"success": False, "error": f'Type "{expected}" exactly to confirm deletion.'}), 400

    res = requests.delete(f"{GITHUB_API_URL}/repos/{owner}/{repo}", headers=get_headers(), timeout=10)
    if res.status_code not in (204, 200):
        return jsonify({"success": False, "error": github_error_message(res, "Could not delete repository")}), res.status_code
    return jsonify({"success": True, "redirect": url_for("list_repos")})


@app.route("/repo/<owner>/<repo>/file/upload", methods=["POST"])
@require_permission("files:write")
def upload_repo_file(owner, repo):
    if not current_auth():
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    path = (request.form.get("path") or "").strip().lstrip("/")
    branch = (request.form.get("branch") or "").strip()
    commit_message = (request.form.get("commit_message") or "").strip() or f"Add {path or 'file'}"
    if not path or path.endswith("/") or ".." in path.split("/"):
        return jsonify({"success": False, "error": "Enter a valid file path inside the repository."}), 400
    upload = request.files.get("file")
    if not upload or not upload.filename:
        return jsonify({"success": False, "error": "Select a file to upload."}), 400

    content = upload.read()
    if len(content) > 95 * 1024 * 1024:
        return jsonify({"success": False, "error": "File is too large for the GitHub Contents API (95 MB limit in this app)."}), 400

    try:
        author_name, author_email = get_commit_author_config(request.form)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400

    payload = {
        "message": commit_message,
        "content": __import__("base64").b64encode(content).decode("ascii"),
        "branch": branch or None,
        "author": {"name": author_name, "email": author_email},
        "committer": {"name": author_name, "email": author_email},
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    res = requests.put(f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{quote(path, safe='/')}", headers=get_headers(), json=payload, timeout=20)
    if res.status_code not in (200, 201):
        return jsonify({"success": False, "error": github_error_message(res, "Could not upload file")}), res.status_code
    return jsonify({"success": True, "path": path, "commit": res.json().get("commit", {}).get("sha", "")})


@app.route("/repo/<owner>/<repo>/file/create", methods=["POST"])
@require_permission("files:write")
def create_repo_file(owner, repo):
    if not current_auth():
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    data = request.get_json() or {}
    path = (data.get("path") or "").strip().lstrip("/")
    branch = (data.get("branch") or "").strip()
    if not path or path.endswith("/") or ".." in path.split("/"):
        return jsonify({"success": False, "error": "Enter a valid file path."}), 400
    try:
        author_name, author_email = get_commit_author_config(data)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    payload = {
        "message": (data.get("commit_message") or f"Create {path}").strip(),
        "content": __import__("base64").b64encode((data.get("content") or "").encode("utf-8")).decode("ascii"),
        "author": {"name": author_name, "email": author_email},
        "committer": {"name": author_name, "email": author_email},
    }
    if branch:
        payload["branch"] = branch
    res = requests.put(f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{quote(path, safe='/')}", headers=get_headers(), json=payload, timeout=15)
    if res.status_code not in (200, 201):
        return jsonify({"success": False, "error": github_error_message(res, "Could not create file")}), res.status_code
    return jsonify({"success": True, "path": path})


@app.route("/repo/<owner>/<repo>/folder/create", methods=["POST"])
@require_permission("files:write")
def create_repo_folder(owner, repo):
    if not current_auth():
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    data = request.get_json() or {}
    folder = (data.get("path") or "").strip().strip("/")
    branch = (data.get("branch") or "").strip()
    if not folder or ".." in folder.split("/"):
        return jsonify({"success": False, "error": "Enter a valid folder path."}), 400
    keep_path = f"{folder}/.gitkeep"
    try:
        author_name, author_email = get_commit_author_config(data)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    payload = {
        "message": (data.get("commit_message") or f"Create folder {folder}").strip(),
        "content": __import__("base64").b64encode(b"").decode("ascii"),
        "author": {"name": author_name, "email": author_email},
        "committer": {"name": author_name, "email": author_email},
    }
    if branch:
        payload["branch"] = branch
    res = requests.put(f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{quote(keep_path, safe='/')}", headers=get_headers(), json=payload, timeout=15)
    if res.status_code not in (200, 201):
        return jsonify({"success": False, "error": github_error_message(res, "Could not create folder")}), res.status_code
    return jsonify({"success": True, "path": folder, "placeholder": keep_path})


@app.route("/repo/<owner>/<repo>/file/content")
@require_permission("files:read")
def get_repo_file_content(owner, repo):
    if not current_auth():
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    path = (request.args.get("path") or "").strip().lstrip("/")
    branch = (request.args.get("branch") or "").strip()
    if not path or path.endswith("/") or ".." in path.split("/"):
        return jsonify({"success": False, "error": "Enter a valid file path."}), 400
    params = {"ref": branch} if branch else {}
    res = requests.get(
        f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{quote(path, safe='/')}",
        headers=get_headers(), params=params, timeout=15
    )
    if res.status_code != 200:
        return jsonify({"success": False, "error": github_error_message(res, "Could not read file")}), res.status_code
    data = res.json()
    if data.get("type") != "file":
        return jsonify({"success": False, "error": "Selected path is not a file."}), 400
    try:
        content = __import__("base64").b64decode((data.get("content") or "").replace("\n", "")).decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return jsonify({"success": False, "error": "This file is binary or is not valid UTF-8 and cannot be edited in the web editor."}), 400
    return jsonify({"success": True, "path": path, "sha": data.get("sha", ""), "content": content})


@app.route("/repo/<owner>/<repo>/file/edit", methods=["POST"])
@require_permission("files:write")
def edit_repo_file(owner, repo):
    if not current_auth():
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    data = request.get_json() or {}
    path = (data.get("path") or "").strip().lstrip("/")
    branch = (data.get("branch") or "").strip()
    sha = (data.get("sha") or "").strip()
    if not path or path.endswith("/") or ".." in path.split("/"):
        return jsonify({"success": False, "error": "Enter a valid file path."}), 400
    if not sha:
        return jsonify({"success": False, "error": "File SHA is required."}), 400
    try:
        author_name, author_email = get_commit_author_config(data)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    payload = {
        "message": (data.get("commit_message") or f"Update {path}").strip(),
        "content": __import__("base64").b64encode((data.get("content") or "").encode("utf-8")).decode("ascii"),
        "sha": sha,
        "author": {"name": author_name, "email": author_email},
        "committer": {"name": author_name, "email": author_email},
    }
    if branch:
        payload["branch"] = branch
    res = requests.put(
        f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{quote(path, safe='/')}",
        headers=get_headers(), json=payload, timeout=20
    )
    if res.status_code not in (200, 201):
        return jsonify({"success": False, "error": github_error_message(res, "Could not update file")}), res.status_code
    return jsonify({"success": True, "path": path, "commit": res.json().get("commit", {}).get("sha", "")})


@app.route("/repo/<owner>/<repo>/file/delete", methods=["POST"])
@require_permission("files:delete")
def delete_repo_file(owner, repo):
    if not current_auth():
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    data = request.get_json() or {}
    path = (data.get("path") or "").strip().lstrip("/")
    branch = (data.get("branch") or "").strip()
    sha = (data.get("sha") or "").strip()
    if not path or not sha:
        return jsonify({"success": False, "error": "File path and SHA are required."}), 400
    try:
        author_name, author_email = get_commit_author_config(data)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    payload = {
        "message": (data.get("commit_message") or f"Delete {path}").strip(),
        "sha": sha,
        "author": {"name": author_name, "email": author_email},
        "committer": {"name": author_name, "email": author_email},
    }
    if branch:
        payload["branch"] = branch
    res = requests.delete(f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{quote(path, safe='/')}", headers=get_headers(), json=payload, timeout=15)
    if res.status_code != 200:
        return jsonify({"success": False, "error": github_error_message(res, "Could not delete file")}), res.status_code
    return jsonify({"success": True, "path": path})


@app.route("/repo/<owner>/<repo>/download")
@require_permission("files:read")
def download_repo(owner, repo):
    if not current_auth():
        return redirect(url_for("index"))
    branch = request.args.get("branch") or "main"
    upstream = requests.get(
        f"{GITHUB_API_URL}/repos/{owner}/{repo}/zipball/{quote(branch, safe='')}",
        headers=get_headers(),
        stream=True,
        timeout=20,
    )
    if upstream.status_code != 200:
        flash(f"Could not download repository: {github_error_message(upstream)}", "danger")
        return redirect(url_for("manage_repo", owner=owner, repo=repo, branch=branch))

    def generate():
        try:
            for chunk in upstream.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    yield chunk
        finally:
            upstream.close()

    return Response(
        generate(),
        status=200,
        content_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{owner}-{repo}-{branch}.zip"'},
    )


@app.route("/repo/<owner>/<repo>")
@require_permission("commits:read")
def repo_commits(owner, repo):
    if not current_auth():
        return redirect(url_for("index"))

    headers = get_headers()

    branch_res = requests.get(f"{GITHUB_API_URL}/repos/{owner}/{repo}/branches", headers=headers)
    branches = branch_res.json() if branch_res.status_code == 200 else []

    branch = request.args.get("branch")
    if not branch:
        repo_info = requests.get(f"{GITHUB_API_URL}/repos/{owner}/{repo}", headers=headers).json()
        branch = repo_info.get("default_branch", "main")

    commits_res = requests.get(
        f"{GITHUB_API_URL}/repos/{owner}/{repo}/commits",
        headers=headers,
        params={"sha": branch, "per_page": 40},
    )
    commits = commits_res.json() if commits_res.status_code == 200 else []

    # Parallel fast CI status retrieval for top 12 commits
    def attach_ci(c):
        c["ci_status"] = compute_accurate_ci_status(owner, repo, c["sha"], headers)
        return c

    with ThreadPoolExecutor(max_workers=6) as pool:
        commits[:12] = list(pool.map(attach_ci, commits[:12]))

    backup_key = f"backup_{owner}_{repo}_{branch}"
    last_backup_sha = session.get(backup_key)

    return render_template(
        "commits.html",
        owner=owner,
        repo=repo,
        branch=branch,
        branches=branches,
        commits=commits,
        last_backup_sha=last_backup_sha,
    )


@app.route("/api/repo/<owner>/<repo>/commits")
@require_permission("commits:read")
def api_commits(owner, repo):
    """
    Ultra-fast real-time JSON endpoint for live polling without delays.
    """
    if not current_auth():
        return jsonify({"error": "Unauthorized"}), 401

    headers = get_headers()
    branch = request.args.get("branch")
    if not branch:
        repo_info = requests.get(f"{GITHUB_API_URL}/repos/{owner}/{repo}", headers=headers).json()
        branch = repo_info.get("default_branch", "main")

    commits_res = requests.get(
        f"{GITHUB_API_URL}/repos/{owner}/{repo}/commits",
        headers=headers,
        params={"sha": branch, "per_page": 35},
    )
    raw_commits = commits_res.json() if commits_res.status_code == 200 else []

    # Process items
    formatted = []
    for c in raw_commits:
        msg = c.get("commit", {}).get("message", "").split("\n")[0]
        author = c.get("commit", {}).get("author", {}).get("name", "Unknown")
        date_str = c.get("commit", {}).get("author", {}).get("date", "")[:10] if c.get("commit", {}).get("author", {}).get("date") else ""
        formatted.append({
            "sha": c["sha"],
            "short_sha": c["sha"][:7],
            "message": msg,
            "author_name": author,
            "date": date_str,
            "ci_status": None
        })

    # Parallel fast CI status retrieval for top 10 commits
    def attach_fast_ci(item):
        item["ci_status"] = compute_accurate_ci_status(owner, repo, item["sha"], headers)
        return item

    # Only fetch CI for top 4 commits to conserve GitHub API rate limits
    with ThreadPoolExecutor(max_workers=4) as pool:
        formatted[:4] = list(pool.map(attach_fast_ci, formatted[:4]))

    return jsonify({"commits": formatted, "branch": branch})


@app.route("/repo/<owner>/<repo>/delete-commits", methods=["POST"])
@require_permission("commits:write")
def delete_commits(owner, repo):
    token = get_auth_github_token()
    if not token:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    headers = get_headers()
    data = request.get_json() or {}
    branch = data.get("branch")
    selected_shas = set(data.get("commit_shas", []))
    strategy = data.get("strategy", "absorb_code_drop_history")
    custom_msg = data.get("commit_message", "Clean history (removed unwanted commits)")

    if not branch or not selected_shas:
        return jsonify({"success": False, "error": "Missing branch or selected commits"}), 400

    ref_res = requests.get(f"{GITHUB_API_URL}/repos/{owner}/{repo}/git/ref/heads/{branch}", headers=headers)
    if ref_res.status_code != 200:
        return jsonify({"success": False, "error": "Could not fetch current branch ref from GitHub"}), 400

    original_head_sha = ref_res.json()["object"]["sha"]
    backup_key = f"backup_{owner}_{repo}_{branch}"
    session[backup_key] = original_head_sha

    ts = int(time.time())
    backup_tag_name = f"backup-{branch}-{ts}"
    requests.post(
        f"{GITHUB_API_URL}/repos/{owner}/{repo}/git/refs",
        headers=headers,
        json={"ref": f"refs/tags/{backup_tag_name}", "sha": original_head_sha}
    )

    temp_dir = tempfile.mkdtemp(prefix="git_rebase_")
    auth_repo_url = f"https://x-access-token:{token}@github.com/{owner}/{repo}.git"

    try:
        clone_cmd = [
            "git", "clone",
            "--branch", branch,
            auth_repo_url,
            temp_dir
        ]
        res = subprocess.run(clone_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode != 0:
            return jsonify({"success": False, "error": f"Git clone failed: {res.stderr}"}), 400

        user_info = session.get("user", {})
        git_user = user_info.get("login", "Commit Manager")
        git_email = user_info.get("email") or f"{git_user}@users.noreply.github.com"
        subprocess.run(["git", "config", "user.name", git_user], cwd=temp_dir, check=True)
        subprocess.run(["git", "config", "user.email", git_email], cwd=temp_dir, check=True)

        log_res = subprocess.check_output(
            ["git", "log", "--reverse", "--format=%H"],
            cwd=temp_dir,
            text=True
        ).strip().splitlines()
        commits_in_branch = [sha.strip() for sha in log_res if sha.strip()]

        first_selected_idx = None
        for idx, sha in enumerate(commits_in_branch):
            if sha in selected_shas:
                first_selected_idx = idx
                break

        if first_selected_idx is None:
            return jsonify({"success": False, "error": "Selected commits not found in branch history"}), 400

        base_parent_sha = commits_in_branch[first_selected_idx - 1] if first_selected_idx > 0 else None

        if strategy == "rollback_to_base":
            if not base_parent_sha:
                return jsonify({
                    "success": False,
                    "error": "Cannot rollback past initial commit"
                }), 400

            # Verify that the rollback target exists locally.
            verify_res = subprocess.run(
                ["git", "cat-file", "-e", f"{base_parent_sha}^{{commit}}"],
                cwd=temp_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # If the commit is missing, refresh the branch history.
            if verify_res.returncode != 0:
                fetch_res = subprocess.run(
                    ["git", "fetch", "--no-tags", "origin", branch],
                    cwd=temp_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                if fetch_res.returncode != 0:
                    return jsonify({
                        "success": False,
                        "error": (
                            "Could not fetch branch history before rollback: "
                            f"{fetch_res.stderr.strip()}"
                        )
                    }), 400

                # Verify again after fetching.
                verify_res = subprocess.run(
                    ["git", "cat-file", "-e", f"{base_parent_sha}^{{commit}}"],
                    cwd=temp_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                if verify_res.returncode != 0:
                    return jsonify({
                        "success": False,
                        "error": (
                            f"Rollback target commit {base_parent_sha} "
                            "is not available in the cloned branch history."
                        )
                    }), 400

            # Reset only after confirming the target commit exists.
            reset_res = subprocess.run(
                ["git", "reset", "--hard", base_parent_sha],
                cwd=temp_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if reset_res.returncode != 0:
                return jsonify({
                    "success": False,
                    "error": f"Git reset failed: {reset_res.stderr.strip()}"
                }), 400

        elif strategy == "preserve_files":
            if base_parent_sha:
                verify_res = subprocess.run(
                    ["git", "cat-file", "-e", f"{base_parent_sha}^{{commit}}"],
                    cwd=temp_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                if verify_res.returncode != 0:
                    fetch_res = subprocess.run(
                        ["git", "fetch", "--no-tags", "origin", branch],
                        cwd=temp_dir,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )

                    if fetch_res.returncode != 0:
                        return jsonify({
                            "success": False,
                            "error": (
                                "Could not fetch branch history before preserving files: "
                                f"{fetch_res.stderr.strip()}"
                            )
                        }), 400

                    verify_res = subprocess.run(
                        ["git", "cat-file", "-e", f"{base_parent_sha}^{{commit}}"],
                        cwd=temp_dir,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )

                    if verify_res.returncode != 0:
                        return jsonify({
                            "success": False,
                            "error": (
                                f"Base commit {base_parent_sha} "
                                "is not available in the cloned branch history."
                            )
                        }), 400

                reset_res = subprocess.run(
                    ["git", "reset", "--hard", base_parent_sha],
                    cwd=temp_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                if reset_res.returncode != 0:
                    return jsonify({
                        "success": False,
                        "error": f"Git reset failed: {reset_res.stderr.strip()}"
                    }), 400

            # original_head_sha came from GitHub's branch reference, so verify it too.
            checkout_res = subprocess.run(
                ["git", "cat-file", "-e", f"{original_head_sha}^{{commit}}"],
                cwd=temp_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if checkout_res.returncode != 0:
                fetch_res = subprocess.run(
                    ["git", "fetch", "--no-tags", "origin", branch],
                    cwd=temp_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                if fetch_res.returncode != 0:
                    return jsonify({
                        "success": False,
                        "error": (
                            "Could not fetch original HEAD before preserving files: "
                            f"{fetch_res.stderr.strip()}"
                        )
                    }), 400

            checkout_res = subprocess.run(
                ["git", "checkout", original_head_sha, "--", "."],
                cwd=temp_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if checkout_res.returncode != 0:
                return jsonify({
                    "success": False,
                    "error": f"Git checkout failed: {checkout_res.stderr.strip()}"
                }), 400

            subprocess.run(["git", "add", "-A"], cwd=temp_dir, check=True)

            fmt = "%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI"
            meta = subprocess.check_output(["git", "log", "-1", f"--format={fmt}", original_head_sha], cwd=temp_dir, text=True).strip().split("\x00")
            an, ae, ad, cn, ce, cd = meta
            commit_env = os.environ.copy()
            commit_env["GIT_AUTHOR_NAME"] = an
            commit_env["GIT_AUTHOR_EMAIL"] = ae
            commit_env["GIT_AUTHOR_DATE"] = ad
            commit_env["GIT_COMMITTER_NAME"] = cn
            commit_env["GIT_COMMITTER_EMAIL"] = ce
            commit_env["GIT_COMMITTER_DATE"] = cd
            subprocess.run(["git", "commit", "-m", custom_msg], cwd=temp_dir, env=commit_env, check=True)

        else:
            # Tree-chain absorption preserving exact original dates and authors
            current_parent = base_parent_sha

            for idx in range(first_selected_idx, len(commits_in_branch)):
                sha = commits_in_branch[idx]
                if sha in selected_shas:
                    continue

                tree = subprocess.check_output(["git", "rev-parse", f"{sha}^{{tree}}"], cwd=temp_dir, text=True).strip()
                msg = subprocess.check_output(["git", "log", "-1", "--format=%B", sha], cwd=temp_dir, text=True).strip()

                fmt = "%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI"
                meta = subprocess.check_output(["git", "log", "-1", f"--format={fmt}", sha], cwd=temp_dir, text=True).strip().split("\x00")
                an, ae, ad, cn, ce, cd = meta

                commit_env = os.environ.copy()
                commit_env["GIT_AUTHOR_NAME"] = an
                commit_env["GIT_AUTHOR_EMAIL"] = ae
                commit_env["GIT_AUTHOR_DATE"] = ad
                commit_env["GIT_COMMITTER_NAME"] = cn
                commit_env["GIT_COMMITTER_EMAIL"] = ce
                commit_env["GIT_COMMITTER_DATE"] = cd

                cmd = ["git", "commit-tree", tree, "-m", msg]
                if current_parent:
                    cmd.extend(["-p", current_parent])
                p = subprocess.Popen(cmd, cwd=temp_dir, env=commit_env, stdout=subprocess.PIPE, text=True)
                new_sha, _ = p.communicate()
                new_sha = new_sha.strip()
                current_parent = new_sha

            if not current_parent:
                return jsonify({"success": False, "error": "All commits were selected."}), 400

            subprocess.run(["git", "reset", "--hard", current_parent], cwd=temp_dir, check=True)

        push_res = subprocess.run(
            ["git", "push", "origin", f"HEAD:{branch}", "--force"],
            cwd=temp_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if push_res.returncode != 0:
            return jsonify({
                "success": False,
                "error": f"Force push failed: {push_res.stderr}. Check branch protection settings on GitHub."
            }), 400

        # Clear CI cache on branch update
        CI_CACHE.clear()

        return jsonify({
            "success": True,
            "branch": branch,
            "backup_sha": original_head_sha,
            "backup_tag": backup_tag_name,
            "local_sync_instructions": [
                f"git checkout {branch}",
                f"git fetch origin {branch}",
                f"git reset --hard origin/{branch}",
            ],
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.route("/repo/<owner>/<repo>/restore", methods=["POST"])
@require_permission("commits:write")
def restore_commit(owner, repo):
    token = get_auth_github_token()
    if not token:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    headers = get_headers()
    data = request.get_json() or {}
    branch = data.get("branch")
    target_sha = (data.get("target_sha") or "").strip()

    if not branch or not target_sha:
        return jsonify({"success": False, "error": "Missing branch or target commit SHA"}), 400

    commit_check = requests.get(f"{GITHUB_API_URL}/repos/{owner}/{repo}/commits/{target_sha}", headers=headers)
    if commit_check.status_code != 200:
        return jsonify({
            "success": False,
            "error": f"Commit {target_sha} not found on GitHub. Make sure the SHA is correct."
        }), 400

    update_res = requests.patch(
        f"{GITHUB_API_URL}/repos/{owner}/{repo}/git/refs/heads/{branch}",
        headers=headers,
        json={"sha": target_sha, "force": True},
    )

    if update_res.status_code != 200:
        return jsonify({
            "success": False,
            "error": f"Failed to restore branch on GitHub: {update_res.text}"
        }), 400

    CI_CACHE.clear()

    return jsonify({
        "success": True,
        "restored_sha": target_sha,
        "branch": branch,
        "local_sync_instructions": [
            f"git checkout {branch}",
            f"git fetch origin {branch}",
            f"git reset --hard origin/{branch}",
        ]
    })


@app.route("/api/repo/<owner>/<repo>/commit/<sha>")
@require_permission("commits:read")
def api_commit_detail(owner, repo, sha):
    """
    Returns full commit diff details with file tree, additions (+), and deletions (-).
    """
    if not current_auth():
        return jsonify({"error": "Unauthorized"}), 401

    headers = get_headers()
    res = requests.get(
        f"{GITHUB_API_URL}/repos/{owner}/{repo}/commits/{sha}",
        headers=headers,
        timeout=5
    )
    if res.status_code != 200:
        return jsonify({"error": "Could not fetch commit details from GitHub"}), 400

    data = res.json()
    files = []
    for f in data.get("files", []):
        files.append({
            "filename": f.get("filename"),
            "status": f.get("status"),
            "additions": f.get("additions", 0),
            "deletions": f.get("deletions", 0),
            "changes": f.get("changes", 0),
            "patch": f.get("patch", "")
        })

    stats = data.get("stats", {})
    commit_meta = data.get("commit", {})

    return jsonify({
        "sha": sha,
        "short_sha": sha[:7],
        "message": commit_meta.get("message", ""),
        "author_name": commit_meta.get("author", {}).get("name", "Unknown"),
        "author_email": commit_meta.get("author", {}).get("email", ""),
        "author_date": commit_meta.get("author", {}).get("date", ""),
        "stats": stats,
        "files": files,
    })



@app.route("/repo/<owner>/<repo>/rename-commit", methods=["POST"])
@require_permission("commits:write")
def rename_commit(owner, repo):
    """
    Renames any commit message in history while preserving all code, authors, and timestamps.
    """
    token = get_auth_github_token()
    if not token:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    headers = get_headers()
    data = request.get_json() or {}
    branch = data.get("branch")
    target_sha = data.get("target_sha")
    new_message = (data.get("new_message") or "").strip()

    if not branch or not target_sha or not new_message:
        return jsonify({"success": False, "error": "Missing branch, target commit, or new message"}), 400

    ref_res = requests.get(f"{GITHUB_API_URL}/repos/{owner}/{repo}/git/ref/heads/{branch}", headers=headers)
    if ref_res.status_code != 200:
        return jsonify({"success": False, "error": "Could not fetch branch reference"}), 400

    original_head_sha = ref_res.json()["object"]["sha"]
    backup_key = f"backup_{owner}_{repo}_{branch}"
    session[backup_key] = original_head_sha

    ts = int(time.time())
    requests.post(
        f"{GITHUB_API_URL}/repos/{owner}/{repo}/git/refs",
        headers=headers,
        json={"ref": f"refs/tags/backup-{branch}-{ts}", "sha": original_head_sha}
    )

    temp_dir = tempfile.mkdtemp(prefix="git_rename_")
    auth_repo_url = f"https://x-access-token:{token}@github.com/{owner}/{repo}.git"

    try:
        clone_cmd = [
            "git", "clone",
            "--branch", branch,
            auth_repo_url,
            temp_dir
        ]
        res = subprocess.run(clone_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode != 0:
            return jsonify({"success": False, "error": f"Git clone failed: {res.stderr}"}), 400

        user_info = session.get("user", {})
        git_user = user_info.get("login", "Commit Manager")
        git_email = user_info.get("email") or f"{git_user}@users.noreply.github.com"
        subprocess.run(["git", "config", "user.name", git_user], cwd=temp_dir, check=True)
        subprocess.run(["git", "config", "user.email", git_email], cwd=temp_dir, check=True)

        log_res = subprocess.check_output(
            ["git", "log", "--reverse", "--format=%H"],
            cwd=temp_dir,
            text=True
        ).strip().splitlines()
        commits_in_branch = [sha.strip() for sha in log_res if sha.strip()]

        if target_sha not in commits_in_branch:
            return jsonify({"success": False, "error": "Target commit not found in branch history"}), 400

        target_idx = commits_in_branch.index(target_sha)
        current_parent = commits_in_branch[target_idx - 1] if target_idx > 0 else None

        for idx in range(target_idx, len(commits_in_branch)):
            sha = commits_in_branch[idx]
            tree = subprocess.check_output(["git", "rev-parse", f"{sha}^{{tree}}"], cwd=temp_dir, text=True).strip()

            if sha == target_sha:
                msg = new_message
            else:
                msg = subprocess.check_output(["git", "log", "-1", "--format=%B", sha], cwd=temp_dir, text=True).strip()

            fmt = "%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI"
            meta = subprocess.check_output(["git", "log", "-1", f"--format={fmt}", sha], cwd=temp_dir, text=True).strip().split("\x00")
            an, ae, ad, cn, ce, cd = meta

            commit_env = os.environ.copy()
            commit_env["GIT_AUTHOR_NAME"] = an
            commit_env["GIT_AUTHOR_EMAIL"] = ae
            commit_env["GIT_AUTHOR_DATE"] = ad
            commit_env["GIT_COMMITTER_NAME"] = cn
            commit_env["GIT_COMMITTER_EMAIL"] = ce
            commit_env["GIT_COMMITTER_DATE"] = cd

            cmd = ["git", "commit-tree", tree, "-m", msg]
            if current_parent:
                cmd.extend(["-p", current_parent])
            p = subprocess.Popen(cmd, cwd=temp_dir, env=commit_env, stdout=subprocess.PIPE, text=True)
            new_sha, _ = p.communicate()
            new_sha = new_sha.strip()
            current_parent = new_sha

        subprocess.run(["git", "reset", "--hard", current_parent], cwd=temp_dir, check=True)
        push_res = subprocess.run(
            ["git", "push", "origin", f"HEAD:{branch}", "--force"],
            cwd=temp_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if push_res.returncode != 0:
            return jsonify({"success": False, "error": f"Force push failed: {push_res.stderr}"}), 400

        CI_CACHE.clear()

        return jsonify({
            "success": True,
            "branch": branch,
            "new_head_sha": current_parent,
            "local_sync_instructions": [
                f"git checkout {branch}",
                f"git fetch origin {branch}",
                f"git reset --hard origin/{branch}",
            ],
        })

    except subprocess.CalledProcessError as e:
        return jsonify({
            "success": False,
            "error": f"Git command failed (exit {e.returncode}): {e}"
        }), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", debug=False, port=port)
