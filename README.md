# GitHub Commit History Manager (Flask Web App)

A web application built with Flask that connects to GitHub OAuth, lists all public and private repositories, presents commit logs, and allows you to safely remove unwanted commits from GitHub without losing local project files.

## Features
- **GitHub OAuth 2.0 Integration**: Secure login with `repo` scope to manage public and private repositories.
- **Repository Browser**: List all accessible repositories with real-time filtering, visibility badges, and stars.
- **Commit History & Branch Switching**: Inspect commits across branches with messages, authors, dates, and commit hashes.
- **Safe Commit Removal**:
  - **Strategy 1 (Preserve Files)**: Rewrites branch history on GitHub to omit selected commits while preserving 100% of the files from HEAD.
  - **Strategy 2 (Branch Rollback)**: Points the remote branch back to the clean parent commit.
- **Local Synchronization Guide**: Provides `git reset --soft` commands to keep local working directories intact.

## Setup Instructions

1. **Register a GitHub OAuth App**:
   - Go to GitHub Settings -> Developer Settings -> OAuth Apps -> New OAuth App.
   - Homepage URL: `http://127.0.0.1:5000`
   - Authorization callback URL: `http://127.0.0.1:5000/callback`

2. **Configure Environment Variables**:
   - Copy `.env.example` to `.env`.
   - Add your `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, and `FLASK_SECRET_KEY`.

3. **Install and Run**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   python app.py
   ```
   Open `http://127.0.0.1:5000` in your browser.

## Repository Manager

The repository manager now provides:

- Repository description editing.
- Permanent repository deletion with an exact `owner/repository` confirmation.
- Branch-aware repository file/folder listing.
- New file creation with text content.
- New file upload for binary/text files.
- New folder creation using a `.gitkeep` placeholder (Git cannot store empty folders).
- Specific file deletion using the GitHub Contents API.
- Authenticated repository ZIP download.
- Commit author selection for file-management commits: current GitHub account or a manually entered author name/email.

Open **Manage** from the repository list to use these controls.

## Application Access Tokens

After signing in to GitHub, open **Tokens** in the top navigation to generate scoped Git Manager API tokens. Each token has a name and selected permissions. The full token is displayed only once; the database stores only a hash of the token and an encrypted copy of the GitHub credential needed to perform GitHub operations.

Use generated tokens with API requests as:

```text
Authorization: Bearer gm_...
```

Supported permissions:
- `repos:read`
- `repos:settings`
- `repos:delete`
- `files:read`
- `files:write`
- `files:delete`
- `commits:read`
- `commits:write`

Revoked tokens stop working immediately. Runtime token data is stored under `data/`, which is ignored by Git.


## GitHub-issued token generation

The Tokens page can generate a GitHub-issued scoped user token instead of a local `gm_*` token. The existing `GH_CLIENT_ID` / `GH_CLIENT_SECRET` OAuth App remains responsible for the normal Git Manager login. The GitHub App credentials `GA_CLIENT_ID` / `GA_CLIENT_SECRET` are used separately: the Tokens page first authorizes the GitHub App, receives its `ghu_*` user access token, and then calls GitHub's `POST /applications/{client_id}/token/scoped` endpoint with the selected repositories and GitHub permission mapping. The generated `ghu_*` token is stored encrypted locally so Git Manager can use it, while the raw token is shown only once.

Set `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` for the GitHub application used by the login flow. GitHub Classic PATs cannot be generated through this API; the Classic option opens GitHub's token settings page.
