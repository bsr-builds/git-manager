# Git Manager deployment

## GitHub Actions Secrets

Use these exact names:

- `SERVER_HOST`
- `SERVER_USER`
- `SERVER_SSH_KEY`
- `GH_CLIENT_ID`
- `GH_CLIENT_SECRET`
- `FLASK_SECRET_KEY`
- `CLOUDFLARE_API_TOKEN`

`GH_CLIENT_ID` and `GH_CLIENT_SECRET` are deliberately not named `GITHUB_*` because GitHub Actions reserves the `GITHUB_` prefix for its own variables.

## GitHub Actions Variables

Recommended values:

```text
WORKER_NAME=git-manager
APP_PORT=
DOCKER_CONTAINER=git-manager
SERVER_SSH_PORT=22
GATEKEEPER_PORT=10000
```

No `CLOUDFLARE_ORIGIN_HOST` or `EXTERNAL_BASE_URL` variable is required.

## How production routing works

```text
Worker URL
   ↓
Cloudflare Worker
   ↓  (adds X-Worker-Secret)
Cloudflare Quick Tunnel
   ↓
localhost-only Nginx gatekeeper
   ↓
localhost-only Docker port
   ↓
Flask :5000
```

The deployment script automatically:

1. Chooses a local host port if `APP_PORT` is blank.
2. Binds Docker to `127.0.0.1`, not the server's public interface.
3. Runs a localhost-only Nginx gatekeeper.
4. Starts a Cloudflare Quick Tunnel to the gatekeeper.
5. Detects the generated `trycloudflare.com` URL automatically.
6. Deploys the Worker using `WORKER_NAME`.
7. Stores the generated tunnel URL and gatekeeper secret as Worker secrets.
8. Detects the real `workers.dev` URL automatically.
9. Restarts Git Manager with that Worker URL as `EXTERNAL_BASE_URL`.

Therefore the server's `IP:PORT` is not the public application URL. Direct requests to the tunnel without the Worker secret receive `403`.

## GitHub App callback

After the first deployment, the workflow prints the exact Worker URL. Configure the GitHub App:

```text
Homepage URL:
https://<worker-url>

Callback URL:
https://<worker-url>/callback
```

Do not use the server IP, Docker port, or `trycloudflare.com` URL as the GitHub callback.
