#!/usr/bin/env bash
set -euo pipefail

APP_PORT="${APP_PORT:-}"
DOCKER_CONTAINER="${DOCKER_CONTAINER:-git-manager}"
WORKER_NAME="${WORKER_NAME:-git-manager}"
GATEKEEPER_PORT="${GATEKEEPER_PORT:-10000}"
GITHUB_CLIENT_ID="${GITHUB_CLIENT_ID:-}"
GITHUB_CLIENT_SECRET="${GITHUB_CLIENT_SECRET:-}"
FLASK_SECRET_KEY="${FLASK_SECRET_KEY:-}"
CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-}"

SERVER_PATH="${HOME}/git-manager"
STATE_DIR="${HOME}/.git-manager"
TUNNEL_LOG="${STATE_DIR}/cloudflared.log"
TUNNEL_PID="${STATE_DIR}/cloudflared.pid"
WORKER_DIR="${SERVER_PATH}/worker"

mkdir -p "$STATE_DIR"
cd "$SERVER_PATH"

if [[ -z "$CLOUDFLARE_API_TOKEN" ]]; then
  echo "ERROR: CLOUDFLARE_API_TOKEN is required."
  exit 1
fi

if [[ -z "$GITHUB_CLIENT_ID" || -z "$GITHUB_CLIENT_SECRET" || -z "$FLASK_SECRET_KEY" ]]; then
  echo "ERROR: GitHub OAuth secrets and FLASK_SECRET_KEY are required."
  exit 1
fi

# Pick a free local-only host port when APP_PORT is blank.
if [[ -z "$APP_PORT" ]]; then
  APP_PORT=8080
  while ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ":${APP_PORT}$"; do
    APP_PORT=$((APP_PORT + 1))
  done
fi

# Stop old app/gatekeeper/tunnel before replacing them.
sudo docker rm -f gatekeeper-git-manager "$DOCKER_CONTAINER" >/dev/null 2>&1 || true
if [[ -f "$TUNNEL_PID" ]]; then
  old_pid="$(cat "$TUNNEL_PID" 2>/dev/null || true)"
  [[ -n "$old_pid" ]] && kill "$old_pid" >/dev/null 2>&1 || true
fi
pkill -f 'cloudflared tunnel --url http://127.0.0.1:' >/dev/null 2>&1 || true
rm -f "$TUNNEL_PID" "$TUNNEL_LOG"

# Build the application.
sudo docker build --pull -t "${DOCKER_CONTAINER}:latest" .

# The application is NOT published on the server's public interface.
sudo docker run -d \
  --name "$DOCKER_CONTAINER" \
  --restart unless-stopped \
  -p "127.0.0.1:${APP_PORT}:5000" \
  -e PORT=5000 \
  -e EXTERNAL_BASE_URL="" \
  -e FLASK_SECRET_KEY="$FLASK_SECRET_KEY" \
  -e GITHUB_CLIENT_ID="$GITHUB_CLIENT_ID" \
  -e GITHUB_CLIENT_SECRET="$GITHUB_CLIENT_SECRET" \
  "${DOCKER_CONTAINER}:latest"

sleep 4
sudo docker ps --format '{{.Names}}' | grep -Fxq "$DOCKER_CONTAINER" || {
  sudo docker logs "$DOCKER_CONTAINER" 2>&1 | tail -n 100 || true
  exit 1
}

# Gatekeeper is also localhost-only. Run Nginx in host networking so it can
# reliably proxy to the localhost-only Docker app on Linux. The public quick
# tunnel cannot reach the app without the secret header injected by the Worker.
WORKER_SECRET="$(openssl rand -hex 32)"
mkdir -p "$HOME/gatekeeper"
chmod 700 "$HOME/gatekeeper"
cat > "$HOME/gatekeeper/default.conf" <<NGINX
server {
    listen ${GATEKEEPER_PORT};
    server_name _;

    location / {
        if (\$http_x_worker_secret != "$WORKER_SECRET") {
            return 403;
        }

        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600;
        proxy_send_timeout 3600;
    }
}
NGINX

sudo docker rm -f gatekeeper-git-manager >/dev/null 2>&1 || true
sudo docker run -d \
  --name gatekeeper-git-manager \
  --restart unless-stopped \
  --network host \
  -v "$HOME/gatekeeper/default.conf:/etc/nginx/conf.d/default.conf:ro" \
  nginx:alpine

sleep 2
sudo docker ps --format '{{.Names}}' | grep -Fxq gatekeeper-git-manager || {
  sudo docker logs gatekeeper-git-manager 2>&1 | tail -n 100 || true
  exit 1
}

# Install cloudflared only if it is missing.
if ! command -v cloudflared >/dev/null 2>&1; then
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) cf_arch="amd64" ;;
    aarch64|arm64) cf_arch="arm64" ;;
    armv7l) cf_arch="arm" ;;
    *) echo "ERROR: Unsupported architecture: $arch"; exit 1 ;;
  esac
  tmp_cf="$(mktemp)"
  curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${cf_arch}" -o "$tmp_cf"
  sudo install -m 0755 "$tmp_cf" /usr/local/bin/cloudflared
  rm -f "$tmp_cf"
fi

# Start an ephemeral Cloudflare Quick Tunnel. Its URL is intentionally not
# exposed to the app; the Worker becomes the only usable public entry point.
setsid cloudflared tunnel --no-autoupdate --url "http://127.0.0.1:${GATEKEEPER_PORT}" >"$TUNNEL_LOG" 2>&1 < /dev/null &
echo $! > "$TUNNEL_PID"

TUNNEL_URL=""
for _ in $(seq 1 30); do
  TUNNEL_URL="$(grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com' "$TUNNEL_LOG" | tail -n 1 || true)"
  [[ -n "$TUNNEL_URL" ]] && break
  sleep 1
done

if [[ -z "$TUNNEL_URL" ]]; then
  echo "ERROR: Cloudflare Tunnel URL was not detected."
  tail -n 100 "$TUNNEL_LOG" || true
  exit 1
fi

echo "Cloudflare Tunnel: $TUNNEL_URL"

# Deploy the Worker using only the Worker name variable.
mkdir -p "$WORKER_DIR/src"
cat > "$WORKER_DIR/wrangler.toml" <<WRANGLER
name = "${WORKER_NAME}"
main = "src/index.js"
compatibility_date = "2026-10-01"
workers_dev = true
WRANGLER

export CLOUDFLARE_API_TOKEN
cd "$WORKER_DIR"

wrangler_output="$(npx --yes wrangler@latest deploy --name "$WORKER_NAME" 2>&1 | tee /tmp/git-manager-wrangler.log)"
WORKER_URL="$(printf '%s\n' "$wrangler_output" | grep -Eo 'https://[^[:space:]]+\.workers\.dev' | tail -n 1 || true)"

if [[ -z "$WORKER_URL" ]]; then
  echo "ERROR: Could not detect the deployed Worker URL."
  printf '%s\n' "$wrangler_output"
  exit 1
fi

# Secrets are stored in the Worker, not in the repository.
printf '%s' "$WORKER_SECRET" | npx --yes wrangler@latest secret put WORKER_SECRET --name "$WORKER_NAME" >/dev/null
printf '%s' "$TUNNEL_URL" | npx --yes wrangler@latest secret put TUNNEL_URL --name "$WORKER_NAME" >/dev/null

# Restart the app with the exact Worker URL so GitHub OAuth always returns to
# the Worker. The server IP/port is never used as the public callback URL.
sudo docker rm -f "$DOCKER_CONTAINER" >/dev/null 2>&1 || true
sudo docker run -d \
  --name "$DOCKER_CONTAINER" \
  --restart unless-stopped \
  -p "127.0.0.1:${APP_PORT}:5000" \
  -e PORT=5000 \
  -e EXTERNAL_BASE_URL="$WORKER_URL" \
  -e FLASK_SECRET_KEY="$FLASK_SECRET_KEY" \
  -e GITHUB_CLIENT_ID="$GITHUB_CLIENT_ID" \
  -e GITHUB_CLIENT_SECRET="$GITHUB_CLIENT_SECRET" \
  "${DOCKER_CONTAINER}:latest"

sleep 3

cat > "$STATE_DIR/deployment.env" <<STATE
WORKER_NAME=$WORKER_NAME
WORKER_URL=$WORKER_URL
TUNNEL_URL=$TUNNEL_URL
APP_PORT=$APP_PORT
STATE
chmod 600 "$STATE_DIR/deployment.env"

echo ""
echo "=========================================="
echo "GIT MANAGER DEPLOYED"
echo "=========================================="
echo "Worker URL : $WORKER_URL"
echo "Tunnel     : internal/ephemeral"
echo "App bind   : 127.0.0.1:$APP_PORT"
echo "Public IP  : BLOCKED"
echo "=========================================="
