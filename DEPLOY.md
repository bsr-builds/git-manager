# Git Manager deployment

## Required GitHub Secrets

- `SERVER_HOST`
- `SERVER_USER`
- `SERVER_SSH_KEY`
- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`
- `FLASK_SECRET_KEY`

## Optional Secrets

- `WORKER_SECRET` - required when the Nginx gatekeeper is enabled
- `CLOUDFLARE_API_TOKEN` - required when Worker deployment is enabled

## GitHub Variables

- `APP_PORT` - optional; empty = automatically choose a free host port starting at 8080
- `DOCKER_CONTAINER` - optional; default `git-manager`
- `SERVER_SSH_PORT` - optional; default `22`
- `GATEKEEPER_ENABLED` - `false` by default
- `GATEKEEPER_PORT` - default `10000`
- `CLOUDFLARE_WORKER_ENABLED` - `false` by default
- `CLOUDFLARE_WORKER_NAME` - e.g. `git-manager`
- `CLOUDFLARE_ORIGIN_HOST` - hostname of the existing Cloudflare Named Tunnel origin, e.g. `git-manager-origin.example.com`
- `EXTERNAL_BASE_URL` - public GitHub OAuth base URL, e.g. `https://git-manager.example.workers.dev`

## GitHub App

Set the GitHub OAuth App / GitHub App callback to:

`EXTERNAL_BASE_URL + /callback`

Example:

`https://git-manager.example.workers.dev/callback`

Do not use `127.0.0.1` in production.

## Cloudflare Worker

The Worker name comes from the GitHub Actions variable:

`CLOUDFLARE_WORKER_NAME`

The workflow deploys that exact name with Wrangler.

Quick Tunnel / `trycloudflare.com` is not used.

The Worker forwards requests to `CLOUDFLARE_ORIGIN_HOST`, which should be the hostname already exposed by the permanent Cloudflare Named Tunnel.

The Worker URL is not guessed from the name because a `workers.dev` URL also depends on the Cloudflare account's workers.dev subdomain. Use `EXTERNAL_BASE_URL` for the exact public URL used by GitHub OAuth.
