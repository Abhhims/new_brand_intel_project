# Deployment Guide (DEL-05)

The whole platform runs from one Docker Compose file (decision D-16). Staging and production use the same file
with different `.env` values.

## 1. What runs

| Service | Image | Purpose | Port (host) |
|---|---|---|---|
| `web` | `brandintel-web` | Next.js analyst dashboard | 3000 |
| `api` | `brandintel-backend` | FastAPI REST API; runs DB migrations and creates the first admin on start | 8010 → 8000 |
| `worker` | `brandintel-backend` | Celery worker, queue `default` (DNS, WHOIS, app stores, search, documents) | — |
| `browser-worker` | `brandintel-backend` | Celery worker, queue `browser` (headless Chromium: screenshots, logo crawling) | — |
| `beat` | `brandintel-backend` | Scheduler: full scan daily 02:00 UTC, domain re-check every 6 h | — |
| `postgres` | `postgres:17-alpine` | Database | 5432 |
| `redis` | `redis:7-alpine` | Task queue, per-host rate limits | 6379 |
| `minio` | `rustfs/rustfs` | S3-compatible evidence storage (D-22) | 9000 (S3), 9001 (console) |
| `fixtures` | `nginx:alpine` | Test website for automated tests only (profile `test`, not started with the platform) | 8088 |

## 2. Server requirements

- Linux VM (Ubuntu 22.04/24.04 or similar) with Docker Engine 24+ and the Compose plugin.
- **4 vCPU, 8 GB RAM, 60 GB disk** minimum for up to ~20 brands (browser work is the heaviest part).
- Outbound internet (HTTP/HTTPS, DNS port 53). Inbound only 443 via a reverse proxy.
- A DNS name for the dashboard (e.g. `brandintel.beyondcloud.internal`) and one for the API (or one host with
  path routing), with TLS certificates.

## 3. Information needed before production

| # | Item | Where it goes | Who provides |
|---|---|---|---|
| 1 | **Database**: use the bundled Postgres container, *or* a managed PostgreSQL 15+ (host, port, database name, user, password, SSL requirement) | `POSTGRES_*`, or `DATABASE_URL=postgresql+psycopg://user:pass@host:5432/db?sslmode=require` | Beyond Cloud IT |
| 2 | **Object storage**: bundled RustFS, *or* an S3 bucket (endpoint, bucket, access key, secret, region) | `S3_ENDPOINT_URL`, `S3_BUCKET`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `S3_REGION`, `S3_PUBLIC_ENDPOINT_URL` | Beyond Cloud IT |
| 3 | **Hostnames + TLS** for dashboard and API | reverse proxy; `PUBLIC_API_URL`, `CORS_ORIGINS` | Beyond Cloud IT |
| 4 | **First admin** email + strong password | `BOOTSTRAP_ADMIN_EMAIL`, `BOOTSTRAP_ADMIN_PASSWORD` | Project owner |
| 5 | **JWT secret**: 48+ random characters (`python -c "import secrets;print(secrets.token_urlsafe(48))"`) | `JWT_SECRET` | Generated at install |
| 6 | **Web search API key** — Brave Search API (preferred) or SerpAPI. Needed for live APK, social (X/FB/IG/LinkedIn) and document discovery | `BRAVE_SEARCH_API_KEY` or `SERPAPI_API_KEY` | Project owner |
| 7 | **Telegram API** ID + hash (my.telegram.org) and a phone number for a monitoring account; then run `python -m scripts.telegram_login` once | `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, `TELEGRAM_SESSION` | Project owner |
| 8 | Written confirmation that Beyond Cloud is **authorised to monitor** each client brand | — | Project owner / legal |

Without 6 and 7 the platform still runs (decision D-23):
- **No search key:** a free, paced fallback (DuckDuckGo's public results page) is used. It pauses for 15 minutes as
  soon as it is rate-limited, so Fake APK, Documents and X/Facebook/Instagram/LinkedIn discovery is *best-effort*
  — typically a few searches per scan. A Brave Search API key (free tier) makes these modules reliable.
- **No Telegram credentials:** likely impersonator usernames (brand name + support/official/help/care/…) are checked
  on Telegram's public `t.me` pages. The official API adds keyword search.
Each scan lists every part it ran — for example "Web search - DuckDuckGo (free, paced)" or "Telegram API: Not
configured" — on the **Scans** page, and the **Integrations** page shows every tool, whether it is configured and
how to configure it (D-31).

## 4. Install

```bash
git clone <repository> brandintel && cd brandintel
cp deploy/.env.example deploy/.env
# Edit deploy/.env: set ENV=production and every value marked CHANGE; empty FETCH_ALLOW_PRIVATE_HOSTS=[]
docker compose -f deploy/docker-compose.yml --profile app up -d --build
docker compose -f deploy/docker-compose.yml --profile app ps        # all services "healthy"/"running"
curl -fs http://localhost:8010/health                              # {"status":"ok","database":"ok"}
```

With `ENV=production` the backend **refuses to start** if the JWT secret, admin password or storage secret are
still the defaults, if the JWT secret is shorter than 32 characters, or if the private-host allowlist is not empty.

The product scans live sources only and has no demo mode (D-27, D-32): there is no `ALLOW_DEMO_MODE`,
`FIXTURES_DIR` or `FIXTURES_BASE_URL` setting any more. The `fixtures` test website belongs to the automated tests
(Compose profile `test`) and is not started with the platform.

### Reverse proxy (example: Caddy)

```
brandintel.example.com {
    reverse_proxy localhost:3000
}
api.brandintel.example.com {
    reverse_proxy localhost:8010
}
```

Set `PUBLIC_API_URL=https://api.brandintel.example.com` (rebuild `web`, the URL is baked in at build time) and
`CORS_ORIGINS=["https://brandintel.example.com"]`. If evidence links must open from analysts' browsers, expose the
storage endpoint (or use AWS S3) and set `S3_PUBLIC_ENDPOINT_URL` accordingly.

## 5. Upgrades

```bash
git pull
docker compose -f deploy/docker-compose.yml --profile app up -d --build   # the api runs `alembic upgrade head` on start
```

## 6. Backup and restore

```bash
# Database (daily, keep 30 days)
docker compose -f deploy/docker-compose.yml exec -T postgres pg_dump -U brandintel -Fc brandintel > backup-$(date +%F).dump
# Restore
docker compose -f deploy/docker-compose.yml exec -T postgres pg_restore -U brandintel -d brandintel --clean < backup-YYYY-MM-DD.dump
# Evidence: back up the `miniodata` volume, or enable versioning/replication on the S3 bucket.
```

## 7. Security notes

- Workers deliberately visit malicious sites. The safe fetcher blocks private, loopback, link-local and cloud
  metadata addresses on every request and redirect; the browser worker applies the same rule to every request
  the page makes; downloaded files are stored, hashed and never executed (D-18).
- Run the stack on a host **without access to internal networks** if possible (separate VLAN / security group
  with internet egress only) — defence in depth on top of the fetcher rules.
- Evidence files are stored with `Content-Disposition: attachment` so a malicious HTML/SVG never renders inline.
- Change the bootstrap admin password after first login and create named accounts for every analyst.

## 8. Local development without Docker for the app

```bash
docker compose -f deploy/docker-compose.yml up -d postgres redis minio fixtures
cd backend && python -m uv sync && python -m uv run alembic upgrade head && python -m uv run python -m scripts.bootstrap
python -m uv run uvicorn app.main:app --port 8010 --reload
python -m uv run celery -A app.workers.celery_app worker -Q default,browser -P solo     # Windows: -P solo
cd ../frontend && npm install && npm run dev
```

On Windows, PDF export and libmagic need the Docker image; everything else runs natively.
