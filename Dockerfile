# syntax=docker/dockerfile:1
# One image, two entrypoints:
#   web service (default CMD)   → dashboard + JSON API + Atom feed
#   collector job               → python -m radar.collector

# ── 1. Build the static dashboard ─────────────────────────────────────────────
FROM node:26-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# ── 2. Resolve Python dependencies from the lockfile ──────────────────────────
FROM python:3.15-slim AS deps
COPY --from=ghcr.io/astral-sh/uv:0.13.9 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

# ── 3. Runtime: no build tools, no uv, non-root ───────────────────────────────
FROM python:3.15-slim
# pip/setuptools ship in the base image with vendored libraries (urllib3,
# msgpack…) that lag on security fixes. The app never installs anything at
# runtime, so remove them: less attack surface, fewer CVEs.
RUN set -eux; \
    apt-get update; apt-get upgrade -y; rm -rf /var/lib/apt/lists/*; \
    python -m pip uninstall -y pip setuptools wheel || true; \
    rm -rf /usr/local/lib/python3.13/site-packages/pip* /usr/local/lib/python3.13/site-packages/setuptools* /usr/local/bin/pip*; \
    useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin radar
WORKDIR /app
COPY --from=deps --chown=root:root /app/.venv /app/.venv
COPY --from=web --chown=root:root /web/dist /app/web
ENV PATH=/app/.venv/bin:$PATH WEB_DIR=/app/web PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 10001
EXPOSE 8080
CMD ["uvicorn", "radar.api:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header", "--no-access-log"]
