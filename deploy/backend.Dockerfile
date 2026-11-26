# Backend image: API, workers and scheduler (same image, different commands in docker-compose.yml)
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# libmagic: file-type detection · pango/harfbuzz + fonts: PDF export (WeasyPrint)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libmagic1 libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libharfbuzz-subset0 fonts-dejavu-core curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /usr/local/bin/uv

WORKDIR /app
COPY backend/pyproject.toml backend/uv.lock ./
COPY backend/wheels ./wheels
RUN uv sync --frozen --no-dev --no-install-project

# Headless Chromium + its system libraries for screenshots; owned by the runtime user in the same layer
RUN useradd --create-home --uid 10001 app \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/* \
    && chown -R app /ms-playwright

# Code last, so code changes rebuild in seconds
COPY --chown=app backend/ ./
USER app

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD curl -fs http://127.0.0.1:8000/health || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
