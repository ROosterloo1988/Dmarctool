# Build context: repository root (see docker-compose.yml)

# --- 1. Frontend -------------------------------------------------------------------------
FROM node:22-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build   # writes to /src/backend/dmarc/static

# --- 2. Python application ---------------------------------------------------------------
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

RUN useradd --create-home --uid 10001 app
WORKDIR /app

COPY backend/pyproject.toml ./
COPY backend/dmarc ./dmarc
COPY --from=frontend /src/backend/dmarc/static ./dmarc/static
RUN pip install '.[dev]'

COPY backend/alembic.ini ./
COPY backend/tests ./tests

RUN mkdir -p /data/geoip && chown app /data/geoip
USER app
ENTRYPOINT ["dmarc"]
CMD ["--help"]
