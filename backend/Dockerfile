FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

RUN useradd --create-home --uid 10001 app
WORKDIR /app

COPY pyproject.toml ./
COPY dmarc ./dmarc
RUN pip install '.[dev]'

COPY alembic.ini ./
COPY tests ./tests

RUN mkdir -p /data/geoip && chown app /data/geoip
USER app
ENTRYPOINT ["dmarc"]
CMD ["--help"]
