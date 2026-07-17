# SquidC5 — minimal production image
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SQUIDC5_HOST=0.0.0.0 \
    SQUIDC5_PORT=8443 \
    SQUIDC5_DATA_DIR=/data

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin squidc5

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY web ./web
RUN pip install --no-cache-dir -e . --no-deps

RUN mkdir -p /data && chown -R squidc5:squidc5 /data /app
USER squidc5

VOLUME ["/data"]
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import ssl,urllib.request; ctx=ssl._create_unverified_context(); urllib.request.urlopen('https://127.0.0.1:8443/api/v1/health', timeout=3, context=ctx)"

# Package entrypoint enables unique instance TLS under SQUIDC5_DATA_DIR/tls/
CMD ["python", "-m", "squidc5"]
