# SquidSeC2 — minimal production image
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SQUIDSEC2_HOST=0.0.0.0 \
    SQUIDSEC2_PORT=8443 \
    SQUIDSEC2_DATA_DIR=/data

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin squidsec2

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir -e . --no-deps

RUN mkdir -p /data && chown -R squidsec2:squidsec2 /data /app
USER squidsec2

VOLUME ["/data"]
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8443/api/v1/health', timeout=3)"

CMD ["python", "-m", "uvicorn", "squidsec2.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8443", "--workers", "1"]
