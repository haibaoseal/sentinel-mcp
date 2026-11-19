# syntax=docker/dockerfile:1
FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    AUTO_CREATE_SCHEMA=false \
    DATABASE_URL=sqlite:////data/sentinel_mcp.db

WORKDIR /app

# Install the service dependencies before copying the whole tree so a code-only
# change does not invalidate the dependency layer.
COPY pyproject.toml constraints.txt README.md ./
COPY apps/api ./apps/api
RUN python -m pip install --upgrade pip \
    && python -m pip install ".[api,postgres]" -c constraints.txt \
    && useradd --system --uid 10001 --create-home sentinel

# Runtime assets: policy docs, the SQLite fixture, eval scenarios and the
# migration chain. `sandbox` is writable by the runtime user because the tools
# intentionally operate on it.
COPY knowledge ./knowledge
COPY sandbox ./sandbox
COPY evals ./evals
COPY mcp_servers ./mcp_servers
COPY scripts ./scripts
COPY migrations ./migrations
COPY alembic.ini ./

RUN chmod +x scripts/docker-entrypoint.sh \
    && mkdir -p /data /app/sandbox \
    && chown -R sentinel:sentinel /data /app/sandbox /app/knowledge

USER sentinel
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"

ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]
