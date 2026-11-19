#!/bin/sh
# Container entry point: migrate first, then serve.
#
# `alembic upgrade head` is idempotent, so a restarted container is safe. The
# process that runs migrations is the same image and the same DATABASE_URL as the
# process that serves traffic; there is no second, differently-configured path.
set -eu

if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
    echo "applying database migrations"
    alembic upgrade head
fi

exec uvicorn app.api.asgi:app \
    --host 0.0.0.0 \
    --port "${PORT:-8000}" \
    --proxy-headers \
    --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-127.0.0.1}"
