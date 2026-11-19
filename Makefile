PYTHON ?= python
PIP ?= $(PYTHON) -m pip
PYTEST ?= $(PYTHON) -m pytest
RUFF ?= $(PYTHON) -m ruff

.PHONY: help install test lint format eval demo serve migrate revision docker-up docker-down docker-logs smoke pilot load

help:
	@echo "install    install library + service + dev dependencies"
	@echo "test       run the test suite"
	@echo "lint       ruff check + format check"
	@echo "format     apply ruff formatting"
	@echo "eval       run the deterministic evaluation gate"
	@echo "demo       run the governed-agent demonstration"
	@echo "serve      run the API locally (SQLite, development keys)"
	@echo "migrate    apply database migrations"
	@echo "revision   create an Alembic revision (m=\"message\")"
	@echo "docker-up  build and start Postgres + API"
	@echo "smoke      HTTP smoke test against a temporary database"
	@echo "pilot      1,000-task simulated pilot report"
	@echo "load       HTTP load test with p50/p95/p99 output"

install:
	$(PIP) install -e ".[dev,api]"

test:
	$(PYTEST) apps/api/app/tests -q

lint:
	$(RUFF) check apps/api/app mcp_servers scripts migrations
	$(RUFF) format --check apps/api/app mcp_servers scripts migrations

format:
	$(RUFF) format apps/api/app mcp_servers scripts migrations

eval:
	$(PYTHON) -m app.evals.cli

demo:
	$(PYTHON) scripts/demo_agent.py

serve:
	$(PYTHON) -m uvicorn app.api.asgi:app --host 127.0.0.1 --port 8000 --reload

migrate:
	$(PYTHON) -m alembic upgrade head

revision:
	$(PYTHON) -m alembic revision --autogenerate -m "$(m)"

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down -v

docker-logs:
	docker compose logs -f api

smoke:
	$(PYTHON) scripts/api_smoke.py

pilot:
	$(PYTHON) scripts/pilot_simulation.py --tasks 1000

load:
	$(PYTHON) scripts/load_test.py --requests 200 --concurrency 10
