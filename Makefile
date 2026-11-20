PY ?= .venv/bin/python

.PHONY: install lint test eval up down smoke build-arm64

install:
	python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt

lint:
	$(PY) -m ruff check .

test:
	$(PY) -m pytest -q

eval:  ## golden-set eval in-process (mock unless LLM_PROVIDER=bedrock)
	LLM_PROVIDER=$${LLM_PROVIDER:-mock} $(PY) scripts/evaluate.py --target inprocess

up:
	docker compose up --build -d

down:
	docker compose down

smoke:  ## run against the docker-compose stack
	curl -s -X POST localhost:8080/invocations -H 'Content-Type: application/json' \
	  -d @scripts/sample_transactions.json | $(PY) -m json.tool
	$(PY) scripts/evaluate.py --target http://localhost:8080

build-arm64:
	docker buildx build --platform linux/arm64 -t risk-monitor:arm64 --load .
