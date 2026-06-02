# BlastContain Verify — integration test runner
#
# Usage:
#   make build         Build the verify image and compose services
#   make test          Run full test suite
#   make test-fail     Run only FAIL scenario tests
#   make test-pass     Run only PASS scenario tests
#   make up            Start compose services only
#   make down          Stop and remove compose services
#   make logs          Tail service logs
#   make clean         Remove containers, volumes, and the verify image

VERIFY_IMAGE   ?= blastcontain-verify:0.1.0
VERIFY_DIR     := ../../tools/blastcontain-verify
COMPOSE        ?= podman compose
CONTAINER      ?= podman
COMPOSE_FILE   := compose.yml
PYTEST         := python -m pytest -v --timeout=120

.PHONY: build up down logs test test-fail test-pass clean

build:
	$(CONTAINER) build -t $(VERIFY_IMAGE) $(VERIFY_DIR)
	$(COMPOSE) -f $(COMPOSE_FILE) build

up: build
	$(COMPOSE) -f $(COMPOSE_FILE) up -d
	@echo "Waiting for services..."
	@sleep 8
	@echo "MCP server:"; $(CONTAINER) inspect blastcontain-mcp-test --format '{{.State.Health.Status}}'
	@echo "API server:"; $(CONTAINER) inspect blastcontain-api-test --format '{{.State.Health.Status}}'

down:
	$(COMPOSE) -f $(COMPOSE_FILE) down --volumes

logs:
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f

test: up
	$(PYTEST) test_fail.py test_pass.py

test-fail: up
	$(PYTEST) test_fail.py

test-pass: up
	$(PYTEST) test_pass.py

clean: down
	$(CONTAINER) rmi $(VERIFY_IMAGE) || true
	$(COMPOSE) -f $(COMPOSE_FILE) down --volumes --rmi all || true
