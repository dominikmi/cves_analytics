# CVEs Analytics — containerized deployment entry point.
# Compatible with GNU make (Linux) and BSD make (macOS).

SHELL := /bin/sh
.DEFAULT_GOAL := help

# --- Tooling detection ------------------------------------------------------
RUNTIME := $(shell command -v docker 2>/dev/null || command -v podman 2>/dev/null)
COMPOSE := $(shell \
	if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then \
		echo "docker compose"; \
	elif command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then \
		echo "podman compose"; \
	elif command -v docker-compose >/dev/null 2>&1; then \
		echo "docker-compose"; \
	elif command -v podman-compose >/dev/null 2>&1; then \
		echo "podman-compose"; \
	fi)

OS := $(shell uname -s)
VERSION := $(shell python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])" 2>/dev/null || echo dev)
export VERSION

API_IMAGE  := cves-analytics-api:$(VERSION)
WEB_IMAGE  := cves-analytics-web:$(VERSION)

# ----------------------------------------------------------------------------
help: ## List available targets
	@echo "CVEs Analytics — deployment (v$(VERSION), $(OS))"
	@echo ""
	@echo "  install      Check prerequisites; install missing (asks first)"
	@echo "  check        Verify prerequisites only"
	@echo "  config       Render config.yaml from .env"
	@echo "  build        Build api + web images ($(VERSION))"
	@echo "  up           check+config+build, then start the stack"
	@echo "  down         Stop the stack"
	@echo "  logs         Follow container logs"
	@echo "  ps           Show container status"
	@echo "  scan IMAGE=x       Scan a registry image via the api service"
	@echo "  mirror IMAGE=x     Push host image into the local registry sidecar"
	@echo "  version      Print the project semver"
	@echo "  release BUMP=patch|minor|major   Bump version, tag, rebuild"
	@echo "  test         Run the host-side test suite (uv run pytest)"
	@echo "  clean        Stop stack and remove images+volumes (asks first)"

# ----------------------------------------------------------------------------
check: ## Verify prerequisites
	@missing=0; \
	for t in python3 curl tar; do \
		command -v $$t >/dev/null 2>&1 || { echo "MISSING: $$t"; missing=1; }; \
	done; \
	if [ -z "$(RUNTIME)" ]; then echo "MISSING: docker or podman"; missing=1; fi; \
	if [ -z "$(COMPOSE)" ]; then echo "MISSING: compose plugin or *-compose"; missing=1; fi; \
	if [ $$missing -eq 0 ]; then \
		echo "OK: $(RUNTIME), compose=[$(COMPOSE)], python3, curl, tar"; \
	else \
		echo "Run 'make install' to install missing pieces."; exit 1; \
	fi

install: ## Check prerequisites and install missing pieces (with confirmation)
	@$(MAKE) -s check || { \
		echo "Detected OS: $(OS)"; \
		if [ "$(OS)" = "Darwin" ]; then \
			if [ -z "$(RUNTIME)" ]; then \
				printf "Install Docker Desktop via 'brew install --cask docker'? [y/N] "; \
				read a < /dev/tty; \
				[ "$$a" = "y" ] && brew install --cask docker; \
				printf "Or prefer podman? Install via 'brew install podman'? [y/N] "; \
				read a < /dev/tty; \
				[ "$$a" = "y" ] && brew install podman; \
			fi; \
			command -v python3 >/dev/null 2>&1 || { \
				printf "Install python3 via brew? [y/N] "; read a < /dev/tty; \
				[ "$$a" = "y" ] && brew install python@3.12; }; \
			command -v curl >/dev/null 2>&1 || { \
				printf "Install curl via brew? [y/N] "; read a < /dev/tty; \
				[ "$$a" = "y" ] && brew install curl; }; \
		elif [ "$(OS)" = "Linux" ]; then \
			if [ -z "$(RUNTIME)" ]; then \
				printf "Install docker.io via apt? [y/N] "; read a < /dev/tty; \
				[ "$$a" = "y" ] && sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2; \
				printf "Or prefer podman? Install podman+podman-compose via apt? [y/N] "; \
				read a < /dev/tty; \
				[ "$$a" = "y" ] && sudo apt-get update && sudo apt-get install -y podman podman-compose; \
			fi; \
			command -v python3 >/dev/null 2>&1 || { \
				printf "Install python3 via apt? [y/N] "; read a < /dev/tty; \
				[ "$$a" = "y" ] && sudo apt-get install -y python3; }; \
			command -v curl >/dev/null 2>&1 || { \
				printf "Install curl via apt? [y/N] "; read a < /dev/tty; \
				[ "$$a" = "y" ] && sudo apt-get install -y curl; }; \
		else \
			echo "Unsupported OS: $(OS). Install prerequisites manually."; exit 1; \
		fi; \
		$(MAKE) -s check; \
	}

config: ## Render config.yaml from .env
	python3 scripts/render_config.py

# ----------------------------------------------------------------------------
build: check ## Build api and web images
	$(RUNTIME) build -f docker/api.Dockerfile -t $(API_IMAGE) -t cves-analytics-api:latest .
	$(RUNTIME) build -f docker/web.Dockerfile -t $(WEB_IMAGE) -t cves-analytics-web:latest .

up: check config build ## Start the stack
	$(COMPOSE) up -d
	@echo "Web UI: http://localhost:8080"

down: ## Stop the stack
	$(COMPOSE) down

logs: ## Follow container logs
	$(COMPOSE) logs -f

ps: ## Show container status
	$(COMPOSE) ps

# ----------------------------------------------------------------------------
scan: ## Scan a registry image: make scan IMAGE=nginx:latest
	@test -n "$(IMAGE)" || { echo "usage: make scan IMAGE=<ref>"; exit 1; }
	$(COMPOSE) exec api /opt/venv/bin/cves-analytics --images "$(IMAGE)"

mirror: ## Push a host image into the local registry: make mirror IMAGE=myapp:dev
	@test -n "$(IMAGE)" || { echo "usage: make mirror IMAGE=<ref>"; exit 1; }
	$(RUNTIME) tag "$(IMAGE)" "localhost:5000/$(IMAGE)"
	$(RUNTIME) push "localhost:5000/$(IMAGE)"
	@echo "Now scannable as: registry.local:5000/$(IMAGE)"

# ----------------------------------------------------------------------------
version: ## Print the project semver
	@echo $(VERSION)

release: check ## Bump semver, tag, rebuild: make release BUMP=patch
	@test "$(BUMP)" = "patch" -o "$(BUMP)" = "minor" -o "$(BUMP)" = "major" || \
		{ echo "usage: make release BUMP=patch|minor|major"; exit 1; }
	uv version --bump $(BUMP)
	@NEW=$$(python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])"); \
	printf "Create git tag v$$NEW? [y/N] "; read a < /dev/tty; \
	if [ "$$a" = "y" ]; then git add pyproject.toml && \
		git commit -m "release v$$NEW" && git tag "v$$NEW" && \
		echo "tagged v$$NEW"; fi
	@$(MAKE) build VERSION=$$(python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")

# ----------------------------------------------------------------------------
test: ## Run host-side test suite
	uv run pytest

clean: ## Stop stack, remove images and volumes (asks first)
	@printf "Stop stack and DELETE data volumes (findings, db, registry)? [y/N] "; \
	read a < /dev/tty; \
	if [ "$$a" = "y" ]; then \
		$(COMPOSE) down -v; \
		$(RUNTIME) rmi -f $(API_IMAGE) $(WEB_IMAGE) 2>/dev/null || true; \
		echo "cleaned"; \
	else \
		echo "aborted"; \
	fi

.PHONY: help check install config build up down logs ps scan mirror version release test clean
