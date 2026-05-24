# =============================================================================
# Cyber-homelab SOAR Stack — Makefile shortcuts
# Requires: GNU Make (included in Git for Windows / chocolatey install make)
# Run from: 04-soar/ directory
# =============================================================================

COMPOSE = docker compose

.PHONY: start stop status logs logs-thehive logs-cortex logs-misp clean rebuild help

# Default target
help:
	@echo ""
	@echo "Cyber-homelab SOAR Stack — Commands"
	@echo "────────────────────────────────────────────"
	@echo "  make start         Start all services (detached)"
	@echo "  make stop          Stop all services (keep volumes)"
	@echo "  make status        Show services health & ports"
	@echo "  make logs          Follow all logs"
	@echo "  make logs-thehive  Follow TheHive logs only"
	@echo "  make logs-cortex   Follow Cortex logs only"
	@echo "  make logs-misp     Follow MISP logs only"
	@echo "  make rebuild       Pull latest images + force recreate"
	@echo "  make clean         Stop AND delete all volumes (data loss!)"
	@echo ""

start:
	$(COMPOSE) up -d

stop:
	$(COMPOSE) down

status:
	$(COMPOSE) ps

logs:
	$(COMPOSE) logs -f

logs-thehive:
	$(COMPOSE) logs -f thehive

logs-cortex:
	$(COMPOSE) logs -f cortex

logs-misp:
	$(COMPOSE) logs -f misp

clean:
	$(COMPOSE) down -v

rebuild:
	$(COMPOSE) pull
	$(COMPOSE) up -d --force-recreate
