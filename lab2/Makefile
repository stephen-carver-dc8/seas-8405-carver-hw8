
.PHONY: up down reset logs

DOCKER_COMPOSE := $(shell command -v docker-compose > /dev/null && echo docker-compose || echo docker compose)

up:
	@echo "[*] Starting Lab 1 (Keycloak + Flask App)..."
	@bash setup.sh

down:
	@echo "[*] Stopping and removing all lab containers and volumes..."
	@$(DOCKER_COMPOSE) down -v

reset: down
	@echo "[*] Resetting lab environment..."
	@rm -rf keycloak_data
	@docker system prune -f
	@bash setup.sh

logs:
	@$(DOCKER_COMPOSE) logs -f
