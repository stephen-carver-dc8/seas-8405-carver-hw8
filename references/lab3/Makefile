
.PHONY: up down reset logs

DOCKER_COMPOSE := $(shell command -v docker-compose > /dev/null && echo docker-compose || echo docker compose)

up:
	@echo "[*] Starting Lab 2: SAML + LDAP Hybrid Auth..."
	@bash setup.sh

down:
	@$(DOCKER_COMPOSE) down -v

reset: down
	@docker system prune -f
	@bash setup.sh

logs:
	@$(DOCKER_COMPOSE) logs -f
