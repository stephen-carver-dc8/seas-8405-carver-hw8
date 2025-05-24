# Use the appropriate compose command based on OS
DOCKER_COMPOSE := $(shell if [ "$(shell uname)" = "Darwin" ]; then echo "docker compose"; else echo "docker-compose"; fi)

.PHONY: up down reset logs

up:
	@echo "[*] Starting Lab 1: Mini-Enterprise IAM Stack..."
	@$(DOCKER_COMPOSE) up -d
	@sleep 5
	@echo "[*] Populating LDAP with seed data..."
	@cat seed.ldif | docker exec -i "$$($(DOCKER_COMPOSE) ps -q ldap)" ldapadd -x -D "cn=admin,dc=example,dc=com" -w adminpw

down:
	@$(DOCKER_COMPOSE) down -v

reset: down
	@docker system prune -f
	@echo "[*] Starting Lab 1: Mini-Enterprise IAM Stack..."
	@$(DOCKER_COMPOSE) up -d --build
	@sleep 5
	@echo "[*] Populating LDAP with seed data..."
	@cat seed.ldif | docker exec -i "$$($(DOCKER_COMPOSE) ps -q ldap)" ldapadd -x -D "cn=admin,dc=example,dc=com" -w adminpw

logs:
	@$(DOCKER_COMPOSE) logs -f
