.PHONY: up down reset logs

DOCKER_COMPOSE := $(shell command -v docker-compose > /dev/null && echo docker-compose || echo docker compose)

up:
	@bash setup.sh

down:
	@$(DOCKER_COMPOSE) down -v

reset: down
	@docker system prune -f
	@docker compose down -v
	@docker compose up -d --build 

logs:
	@$(DOCKER_COMPOSE) logs -f