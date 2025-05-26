.PHONY: up down reset logs

DOCKER_COMPOSE := $(shell command -v docker-compose > /dev/null && echo docker-compose || echo docker compose)

up:
	@$(DOCKER_COMPOSE) up -d --build 

down:
	@$(DOCKER_COMPOSE) down -v

reset: down
	@docker system prune -f
	@$(DOCKER_COMPOSE) up -d --build 
	@python3 test.py

logs:
	@$(DOCKER_COMPOSE) logs -f