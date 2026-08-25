# Image coordinates on Docker Hub.
REGISTRY ?= docker.io
OWNER    ?= ruslanrwx
API_IMAGE = $(REGISTRY)/$(OWNER)/secrets-api
UI_IMAGE  = $(REGISTRY)/$(OWNER)/secrets-ui
VERSION  ?= 0.2.0
PLATFORMS ?= linux/amd64,linux/arm64

TEST_DATABASE_URL ?= postgres://secrets:testpass@localhost:55432/secrets_test?sslmode=disable

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: test
test: ## Run every test, including the database integration suite
	cd backend && TEST_DATABASE_URL="$(TEST_DATABASE_URL)" go test ./...
	cd frontend && npm run lint

.PHONY: test-db
test-db: ## Start a throwaway PostgreSQL for the integration suite
	docker run -d --rm --name secrets-test-db \
	  -e POSTGRES_PASSWORD=testpass -e POSTGRES_USER=secrets -e POSTGRES_DB=secrets_test \
	  -p 55432:5432 postgres:16-alpine

.PHONY: build
build: ## Build both images for this machine's architecture
	docker build -t $(API_IMAGE):$(VERSION) --build-arg VERSION=$(VERSION) ./backend
	docker build -t $(UI_IMAGE):$(VERSION) ./frontend

.PHONY: push
push: ## Build for amd64 and arm64 and push to Docker Hub (needs docker login)
	docker buildx build --platform $(PLATFORMS) \
	  --build-arg VERSION=$(VERSION) \
	  -t $(API_IMAGE):$(VERSION) -t $(API_IMAGE):latest --push ./backend
	docker buildx build --platform $(PLATFORMS) \
	  -t $(UI_IMAGE):$(VERSION) -t $(UI_IMAGE):latest --push ./frontend

.PHONY: chart
chart: ## Lint and render the Helm chart
	helm lint ./helm/secrets
	helm template secrets ./helm/secrets > /dev/null && echo "chart renders"

.PHONY: up
up: ## Start the local stack
	docker compose up -d --build

.PHONY: down
down: ## Stop the local stack
	docker compose down
