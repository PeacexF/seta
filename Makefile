.PHONY: build test lint fuzz integration integration-down catalog docs

build:
	go build -o seta ./cmd/seta

test:
	go test -race ./...

lint:
	gofmt -l . | (! grep .)
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@2026.1 ./...

# Fuzz each parser for FUZZTIME (default 30s).
FUZZTIME ?= 30s
fuzz:
	go test -run '^$$' -fuzz FuzzParse -fuzztime $(FUZZTIME) ./checks/email/internal/spf
	go test -run '^$$' -fuzz FuzzParse -fuzztime $(FUZZTIME) ./checks/email/internal/dmarc
	go test -run '^$$' -fuzz FuzzParse -fuzztime $(FUZZTIME) ./checks/email/internal/tags

# Runs the checks against CoreDNS, Postfix and nginx in Docker.
COMPOSE = SETA_GOMODCACHE=$$(go env GOMODCACHE) docker compose -f integration/docker-compose.yml
integration:
	go mod download
	$(COMPOSE) up --build --wait --detach dns mx-tls mx-plain mx-expired mta-sts
	$(COMPOSE) run --rm tests; status=$$?; $(COMPOSE) down -v; exit $$status

integration-down:
	$(COMPOSE) down -v

# Regenerates the docs check catalog from each check's Meta.
catalog:
	go run ./internal/tools/catalog docs/src/content/docs/checks

docs: catalog
	cd docs && npm ci && npm run build
