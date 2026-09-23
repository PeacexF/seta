.PHONY: build test lint vuln fuzz integration integration-down catalog docs

build:
	go build -o seta ./cmd/seta

test:
	go test -race ./...

# Tool versions are pinned here and used by CI, so both run the same checks.
STATICCHECK = honnef.co/go/tools/cmd/staticcheck@v0.8.1
GOVULNCHECK = golang.org/x/vuln/cmd/govulncheck@v1.8.0

lint:
	gofmt -l . | (! grep .)
	go vet ./...
	GOOS=windows go vet ./...
	go vet -tags integration ./integration/
	go run $(STATICCHECK) ./...

vuln:
	go run $(GOVULNCHECK) ./...

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
	$(COMPOSE) up --build --wait --detach dns mx-tls mx-plain mx-expired mta-sts web-legacy
	$(COMPOSE) run --rm tests; status=$$?; $(COMPOSE) down -v; exit $$status

integration-down:
	$(COMPOSE) down -v

# Regenerates the docs check catalog from each check's Meta.
catalog:
	go run ./internal/tools/catalog docs/src/content/docs/checks

docs: catalog
	cd docs && npm ci && npm run build
