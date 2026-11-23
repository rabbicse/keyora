# Keyora developer tasks. Run `make help` for a list.
SHELL := /bin/sh
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
MODULES := . cmd/keyora adapters/gin
EXAMPLES := examples/golang/standard-library examples/golang/gin

.PHONY: help build run test test-race cover fuzz vet fmt fmt-check check-deps lint-openapi vuln check docker clean

help: ## Show this help
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-14s %s\n", $$1, $$2}'

build: ## Build the server binary into bin/keyora
	cd cmd/keyora && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o ../../bin/keyora .

run: build ## Run the server with SQLite in ./data
	./bin/keyora serve

test: ## Run all tests in every module
	@for m in $(MODULES); do echo "== $$m"; (cd $$m && go test -count=1 ./...) || exit 1; done

test-race: ## Run all tests with the race detector
	@for m in $(MODULES); do echo "== $$m"; (cd $$m && go test -count=1 -race ./...) || exit 1; done

cover: ## Write coverage.out and print total coverage of the core module
	go test -count=1 -coverpkg=./... -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -n 1

fuzz: ## Fuzz the token parser and password verifier for 30s each
	go test -run '^$$' -fuzz FuzzVerify -fuzztime 30s ./jwt/
	go test -run '^$$' -fuzz FuzzPasswordVerify -fuzztime 30s ./internal/security/

vet: ## Run go vet in every module and example
	@for m in $(MODULES) $(EXAMPLES); do (cd $$m && go vet ./...) || exit 1; done

fmt: ## Format all Go code
	gofmt -w .

fmt-check: ## Fail if any Go file is not gofmt-formatted
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "not formatted:"; echo "$$out"; exit 1; fi

check-deps: ## Fail if the core module has any third-party dependency
	@n="$$(go list -m all | wc -l | tr -d ' ')"; \
	if [ "$$n" != "1" ] || [ -f go.sum ]; then echo "the core module must have zero dependencies:"; go list -m all; exit 1; fi; \
	echo "core module has zero dependencies"

lint-openapi: ## Validate api/openapi.yaml (needs Node.js)
	npx --yes @redocly/cli@1 lint api/openapi.yaml

vuln: ## Scan every module for known vulnerabilities
	@for m in $(MODULES); do (cd $$m && go run golang.org/x/vuln/cmd/govulncheck@latest ./...) || exit 1; done

check: fmt-check vet check-deps test-race ## Everything CI runs, except Docker and OpenAPI lint

docker: ## Build the container image keyora:$(VERSION)
	docker build --build-arg VERSION=$(VERSION) -t keyora:$(VERSION) .

clean: ## Remove build output
	rm -rf bin coverage.out
