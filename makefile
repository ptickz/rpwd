LOCAL_BIN:=$(CURDIR)/bin

install-deps:
	GOBIN=$(LOCAL_BIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

lint: ## go lint
	$(LOCAL_BIN)/golangci-lint run --color always
