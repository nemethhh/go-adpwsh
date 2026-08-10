.PHONY: test lint tidy golden
test:
	go test ./...
lint:
	golangci-lint run
tidy:
	go mod tidy
golden:
	go test ./internal/adscript -run TestScriptGolden -update
