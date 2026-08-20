.PHONY: test lint tidy golden schema schema-check

CATALOG := schema/catalog.json

# Transport flags are the operator's: the exporter runs from wherever they
# already run the provider. See README.md.
#   make schema ADSCHEMA_FLAGS='--transport local'
ADSCHEMA_FLAGS ?=

test:
	go test ./...
lint:
	golangci-lint run
tidy:
	go mod tidy
golden:
	go test ./internal/adscript -run TestScriptGolden -update
	go test ./internal/adscript -run TestToolScriptGolden -update
	go test ./internal/adschema -run TestEmitGolden -update-golden

# Rewrite the committed catalog from a live domain. A deliberate act with a
# visible result: review the diff before committing it.
schema:
	go run ./cmd/adschema export $(ADSCHEMA_FLAGS) --out $(CATALOG)

# Regenerate to a temporary file and diff, so CI can prove the committed catalog
# matches what the exporter produces. Needs a reachable domain, which CI does
# not have today.
#
# exportedAt is provenance, not schema, so the committed value is passed back
# in. Without that every check would fail on the clock and the target would
# teach the team to ignore it.
schema-check:
	@at=$$(sed -n 's/^ *"exportedAt": *"\([^"]*\)".*/\1/p' $(CATALOG) 2>/dev/null | head -1); \
	 if [ -z "$$at" ]; then echo 'cannot read source.exportedAt from $(CATALOG)' >&2; exit 1; fi; \
	 tmp=$$(mktemp) || exit 1; \
	 trap 'rm -f "$$tmp"' EXIT; \
	 go run ./cmd/adschema export $(ADSCHEMA_FLAGS) --exported-at "$$at" --out "$$tmp" || exit 1; \
	 diff -u $(CATALOG) "$$tmp" || exit 1; \
	 echo 'schema: the committed catalog matches the domain'
