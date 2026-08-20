package schema

import (
	"bytes"
	_ "embed"
	"sync"
)

// baselineJSON is the catalog committed with this module. It is embedded
// because that is the only way a consumer in another module can reach it: Go
// gives no access to a dependency's files at run time, and a catalog nobody can
// read is inert data.
//
//go:embed catalog.json
var baselineJSON []byte

var (
	baselineOnce sync.Once
	baseline     *Catalog
	baselineErr  error
)

// Baseline returns the catalog committed with this module: a stock Windows
// Server 2025 forest with no schema extension.
//
// It is a baseline, not an authority on any particular forest. Exchange alone
// adds roughly a thousand attributes and several auxiliary classes, so a
// consumer that must be right about a specific domain reads a catalog exported
// from that domain — see the regeneration section of README.md. Source names
// which domain, forest mode and schema objectVersion this one came from.
//
// The returned catalog is parsed once and shared. Do not modify it.
func Baseline() (*Catalog, error) {
	baselineOnce.Do(func() { baseline, baselineErr = Load(bytes.NewReader(baselineJSON)) })
	return baseline, baselineErr
}
