package adscript

import (
	"embed"
	"fmt"
	"sync"
)

//go:embed preamble.ps1 epilogue.ps1 ops/*.ps1 tools/*.ps1 endpoint/*.ps1
//go:embed all:ops_psopenad
var files embed.FS

var (
	once          sync.Once
	composed      map[string]string
	composedTools map[string]string
	loadErr       error
)

// composedByDialect holds one op->script map per dialect name.
var composedByDialect map[string]map[string]string

func load() {
	preamble, err := files.ReadFile("preamble.ps1")
	if err != nil {
		loadErr = err
		return
	}
	epilogue, err := files.ReadFile("epilogue.ps1")
	if err != nil {
		loadErr = err
		return
	}
	if composed, loadErr = compose(preamble, epilogue, "ops/", ops); loadErr != nil {
		return
	}
	if composedTools, loadErr = compose(preamble, epilogue, "tools/", tools); loadErr != nil {
		return
	}

	composedByDialect = map[string]map[string]string{"adws": composed}

	// The psopenad dialect carries its own preamble and epilogue. While it is
	// still being filled in, a missing file leaves the set empty rather than
	// failing the whole package.
	psPre, preErr := files.ReadFile("ops_psopenad/preamble.ps1")
	psEpi, epiErr := files.ReadFile("ops_psopenad/epilogue.ps1")
	psSet := map[string]string{}
	if preErr == nil && epiErr == nil {
		for _, name := range ops {
			frag, err := files.ReadFile("ops_psopenad/" + name + ".ps1")
			if err != nil {
				continue // not yet implemented; ScriptFor reports it per-op
			}
			psSet[name] = string(psPre) + string(frag) + string(psEpi)
		}
	}
	composedByDialect["psopenad"] = psSet
}

// compose concatenates the preamble, one fragment and the epilogue for every
// name in a closed set. Nothing is formatted; the only variable is which of a
// fixed set of fragments is chosen.
func compose(preamble, epilogue []byte, dir string, names []string) (map[string]string, error) {
	out := make(map[string]string, len(names))
	for _, name := range names {
		frag, err := files.ReadFile(dir + name + ".ps1")
		if err != nil {
			return nil, fmt.Errorf("adscript: missing fragment for %q: %w", name, err)
		}
		out[name] = string(preamble) + string(frag) + string(epilogue)
	}
	return out, nil
}

// Script returns the complete, constant PowerShell text for op: the preamble,
// the operation's fragment, and the epilogue, concatenated. Nothing is
// formatted; the only variable is which of a fixed set of fragments is chosen.
func Script(op string) (string, error) {
	once.Do(load)
	if loadErr != nil {
		return "", loadErr
	}
	s, ok := composed[op]
	if !ok {
		return "", fmt.Errorf("adscript: unknown op %q", op)
	}
	return s, nil
}

// ScriptFor returns the complete PowerShell text for op in the named dialect.
// dialect is "adws" or "psopenad". Nothing is formatted; the only variables are
// which dialect's fragment set is consulted and which fragment within it.
func ScriptFor(dialect, op string) (string, error) {
	once.Do(load)
	if loadErr != nil {
		return "", loadErr
	}
	set, ok := composedByDialect[dialect]
	if !ok {
		return "", fmt.Errorf("adscript: unknown dialect %q", dialect)
	}
	s, ok := set[op]
	if !ok {
		return "", fmt.Errorf("adscript: dialect %q has no fragment for op %q", dialect, op)
	}
	return s, nil
}

// ToolScript returns the complete, constant PowerShell text for a build-time
// tool. It shares the preamble and the epilogue with every op, so a tool
// inherits the same credential handling, error shape and result framing rather
// than restating them. name comes from the closed tool set, which does not
// overlap the op set.
func ToolScript(name string) (string, error) {
	once.Do(load)
	if loadErr != nil {
		return "", loadErr
	}
	s, ok := composedTools[name]
	if !ok {
		return "", fmt.Errorf("adscript: unknown tool script %q", name)
	}
	return s, nil
}
