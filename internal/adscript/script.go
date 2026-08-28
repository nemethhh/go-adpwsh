package adscript

import (
	"embed"
	"fmt"
	"sync"
)

//go:embed preamble.ps1 epilogue.ps1 ops/*.ps1 tools/*.ps1 endpoint/*.ps1
var files embed.FS

var (
	once          sync.Once
	composed      map[string]string
	composedTools map[string]string
	loadErr       error
)

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
	composedTools, loadErr = compose(preamble, epilogue, "tools/", tools)
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
