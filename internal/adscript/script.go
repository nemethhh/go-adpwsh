package adscript

import (
	"embed"
	"fmt"
	"sync"
)

//go:embed preamble.ps1 epilogue.ps1 ops/*.ps1
var files embed.FS

var (
	once     sync.Once
	composed map[string]string
	loadErr  error
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
	composed = make(map[string]string, len(ops))
	for _, op := range ops {
		frag, err := files.ReadFile("ops/" + op + ".ps1")
		if err != nil {
			loadErr = fmt.Errorf("adscript: missing fragment for op %q: %w", op, err)
			return
		}
		composed[op] = string(preamble) + string(frag) + string(epilogue)
	}
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
