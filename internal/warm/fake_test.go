package warm

import (
	"context"
	"sync"

	adpwsh "github.com/nemethhh/go-adpwsh"
)

// fakeExec is a scriptable Executor. connectErr/execResult/execErr drive one
// call each; callsMu-guarded counters let tests assert checkout spread.
type fakeExec struct {
	id         int
	mu         sync.Mutex
	connects   int
	executes   int
	closes     int
	connectErr error
	result     adpwsh.Result
	execErr    error
}

func (f *fakeExec) Connect(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connects++
	return f.connectErr
}
func (f *fakeExec) Execute(context.Context, string) (adpwsh.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.executes++
	return f.result, f.execErr
}
func (f *fakeExec) Close(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes++
	return nil
}

// fakeClassifier lets a test declare, for a given sentinel error, its Kind and
// whether it is a dead shell — replacing the real go-psrp/wsman detection.
type fakeClassifier struct {
	kind      map[error]adpwsh.Kind
	deadShell map[error]bool
}

func (c fakeClassifier) MapError(err error) error {
	k := adpwsh.KindTransport
	if c.kind != nil {
		if kk, ok := c.kind[err]; ok {
			k = kk
		}
	}
	return &adpwsh.Error{Kind: k, Op: "Execute", Err: err}
}
func (c fakeClassifier) DeadShell(err error) bool {
	return c.deadShell != nil && c.deadShell[err]
}

// identityWrapper is the no-op wrapper for tests that don't exercise payload.
func identityWrapper(script string, _ []byte) string { return script }
