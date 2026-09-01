package winrm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/warm"
)

type stubExec struct {
	host       string
	connectErr error
	closed     bool
}

func (s *stubExec) Connect(ctx context.Context) error { return s.connectErr }
func (s *stubExec) Execute(ctx context.Context, wrapped string) (adpwsh.Result, error) {
	return adpwsh.Result{Stdout: s.host}, nil
}
func (s *stubExec) Close(ctx context.Context) error { s.closed = true; return nil }

// withStubs replaces the per-endpoint factory with stubs keyed by host and
// records the build order.
func withStubs(fe *failoverExecutor, stubs map[string]*stubExec, built *[]string) {
	fe.newExec = func(c Config) (warm.Executor, error) {
		*built = append(*built, c.Host)
		return stubs[c.Host], nil
	}
}

func TestFailoverBindsFirstHealthy(t *testing.T) {
	fe := newFailoverExecutor([]Config{{Host: "a"}, {Host: "b"}, {Host: "c"}})
	stubs := map[string]*stubExec{
		"a": {host: "a", connectErr: errors.New("refused")},
		"b": {host: "b"},
		"c": {host: "c"},
	}
	var built []string
	withStubs(fe, stubs, &built)

	if err := fe.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if strings.Join(built, ",") != "a,b" {
		t.Errorf("built = %v, want a then b (c never tried)", built)
	}
	if !stubs["a"].closed {
		t.Error("failed endpoint a should be Closed")
	}
	res, _ := fe.Execute(context.Background(), "x")
	if res.Stdout != "b" {
		t.Errorf("Execute delegated to %q, want b", res.Stdout)
	}
}

func TestFailoverAllFailAggregates(t *testing.T) {
	fe := newFailoverExecutor([]Config{{Host: "a"}, {Host: "b"}})
	var built []string
	withStubs(fe, map[string]*stubExec{
		"a": {host: "a", connectErr: errors.New("refused-a")},
		"b": {host: "b", connectErr: errors.New("refused-b")},
	}, &built)

	err := fe.Connect(context.Background())
	if err == nil {
		t.Fatal("want error when all endpoints fail")
	}
	for _, want := range []string{"all 2 WinRM endpoints", "a: refused-a", "b: refused-b"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestFailoverSingleEndpointReturnsRawError(t *testing.T) {
	raw := errors.New("refused")
	fe := newFailoverExecutor([]Config{{Host: "a"}})
	var built []string
	withStubs(fe, map[string]*stubExec{"a": {host: "a", connectErr: raw}}, &built)

	if err := fe.Connect(context.Background()); !errors.Is(err, raw) {
		t.Errorf("single-endpoint error = %v, want the raw error unwrapped", err)
	}
}

func TestConnectBudgetClamp(t *testing.T) {
	// ceiling: Timeout/n above the cap is clamped down (this is the hung-endpoint fix)
	if got := connectBudget(90*time.Second, 2); got != maxConnectBudget {
		t.Errorf("budget(90s,2) = %v, want ceiling %v", got, maxConnectBudget)
	}
	if got := connectBudget(60*time.Second, 3); got != maxConnectBudget {
		t.Errorf("budget(60s,3) = %v, want ceiling %v (20s clamped)", got, maxConnectBudget)
	}
	// mid-range: below the ceiling, above the floor, Timeout/n is used as-is
	if got := connectBudget(20*time.Second, 2); got != 10*time.Second {
		t.Errorf("budget(20s,2) = %v, want 10s", got)
	}
	// floor: tiny Timeout/n is raised to the minimum
	if got := connectBudget(3*time.Second, 3); got != minConnectBudget {
		t.Errorf("budget(3s,3) = %v, want floor %v", got, minConnectBudget)
	}
}
