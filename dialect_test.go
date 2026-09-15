package adpwsh_test

import (
	"context"
	"strings"
	"testing"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/transport/fake"
)

func TestDialectStringIsStable(t *testing.T) {
	if got := adpwsh.DialectADWS.String(); got != "adws" {
		t.Fatalf("DialectADWS.String() = %q, want %q", got, "adws")
	}
	if got := adpwsh.DialectPSOpenAD.String(); got != "psopenad" {
		t.Fatalf("DialectPSOpenAD.String() = %q, want %q", got, "psopenad")
	}
}

func TestZeroValueDialectIsADWS(t *testing.T) {
	var cfg adpwsh.Config
	if cfg.Dialect != adpwsh.DialectADWS {
		t.Fatalf("zero-value Config.Dialect = %v, want DialectADWS", cfg.Dialect)
	}
}

func TestPSOpenADRejectsForceSync(t *testing.T) {
	tr := fake.New(func(fake.Call) fake.Response { return fake.OK(rootDSE()) })
	_, err := adpwsh.New(context.Background(), adpwsh.Config{
		Transport:   tr,
		Dialect:     adpwsh.DialectPSOpenAD,
		Replication: adpwsh.ReplicationConfig{Wait: true, ForceSync: true},
	})
	if err == nil {
		t.Fatal("expected New to reject ForceSync on the psopenad dialect")
	}
	if !strings.Contains(err.Error(), "ForceSync") {
		t.Fatalf("error should name ForceSync, got: %v", err)
	}
}

// The polling wait must not be rejected the way ForceSync is. This also proves
// the dialect composes end to end: New runs the rootdse op, so it only succeeds
// if the psopenad fragment set actually resolves.
func TestPSOpenADAllowsPollingWait(t *testing.T) {
	tr := fake.New(func(fake.Call) fake.Response { return fake.OK(rootDSE()) })
	c, err := adpwsh.New(context.Background(), adpwsh.Config{
		Transport:   tr,
		Dialect:     adpwsh.DialectPSOpenAD,
		Replication: adpwsh.ReplicationConfig{Wait: true},
	})
	if err != nil {
		t.Fatalf("polling wait should be allowed: %v", err)
	}
	_ = c.Close()
}
