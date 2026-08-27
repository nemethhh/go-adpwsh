//go:build localwarmlive

// Opt-in live test. Runs ON a Windows host with PowerShell 7 and the
// ActiveDirectory module, and a reachable DC. It proves the local+warm cell
// end-to-end against real AD the way the provider drives it — a pool of warm
// pwsh processes under concurrent load — including the spec's open item, that
// the [Console]::SetIn payload path (and the [PSCredential] rebuild that rides
// it) works inside a go-psrpcore out-of-proc runspace.
//
// Env:
//
//	AD_LIVE_SERVER    DC FQDN, e.g. s-server.corp.local
//	AD_LIVE_USER      domain credential, e.g. CORP\svc_tfacc
//	AD_LIVE_PASS      its password
//	AD_LIVE_CONTAINER a delegated OU the credential may write, e.g.
//	                  OU=tfacc,DC=corp,DC=local (required by the concurrent test)
//	AD_LIVE_IDENTITY  a sAMAccountName to read in the reuse smoke test (default krbtgt)
//
//	go test -tags localwarmlive ./transport/localwarm/ -run TestLive -v
package localwarm

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
)

type liveEnv struct{ server, user, pass, container string }

// liveClient builds an adpwsh.Client over a fresh local+warm transport at the
// given pool size — the same wiring the provider's Configure does.
func liveClient(t *testing.T, concurrency int) (*adpwsh.Client, liveEnv) {
	t.Helper()
	env := liveEnv{
		server:    os.Getenv("AD_LIVE_SERVER"),
		user:      os.Getenv("AD_LIVE_USER"),
		pass:      os.Getenv("AD_LIVE_PASS"),
		container: os.Getenv("AD_LIVE_CONTAINER"),
	}
	if env.server == "" || env.user == "" || env.pass == "" {
		t.Fatal("set AD_LIVE_SERVER, AD_LIVE_USER, AD_LIVE_PASS")
	}
	tr, err := New(Config{Concurrency: concurrency})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	client, err := adpwsh.New(context.Background(), adpwsh.Config{
		Transport:  tr,
		Server:     env.server,
		Credential: &adpwsh.Credential{Username: env.user, Password: adpwsh.NewSecret(env.pass)},
	})
	if err != nil {
		t.Fatalf("adpwsh.New: %v", err)
	}
	return client, env
}

// TestLiveWarmLocalReadReuse is the smoke test: on a pool of one, a second read
// reuses the warm runspace (module + startup already paid) and is faster than
// the first. This is the warm thesis at its simplest.
func TestLiveWarmLocalReadReuse(t *testing.T) {
	ident := os.Getenv("AD_LIVE_IDENTITY")
	if ident == "" {
		ident = "krbtgt"
	}
	client, _ := liveClient(t, 1)
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t0 := time.Now()
	if _, err := client.User.Get(ctx, adpwsh.BySAM(ident)); err != nil {
		t.Fatalf("first read: %v", err)
	}
	d1 := time.Since(t0)
	t1 := time.Now()
	if _, err := client.User.Get(ctx, adpwsh.BySAM(ident)); err != nil {
		t.Fatalf("second (warm) read: %v", err)
	}
	d2 := time.Since(t1)
	t.Logf("warm reuse: read#1=%s read#2=%s (saved ~%s)", d1, d2, d1-d2)
	if d2 >= d1 {
		t.Fatalf("warm reuse not demonstrated: read#2 (%s) not faster than read#1 (%s)", d2, d1)
	}
}

// TestLiveWarmLocalConcurrentPool exercises the transport the way the provider
// does: a pool of warm processes driven by many concurrent operations at once
// (Terraform's default parallelism is 10). It creates a subtree of distinct
// users CONCURRENTLY (the write path in parallel, as the keyed per-identity lock
// allows for distinct objects), then fires a read barrage far above the pool
// size, each read asking for a specific user and asserting it got THAT user
// back.
//
// That assertion is the load-bearing one: [Console]::SetIn payload delivery is
// process-global, so a pool that ever let two concurrently-busy operations share
// one process would cross their payloads (and their -Credential) and a Get would
// return the wrong object. Only "one process per pooled conn, concurrency from
// the pool" keeps this correct — and only a real concurrent run against AD can
// prove it. No unit test can.
func TestLiveWarmLocalConcurrentPool(t *testing.T) {
	const (
		concurrency = 4  // pool of 4 warm pwsh processes
		nUsers      = 8  // distinct objects, > pool size so processes are reused
		nReaders    = 40 // concurrent reads, far above pool size (Terraform-like load)
	)
	client, env := liveClient(t, concurrency)
	defer client.Close()
	if env.container == "" {
		t.Fatal("set AD_LIVE_CONTAINER (a delegated OU, e.g. OU=tfacc,DC=corp,DC=local)")
	}
	ctx := context.Background()

	short := fmt.Sprintf("%d", time.Now().UnixNano())
	short = short[len(short)-6:]

	// A unique parent OU so concurrent or repeated runs never collide.
	parent, err := client.OU.Create(ctx, adpwsh.OUSpec{Name: "lw-conc-" + short, Container: env.container})
	if err != nil {
		t.Fatalf("create parent OU: %v", err)
	}

	sams := make([]string, nUsers)
	for i := range sams {
		sams[i] = fmt.Sprintf("lwc%s-%d", short, i) // e.g. lwc123456-0, <= 20 chars
	}

	var mu sync.Mutex
	createdGUIDs := make([]string, 0, nUsers)

	// Teardown: delete users first (OU.Delete is deliberately non-recursive),
	// then the protected parent OU. On a fresh context so a cancelled test ctx
	// cannot orphan lab objects.
	defer func() {
		cctx := context.Background()
		mu.Lock()
		guids := append([]string(nil), createdGUIDs...)
		mu.Unlock()
		for _, g := range guids {
			if err := client.User.Delete(cctx, adpwsh.ByGUID(g)); err != nil {
				t.Errorf("cleanup: delete user %s: %v", g, err)
			}
		}
		if err := client.OU.Delete(cctx, adpwsh.ByGUID(parent.GUID), adpwsh.DeleteOptions{Unprotect: true}); err != nil {
			t.Errorf("cleanup: delete parent OU %s: %v", parent.DN, err)
		}
	}()

	// Phase 1 — concurrent CREATES of distinct users across the pool.
	var wg sync.WaitGroup
	cErr := make(chan error, nUsers)
	for i := 0; i < nUsers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u, err := client.User.Create(ctx, adpwsh.UserSpec{SamAccountName: sams[i], Container: parent.DN})
			if err != nil {
				cErr <- fmt.Errorf("create %s: %w", sams[i], err)
				return
			}
			if !strings.EqualFold(u.SamAccountName, sams[i]) {
				cErr <- fmt.Errorf("create %s returned sam %q", sams[i], u.SamAccountName)
				return
			}
			mu.Lock()
			createdGUIDs = append(createdGUIDs, u.GUID)
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	close(cErr)
	for err := range cErr {
		t.Fatal(err) // a create failure makes the correctness barrage below moot
	}

	// Phase 2 — the concurrency barrage: nReaders concurrent Gets, each asserting
	// it got back the exact user it asked for (the payload-isolation proof).
	rErr := make(chan error, nReaders)
	var rwg sync.WaitGroup
	t0 := time.Now()
	for r := 0; r < nReaders; r++ {
		rwg.Add(1)
		go func(r int) {
			defer rwg.Done()
			want := sams[r%nUsers]
			u, err := client.User.Get(ctx, adpwsh.BySAM(want))
			if err != nil {
				rErr <- fmt.Errorf("reader %d get %s: %w", r, want, err)
				return
			}
			if !strings.EqualFold(u.SamAccountName, want) {
				rErr <- fmt.Errorf("reader %d PAYLOAD CROSS-TALK: asked %q, got %q", r, want, u.SamAccountName)
			}
		}(r)
	}
	rwg.Wait()
	close(rErr)
	nErr := 0
	for err := range rErr {
		t.Error(err)
		nErr++
	}
	t.Logf("%d concurrent reads across a pool of %d over %d distinct users in %s (%d errors)",
		nReaders, concurrency, nUsers, time.Since(t0), nErr)

	// Phase 3 — provider-like update + read-back on one object.
	target := sams[0]
	newDisplay := "LocalWarm " + short
	if _, err := client.User.Update(ctx, adpwsh.BySAM(target), adpwsh.UserSpec{
		SamAccountName: target, Container: parent.DN, DisplayName: adpwsh.String(newDisplay),
	}); err != nil {
		t.Fatalf("update %s: %v", target, err)
	}
	got, err := client.User.Get(ctx, adpwsh.BySAM(target))
	if err != nil {
		t.Fatalf("read-back %s: %v", target, err)
	}
	if got.DisplayName != newDisplay {
		t.Errorf("update not reflected: DisplayName = %q, want %q", got.DisplayName, newDisplay)
	}
}
