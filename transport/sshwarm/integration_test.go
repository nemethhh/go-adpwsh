//go:build sshwarmlive

// Opt-in live test for the ssh+warm cell. Runs from anywhere that can SSH to the
// jump box (e.g. the Linux dev box) and drives the transport the way the PROVIDER
// does: a pool of warm pwsh -sshs subsystem runspaces under concurrent load, plus
// a real CRUD lifecycle. It proves the cell reads/writes real AD and that the
// pool keeps concurrently-busy operations isolated (the [Console]::SetIn payload
// path is process-global, so a pool that ever shared a process between two busy
// ops would cross their payloads and -Credential and a Get would return the wrong
// object — only a concurrent run against AD can prove it does not).
//
// The jump box must have the `powershell` sshd subsystem registered (see the
// phase-3 plan's Task 6), pointing at PowerShell 7 (5.1 cannot serve -sshs).
//
// Env:
//
//	AD_SSH_HOST       jump-box host/IP, e.g. 192.168.50.31 (x/crypto/ssh ignores
//	                  ~/.ssh/config, so use the address, not an alias)
//	AD_SSH_USER       ssh user, e.g. Administrator
//	AD_SSH_KEY        path to a private key  (or set AD_SSH_PASS instead)
//	AD_SSH_PASS       ssh password           (alternative to AD_SSH_KEY)
//	AD_LIVE_SERVER    DC FQDN, e.g. s-server.corp.local
//	AD_LIVE_CREDUSER  domain credential for AD ops, e.g. CORP\svc_tfacc
//	AD_LIVE_CREDPASS  its password
//	AD_LIVE_CONTAINER a delegated OU the credential may write, e.g.
//	                  OU=tfacc,DC=corp,DC=local (required by the concurrent test)
//	AD_LIVE_IDENTITY  a sAMAccountName to read in the smoke test (default krbtgt)
//
//	go test -tags sshwarmlive ./transport/sshwarm/ -run TestLive -v
package sshwarm

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	adssh "github.com/nemethhh/go-adpwsh/transport/ssh"
)

type sshEnv struct {
	host, user, key, pass      string
	server, credUser, credPass string
	container                  string
}

// liveClient builds an adpwsh.Client over a fresh ssh+warm transport at the given
// pool size — the same wiring the provider's Configure does. The pool is >1 and
// connects lazily; concurrency comes from the pool, exactly as in production.
func liveClient(t *testing.T, concurrency int) (*adpwsh.Client, sshEnv) {
	t.Helper()
	env := sshEnv{
		host:      os.Getenv("AD_SSH_HOST"),
		user:      os.Getenv("AD_SSH_USER"),
		key:       os.Getenv("AD_SSH_KEY"),
		pass:      os.Getenv("AD_SSH_PASS"),
		server:    os.Getenv("AD_LIVE_SERVER"),
		credUser:  os.Getenv("AD_LIVE_CREDUSER"),
		credPass:  os.Getenv("AD_LIVE_CREDPASS"),
		container: os.Getenv("AD_LIVE_CONTAINER"),
	}
	if env.host == "" || env.server == "" {
		t.Fatal("set AD_SSH_HOST and AD_LIVE_SERVER (+ ssh auth + AD cred env)")
	}
	sshCfg := adssh.Config{
		Host: env.host,
		User: env.user,
		// A lab jump box's host key is not in known_hosts; relax host-key checking
		// the way the ssh transport's own live tests do.
		InsecureIgnoreHostKey: true,
		Concurrency:           concurrency, // pool size = concurrent warm processes
	}
	// Exactly one credential source (adssh.Config.Validate enforces it): a key
	// path by default, or a password if AD_SSH_PASS is set.
	if env.pass != "" {
		sshCfg.Password = env.pass
	} else {
		sshCfg.PrivateKeyPath = env.key
	}

	tr, err := New(Config{SSH: sshCfg})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	client, err := adpwsh.New(context.Background(), adpwsh.Config{
		Transport:  tr,
		Server:     env.server,
		Credential: &adpwsh.Credential{Username: env.credUser, Password: adpwsh.NewSecret(env.credPass)},
	})
	if err != nil {
		t.Fatalf("adpwsh.New: %v", err)
	}
	return client, env
}

// TestLiveWarmSSHReadsAD is the smoke test: over a default-size warm pool, a read
// of a well-known object succeeds. It proves connect + subsystem channel +
// runspace + AD read end-to-end. (Perf/warm reuse is a property of the pool under
// load, exercised by the concurrent test below — NOT of two sequential reads on a
// shrunk pool, which would land on different cold conns and prove nothing.)
func TestLiveWarmSSHReadsAD(t *testing.T) {
	ident := os.Getenv("AD_LIVE_IDENTITY")
	if ident == "" {
		ident = "krbtgt"
	}
	client, _ := liveClient(t, 4)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	u, err := client.User.Get(ctx, adpwsh.BySAM(ident))
	if err != nil {
		t.Fatalf("read %s over warm-ssh: %v", ident, err)
	}
	if !strings.EqualFold(u.SamAccountName, ident) {
		t.Fatalf("asked for %q, got %q", ident, u.SamAccountName)
	}
	t.Logf("warm-ssh read OK: sam=%s dn=%s", u.SamAccountName, u.DN)
}

// TestLiveWarmSSHConcurrentPool exercises the transport the way the provider does:
// a pool of warm processes driven by many concurrent operations (Terraform's
// default parallelism is 10). It creates a subtree of distinct users CONCURRENTLY,
// then fires a read barrage far above the pool size, each read asserting it got
// back the user it ASKED for — the payload-isolation proof — then updates and
// reads one back. Only a real concurrent run against AD can prove this.
func TestLiveWarmSSHConcurrentPool(t *testing.T) {
	const (
		concurrency = 4  // pool of 4 warm pwsh -sshs processes (provider default)
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
	parent, err := client.OU.Create(ctx, adpwsh.OUSpec{Name: "sw-conc-" + short, Container: env.container})
	if err != nil {
		t.Fatalf("create parent OU: %v", err)
	}

	sams := make([]string, nUsers)
	for i := range sams {
		sams[i] = fmt.Sprintf("swc%s-%d", short, i) // e.g. swc123456-0, <= 20 chars
	}

	var mu sync.Mutex
	createdGUIDs := make([]string, 0, nUsers)

	// Teardown: delete users first (OU.Delete is deliberately non-recursive), then
	// the protected parent OU. On a fresh context so a cancelled test ctx cannot
	// orphan lab objects.
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
	newDisplay := "SshWarm " + short
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
