//go:build acc

// TestAccDialectsAgree creates one object of each class through one dialect,
// reads it back through BOTH dialects, and requires the decoded DTOs to be
// identical. The JSON envelope is the contract both dialects promise to
// satisfy; this is the only test that checks the promise against the other
// side rather than against an expectation of it.
//
// It is gated on AD_ACC_DIFFERENTIAL=1 so it never runs by accident, and needs
// a Windows host with RSAT-AD-PowerShell reachable over WinRM:
//
//	AD_ACC_DIFFERENTIAL=1
//	AD_ACC_WINRM_HOST   e.g. s-client.corp.local
//	KRB5_CONFIG, KRB5CCNAME  a TGT that can reach both the WinRM host and the DC
package adpwsh_test

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/transport/winrm"
)

// accADWSClient builds a client on the ADWS dialect, reaching the Microsoft
// ActiveDirectory module through WinRM on a Windows host. It is the other side
// of the comparison; the PSOpenAD client comes from accClient.
func accADWSClient(t *testing.T) *adpwsh.Client {
	t.Helper()
	host := accEnv(t, "AD_ACC_WINRM_HOST")
	tr, err := winrm.New(winrm.Config{
		Host:         host,
		Realm:        os.Getenv("AD_ACC_REALM"),
		Krb5ConfPath: os.Getenv("KRB5_CONFIG"),
		CCachePath:   strings.TrimPrefix(os.Getenv("KRB5CCNAME"), "FILE:"),
		Username:     os.Getenv("AD_ACC_WINRM_USER"),
		Timeout:      120 * time.Second,
	})
	if err != nil {
		t.Fatalf("winrm.New: %v", err)
	}
	c, err := adpwsh.New(context.Background(), adpwsh.Config{
		Transport: tr,
		Server:    accEnv(t, "AD_ACC_SERVER"),
		Dialect:   adpwsh.DialectADWS,
	})
	if err != nil {
		t.Fatalf("adpwsh.New (adws): %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// requireSame compares two DTOs read through different dialects. A divergence
// is the most valuable signal this suite can produce: it means the JSON
// contract, which the whole design rests on, is not actually held. Nothing is
// normalised away - if a field has to be excused, that is a finding about the
// dialect, not about the test.
func requireSame(t *testing.T, what string, adws, psopenad any) {
	t.Helper()
	if reflect.DeepEqual(adws, psopenad) {
		return
	}
	a, _ := json.MarshalIndent(adws, "", "  ")
	p, _ := json.MarshalIndent(psopenad, "", "  ")
	t.Errorf("%s diverges between dialects\n--- adws ---\n%s\n--- psopenad ---\n%s", what, a, p)
}

func TestAccDialectsAgree(t *testing.T) {
	if os.Getenv("AD_ACC_DIFFERENTIAL") != "1" {
		t.Skip("set AD_ACC_DIFFERENTIAL=1 to run the cross-dialect comparison")
	}
	ctx := context.Background()
	ps := accClient(t)
	ad := accADWSClient(t)
	container := accContainer(t)

	t.Run("OU", func(t *testing.T) {
		for _, creator := range []struct {
			name string
			c    *adpwsh.Client
		}{{"created-by-adws", ad}, {"created-by-psopenad", ps}} {
			t.Run(creator.name, func(t *testing.T) {
				desc := "differential"
				name := accName("dou")
				made, err := creator.c.OU.Create(ctx, adpwsh.OUSpec{
					Name: name, Container: container, Description: &desc,
				})
				if err != nil {
					t.Fatalf("OU.Create: %v", err)
				}
				t.Cleanup(func() {
					_ = creator.c.OU.Delete(context.Background(), adpwsh.ByGUID(made.GUID), adpwsh.DeleteOptions{Unprotect: true})
				})
				viaADWS, err := ad.OU.Get(ctx, adpwsh.ByGUID(made.GUID))
				if err != nil {
					t.Fatalf("OU.Get via adws: %v", err)
				}
				viaPS, err := ps.OU.Get(ctx, adpwsh.ByGUID(made.GUID))
				if err != nil {
					t.Fatalf("OU.Get via psopenad: %v", err)
				}
				requireSame(t, "OU", viaADWS, viaPS)
			})
		}
	})

	t.Run("Group", func(t *testing.T) {
		for _, creator := range []struct {
			name string
			c    *adpwsh.Client
		}{{"created-by-adws", ad}, {"created-by-psopenad", ps}} {
			t.Run(creator.name, func(t *testing.T) {
				name := accName("dgrp")
				made, err := creator.c.Group.Create(ctx, adpwsh.GroupSpec{
					Name: name, SamAccountName: name, Container: container,
					Scope: adpwsh.GroupScopeGlobal, Category: adpwsh.GroupCategorySecurity,
				})
				if err != nil {
					t.Fatalf("Group.Create: %v", err)
				}
				t.Cleanup(func() { _ = creator.c.Group.Delete(context.Background(), adpwsh.ByGUID(made.GUID)) })
				viaADWS, err := ad.Group.Get(ctx, adpwsh.ByGUID(made.GUID))
				if err != nil {
					t.Fatalf("Group.Get via adws: %v", err)
				}
				viaPS, err := ps.Group.Get(ctx, adpwsh.ByGUID(made.GUID))
				if err != nil {
					t.Fatalf("Group.Get via psopenad: %v", err)
				}
				requireSame(t, "Group", viaADWS, viaPS)
			})
		}
	})

	t.Run("User", func(t *testing.T) {
		for _, creator := range []struct {
			name string
			c    *adpwsh.Client
		}{{"created-by-adws", ad}, {"created-by-psopenad", ps}} {
			t.Run(creator.name, func(t *testing.T) {
				name := accName("dusr")
				pw := adpwsh.NewSecret("Zq7!vMx2Lp#9Tr4W")
				enabled := true
				made, err := creator.c.User.Create(ctx, adpwsh.UserSpec{
					SamAccountName: name, Container: container,
					Password: &pw, Enabled: &enabled,
				})
				if err != nil {
					t.Fatalf("User.Create: %v", err)
				}
				t.Cleanup(func() { _ = creator.c.User.Delete(context.Background(), adpwsh.ByGUID(made.GUID)) })
				viaADWS, err := ad.User.Get(ctx, adpwsh.ByGUID(made.GUID))
				if err != nil {
					t.Fatalf("User.Get via adws: %v", err)
				}
				viaPS, err := ps.User.Get(ctx, adpwsh.ByGUID(made.GUID))
				if err != nil {
					t.Fatalf("User.Get via psopenad: %v", err)
				}
				requireSame(t, "User", viaADWS, viaPS)
			})
		}
	})

	t.Run("Computer", func(t *testing.T) {
		name := accShortName("c")
		made, err := ad.Computer.Create(ctx, adpwsh.ComputerSpec{
			Name: name, SamAccountName: name, Container: container,
		})
		if err != nil {
			t.Fatalf("Computer.Create: %v", err)
		}
		t.Cleanup(func() { _ = ad.Computer.Delete(context.Background(), adpwsh.ByGUID(made.GUID)) })
		viaADWS, err := ad.Computer.Get(ctx, adpwsh.ByGUID(made.GUID))
		if err != nil {
			t.Fatalf("Computer.Get via adws: %v", err)
		}
		viaPS, err := ps.Computer.Get(ctx, adpwsh.ByGUID(made.GUID))
		if err != nil {
			t.Fatalf("Computer.Get via psopenad: %v", err)
		}
		requireSame(t, "Computer", viaADWS, viaPS)
	})

	// A gMSA needs a KDS root key in the forest. Where there is none the class
	// cannot be created at all, which is an environment limit rather than a
	// dialect finding, so it is reported as a skip with the DC's own words.
	t.Run("GMSA", func(t *testing.T) {
		name := accShortName("g")
		made, err := ad.ServiceAccount.Create(ctx, adpwsh.GMSASpec{
			Name: name, SamAccountName: name, Container: container,
			DNSHostName: strPtr(name + ".corp.local"),
		})
		if err != nil {
			if strings.Contains(err.Error(), "key") || strings.Contains(err.Error(), "0x80070005") {
				t.Skipf("the forest has no KDS root key, so no gMSA can be created: %v", err)
			}
			t.Fatalf("ServiceAccount.Create: %v", err)
		}
		t.Cleanup(func() { _ = ad.ServiceAccount.Delete(context.Background(), adpwsh.ByGUID(made.GUID)) })
		viaADWS, err := ad.ServiceAccount.Get(ctx, adpwsh.ByGUID(made.GUID))
		if err != nil {
			t.Fatalf("ServiceAccount.Get via adws: %v", err)
		}
		viaPS, err := ps.ServiceAccount.Get(ctx, adpwsh.ByGUID(made.GUID))
		if err != nil {
			t.Fatalf("ServiceAccount.Get via psopenad: %v", err)
		}

		requireSame(t, "GMSA", viaADWS, viaPS)
	})
}

func strPtr(s string) *string { return &s }
