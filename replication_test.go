package adpwsh_test

import (
	"context"
	"errors"
	"testing"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/transport/fake"
)

func ouData() map[string]any {
	return map[string]any{
		"objectGUID": "9f2c", "distinguishedName": "OU=Staff,DC=corp,DC=local",
		"name": "Staff", "description": "", "protected": true,
	}
}

func TestReplicationDisabledIssuesNoCalls(t *testing.T) {
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "ou_create":
			return fake.OK(ouData())
		}
		t.Fatalf("unexpected op %q with replication off", c.Op)
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})
	if _, err := client.OU.Create(context.Background(), adpwsh.OUSpec{Name: "Staff", Container: "DC=corp,DC=local"}); err != nil {
		t.Fatal(err)
	}
}

func TestReplicationSyncsThenPolls(t *testing.T) {
	var syncs, verifies int
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "ou_create":
			return fake.OK(ouData())
		case "replicate":
			syncs++
			if c.Payload["source"] != "dc01.corp.local" {
				t.Errorf("source = %v, want the pinned DC", c.Payload["source"])
			}
			return fake.OK(map[string]any{"synced": true})
		case "replicate_verify":
			verifies++
			present := verifies >= 2 // absent on the first poll, present on the second
			return fake.OK(map[string]any{"results": []any{
				map[string]any{"target": "dc02.corp.local", "present": present},
			}})
		}
		t.Fatalf("unexpected op %q", c.Op)
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{
		Transport: tr,
		Server:    "dc01.corp.local",
		Replication: adpwsh.ReplicationConfig{
			Wait: true, ForceSync: true, Targets: []string{"dc02.corp.local"},
			Timeout: 2 * time.Second, PollInterval: time.Millisecond,
		},
	})
	if _, err := client.OU.Create(context.Background(), adpwsh.OUSpec{Name: "Staff", Container: "DC=corp,DC=local"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if syncs != 1 || verifies != 2 {
		t.Errorf("syncs = %d, verifies = %d; want 1 and 2", syncs, verifies)
	}
}

// The object exists and the wait did not complete. Both the model and the
// error must come back, because erroring without the model orphans the object.
func TestReplicationTimeoutReturnsModelAndError(t *testing.T) {
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "ou_create":
			return fake.OK(ouData())
		case "replicate":
			return fake.OK(map[string]any{"synced": true})
		default: // replicate_verify: never converges
			return fake.OK(map[string]any{"results": []any{
				map[string]any{"target": "dc02.corp.local", "present": false},
			}})
		}
	})
	client := mustClient(t, adpwsh.Config{
		Transport: tr,
		Server:    "dc01.corp.local",
		Replication: adpwsh.ReplicationConfig{
			Wait: true, ForceSync: true, Targets: []string{"dc02.corp.local"},
			Timeout: 25 * time.Millisecond, PollInterval: 5 * time.Millisecond,
		},
	})
	ou, err := client.OU.Create(context.Background(), adpwsh.OUSpec{Name: "Staff", Container: "DC=corp,DC=local"})
	if err == nil {
		t.Fatal("expected a replication error")
	}
	if !errors.Is(err, adpwsh.ErrReplication) {
		t.Errorf("want KindReplication, got %v", err)
	}
	if ou == nil || ou.GUID != "9f2c" {
		t.Fatalf("the model must accompany the error, got %+v", ou)
	}
	var e *adpwsh.Error
	if errors.As(err, &e) && e.Kind.String() == "transient" {
		t.Error("a replication timeout must never be retryable")
	}
}

// Targets = ["all"] expands through Get-ADDomainController, excluding the
// source, so the caller does not have to enumerate the topology.
func TestReplicationExpandsAllTargets(t *testing.T) {
	var verified []any
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "ou_create":
			return fake.OK(ouData())
		case "dclist":
			return fake.OK(map[string]any{"hostNames": []any{"dc01.corp.local", "dc02.corp.local", "dc03.corp.local"}})
		case "replicate":
			return fake.OK(map[string]any{"synced": true})
		default:
			verified, _ = c.Payload["targets"].([]any)
			return fake.OK(map[string]any{"results": []any{
				map[string]any{"target": "dc02.corp.local", "present": true},
				map[string]any{"target": "dc03.corp.local", "present": true},
			}})
		}
	})
	client := mustClient(t, adpwsh.Config{
		Transport: tr, Server: "dc01.corp.local",
		Replication: adpwsh.ReplicationConfig{
			Wait: true, ForceSync: true, Targets: []string{"all"},
			Timeout: time.Second, PollInterval: time.Millisecond,
		},
	})
	if _, err := client.OU.Create(context.Background(), adpwsh.OUSpec{Name: "Staff", Container: "DC=corp,DC=local"}); err != nil {
		t.Fatal(err)
	}
	if len(verified) != 2 {
		t.Errorf("targets = %v, want the two DCs that are not the source", verified)
	}
}
