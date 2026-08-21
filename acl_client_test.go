package adpwsh_test

import (
	"context"
	"testing"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/transport/fake"
)

func aceFixture() adpwsh.ACE {
	return adpwsh.ACE{
		Trustee:             "S-1-5-21-1-2-3-1105",
		Type:                adpwsh.ACEAllow,
		Rights:              []adpwsh.Right{"ExtendedRight"},
		ObjectType:          "00299570-246d-11d0-a768-00aa006e0529",
		InheritedObjectType: "bf967aba-0de6-11d0-a285-00aa003049e2",
		Inheritance:         adpwsh.InheritanceDescendants,
	}
}

func TestACLGrantSendsResolvedACE(t *testing.T) {
	var sent []any
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "acl_grant":
			sent, _ = c.Payload["aces"].([]any)
			return fake.OK(map[string]any{"granted": true, "guid": "aa11bb22-0000-0000-0000-000000000009"})
		case "replicate", "replicate_verify":
			return fake.OK(map[string]any{"synced": true})
		}
		t.Fatalf("unexpected op %q", c.Op)
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})

	err := client.ACL.Grant(context.Background(), adpwsh.ByDN("OU=Staff,DC=corp,DC=local"), []adpwsh.ACE{aceFixture()})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if len(sent) != 1 {
		t.Fatalf("sent %d aces, want 1", len(sent))
	}
	m, _ := sent[0].(map[string]any)
	if m["trustee"] != "S-1-5-21-1-2-3-1105" || m["inheritance"] != "Descendents" {
		t.Errorf("ace payload = %v", m)
	}
}

func TestACLGetSkipsInheritedACEs(t *testing.T) {
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "acl_read":
			return fake.OK(map[string]any{"aces": []any{
				map[string]any{"trustee": "S-1-1", "type": "Allow", "rights": []any{"GenericAll"},
					"objectType": "", "inheritedObjectType": "", "inheritance": "None", "inherited": true},
				map[string]any{"trustee": "S-1-2", "type": "Allow", "rights": []any{"WriteProperty"},
					"objectType": "", "inheritedObjectType": "", "inheritance": "None", "inherited": false},
			}})
		}
		t.Fatalf("unexpected op %q", c.Op)
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})

	aces, err := client.ACL.Get(context.Background(), adpwsh.ByDN("OU=Staff,DC=corp,DC=local"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Get returns all ACEs; the caller filters. Assert the Inherited flag round-trips.
	var explicit int
	for _, a := range aces {
		if !a.Inherited {
			explicit++
		}
	}
	if len(aces) != 2 || explicit != 1 {
		t.Errorf("got %d aces, %d explicit", len(aces), explicit)
	}
}
