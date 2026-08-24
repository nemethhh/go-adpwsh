package adpwsh

import (
	"context"
	"errors"

	"github.com/nemethhh/go-adpwsh/internal/adscript"
)

// Client is the entry point. Its sub-clients map one method to one provider
// resource operation.
type Client struct {
	OU             *OUClient
	Group          *GroupClient
	User           *UserClient
	ServiceAccount *ServiceAccountClient
	Schema         *SchemaClient
	ACL            *ACLClient
	Delegation     *DelegationClient

	core *core
}

// New validates the configuration, resolves the domain controller this client
// will pin for its lifetime, and proves the jump box can import the
// ActiveDirectory module. It performs one round trip.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Transport == nil {
		return nil, &Error{Kind: KindTransport, Op: "New", Err: errors.New("adpwsh: Config.Transport is required")}
	}
	c := &core{
		tr:     cfg.Transport,
		server: cfg.Server,
		cred:   cfg.Credential,
		retry:  cfg.Retry.withDefaults(),
		repl:   cfg.Replication.withDefaults(),
		log:    cfg.Log,
		locks:  newKeyedMutex(),
	}

	var rootDSE struct {
		DNSHostName          string `json:"dnsHostName"`
		DefaultNamingContext string `json:"defaultNamingContext"`
		SchemaNamingContext  string `json:"schemaNamingContext"`
	}
	if err := c.exec(ctx, adscript.OpRootDSE, map[string]any{}, &rootDSE); err != nil {
		return nil, err
	}
	if c.server == "" {
		if rootDSE.DNSHostName == "" {
			return nil, &Error{Kind: KindTransport, Op: "New", Err: errors.New("adpwsh: rootDSE returned no dnsHostName; cannot pin a domain controller")}
		}
		c.server = rootDSE.DNSHostName
	}
	c.dnc = rootDSE.DefaultNamingContext

	client := &Client{core: c}
	client.OU = &OUClient{c: c}
	client.Group = &GroupClient{c: c}
	client.User = &UserClient{c: c}
	client.ServiceAccount = &ServiceAccountClient{c: c}
	client.Schema = &SchemaClient{c: c}
	client.ACL = &ACLClient{c: c}
	client.Delegation = &DelegationClient{}
	return client, nil
}

// Server returns the pinned domain controller.
func (c *Client) Server() string { return c.core.server }

// DefaultNamingContext returns the domain's naming context, e.g.
// "DC=corp,DC=local".
func (c *Client) DefaultNamingContext() string { return c.core.dnc }

// Close releases the transport.
func (c *Client) Close() error { return c.core.tr.Close() }
