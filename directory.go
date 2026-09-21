package adpwsh

import "github.com/nemethhh/go-adcore"

// Directory presents this client through the backend-neutral contract. The
// sub-clients already have the right method sets, so this is a projection,
// not an adapter: no behaviour is added or changed here.
func (c *Client) Directory() adcore.Directory {
	return adcore.Directory{
		OU:             c.OU,
		Group:          c.Group,
		User:           c.User,
		ServiceAccount: c.ServiceAccount,
		Computer:       c.Computer,
		ACL:            c.ACL,
		Schema:         c.Schema,
		Server:         c.core.server,
		DNC:            c.core.dnc,
		Closer:         c,
	}
}
