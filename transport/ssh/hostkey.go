package ssh

import (
	"fmt"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// hostKeyCallback resolves the three host-key settings in their documented
// order.
func (c Config) hostKeyCallback() (ssh.HostKeyCallback, error) {
	if c.InsecureIgnoreHostKey {
		return ssh.InsecureIgnoreHostKey(), nil //nolint:gosec // explicit opt-out only
	}
	if c.HostKey != "" {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.HostKey))
		if err != nil {
			return nil, fmt.Errorf("ssh: cannot parse host_key: %w", err)
		}
		return ssh.FixedHostKey(pub), nil
	}
	cb, err := knownhosts.New(c.KnownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("ssh: cannot read known_hosts_file: %w", err)
	}
	return cb, nil
}
