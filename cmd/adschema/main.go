// Command adschema exports an Active Directory schema catalog: every
// attribute's type and constraints, and every requested class's effective set
// of allowed attributes.
//
//	adschema export --transport local|ssh [transport flags] \
//	                --server dc01.corp.local \
//	                --classes user,group,organizationalUnit \
//	                --out schema/catalog.json
//
// It is build-time tooling, not one of the library's operations: nothing in an
// apply path queries the schema. It obeys the same contract every operation
// does — the script is a constant, every value arrives as JSON on stdin, and no
// value is ever formatted into script text — and it only reads. Extending a
// schema is irreversible and forest-wide, and no tool of ours should make it
// easy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/internal/adschema"
)

type config struct {
	spec       adschema.TransportSpec
	server     string
	classes    []string
	all        bool
	out        string
	exportedAt time.Time
	timeout    time.Duration
	cred       *adschema.Credential
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "adschema: "+render(err))
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] != "export" {
		usage()
		return errors.New(`the only subcommand is "export"`)
	}
	cfg, err := parseArgs(args[1:], os.Getenv, time.Now())
	if err != nil {
		return err
	}

	tr, err := cfg.spec.Open()
	if err != nil {
		return err
	}
	defer func() { _ = tr.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	raw, err := adschema.Fetch(ctx, tr, adschema.FetchOptions{Server: cfg.server, Credential: cfg.cred})
	if err != nil {
		return err
	}

	classes := cfg.classes
	if cfg.all {
		classes = adschema.AllStructural(raw)
	}
	cat, err := adschema.Build(raw, classes, cfg.exportedAt)
	if err != nil {
		return err
	}
	body, err := adschema.Emit(cat)
	if err != nil {
		return err
	}

	if cfg.out == "-" {
		_, err = os.Stdout.Write(body)
		return err
	}
	if err := writeFileAtomic(cfg.out, body); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr,
		"adschema: wrote %s — %d attributes, %d classes, objectVersion %d, from %s (%s)\n",
		cfg.out, len(cat.Attributes), len(cat.Classes), cat.Source.ObjectVersion,
		cat.Source.Domain, cat.Source.ForestMode)
	return nil
}

func usage() {
	fmt.Fprint(os.Stderr, `adschema exports an Active Directory schema catalog.

usage:
  adschema export --transport local [--pwsh-path PATH] [flags]
  adschema export --transport ssh --ssh-host HOST --ssh-user USER \
                  (--ssh-private-key-path PATH | --ssh-password-env VAR) \
                  (--ssh-known-hosts FILE | --ssh-host-key LINE | --ssh-insecure-ignore-host-key) [flags]

Run "adschema export -h" for every flag.
`)
}

func parseArgs(args []string, getenv func(string) string, now time.Time) (*config, error) {
	fs := flag.NewFlagSet("adschema export", flag.ContinueOnError)

	transport := fs.String("transport", "", `"local" or "ssh" (required)`)
	server := fs.String("server", "", "domain controller every cmdlet targets; empty lets the Windows host resolve one")
	classes := fs.String("classes", "organizationalUnit,group,user",
		`classes to resolve, comma separated, or "all" for every structural class`)
	out := fs.String("out", "schema/catalog.json", `file to write; "-" writes to stdout`)
	exportedAt := fs.String("exported-at", "",
		"provenance timestamp, RFC 3339; defaults to now. make schema-check passes the committed catalog's own value, so an unchanged schema diffs clean")
	timeout := fs.Duration("timeout", 5*time.Minute, "ceiling on the fetch")
	pwshPath := fs.String("pwsh-path", "", `PowerShell 7 executable on the Windows host (default "pwsh")`)

	adUsername := fs.String("ad-username", "", "user the AD cmdlets run as; omit to use the session's own identity")
	adPasswordEnv := fs.String("ad-password-env", "", "name of the environment variable holding that user's password; a password in argv is visible in the process list")

	sshHost := fs.String("ssh-host", "", "Windows host running OpenSSH Server")
	sshPort := fs.Int("ssh-port", 22, "SSH port")
	sshUser := fs.String("ssh-user", "", "SSH user")
	sshKeyPath := fs.String("ssh-private-key-path", "", "SSH private key file")
	sshPasswordEnv := fs.String("ssh-password-env", "", "name of the environment variable holding the SSH password")
	sshKnownHosts := fs.String("ssh-known-hosts", "", "known_hosts file used to verify the host key")
	sshHostKey := fs.String("ssh-host-key", "", "pinned host key, as an authorized_keys line")
	sshInsecure := fs.Bool("ssh-insecure-ignore-host-key", false, "skip host key verification")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	cfg := &config{
		spec: adschema.TransportSpec{
			Kind:                     *transport,
			Timeout:                  *timeout,
			PwshPath:                 *pwshPath,
			SSHHost:                  *sshHost,
			SSHPort:                  *sshPort,
			SSHUser:                  *sshUser,
			SSHPrivateKeyPath:        *sshKeyPath,
			SSHKnownHostsFile:        *sshKnownHosts,
			SSHHostKey:               *sshHostKey,
			SSHInsecureIgnoreHostKey: *sshInsecure,
		},
		server:     *server,
		out:        *out,
		timeout:    *timeout,
		exportedAt: now,
	}

	if *sshPasswordEnv != "" {
		pw := getenv(*sshPasswordEnv)
		if pw == "" {
			return nil, fmt.Errorf("%s is unset or empty, so --ssh-password-env has no password to read", *sshPasswordEnv)
		}
		cfg.spec.SSHPassword = pw
	}

	// Both or neither: a username with no password would silently fall back to
	// the session's identity and export as the wrong principal.
	switch {
	case *adUsername != "" && *adPasswordEnv == "":
		return nil, errors.New("--ad-username needs --ad-password-env")
	case *adUsername == "" && *adPasswordEnv != "":
		return nil, errors.New("--ad-password-env needs --ad-username")
	case *adUsername != "":
		pw := getenv(*adPasswordEnv)
		if pw == "" {
			return nil, fmt.Errorf("%s is unset or empty, so --ad-password-env has no password to read", *adPasswordEnv)
		}
		cfg.cred = &adschema.Credential{Username: *adUsername, Password: pw}
	}

	if strings.TrimSpace(*classes) == "all" {
		cfg.all = true
	} else {
		for _, name := range strings.Split(*classes, ",") {
			if n := strings.TrimSpace(name); n != "" {
				cfg.classes = append(cfg.classes, n)
			}
		}
		if len(cfg.classes) == 0 {
			return nil, errors.New("--classes named no class")
		}
	}

	if *exportedAt != "" {
		at, err := time.Parse(time.RFC3339, *exportedAt)
		if err != nil {
			return nil, fmt.Errorf("--exported-at must be an RFC 3339 timestamp: %w", err)
		}
		cfg.exportedAt = at
	}
	return cfg, nil
}

// render turns the library's error into the CLI's message. The Kind is what a
// person acts on, and Target names the container AD refused, which Error()
// itself does not print.
func render(err error) string {
	var e *adpwsh.Error
	if !errors.As(err, &e) {
		return err.Error()
	}
	msg := e.Error()
	if e.Target != "" {
		msg += " (target " + e.Target + ")"
	}
	switch e.Kind {
	case adpwsh.KindDenied:
		msg += "\n  the account reading the schema needs read access to the schema naming context"
	case adpwsh.KindTransport:
		msg += "\n  check the transport, and that the domain controller answers on TCP 9389"
	}
	return msg
}

// writeFileAtomic writes through a temporary file in the same directory and
// renames. A failed export must not leave a truncated catalog behind, because
// the next thing that reads it is a commit.
func writeFileAtomic(path string, body []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("cannot create a temporary file in %s: %w", dir, err)
	}
	name := tmp.Name()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return fmt.Errorf("cannot write %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("cannot close %s: %w", name, err)
	}
	if err := os.Chmod(name, 0o644); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("cannot rename %s to %s: %w", name, path, err)
	}
	return nil
}
