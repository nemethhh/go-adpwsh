package winrm

import (
	"context"
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/smnsjas/go-psrp/winrs"
	"github.com/smnsjas/go-psrp/wsman"
	"github.com/smnsjas/go-psrp/wsman/auth"
	"github.com/smnsjas/go-psrp/wsman/transport"
)

// coldExecutor runs exactly one WinRS cold operation. The seam exists so the
// wrap/encode logic in ColdTransport.Run is unit-testable with a fake, without a
// live WinRM host.
type coldExecutor interface {
	// exec creates a fresh WinRS shell, starts the bootstrap
	// (`<pwsh> -EncodedCommand <encodedBootstrap>`), feeds stdin, signals EOF, and
	// returns the collected result. One-shot: the shell is created and torn down.
	exec(ctx context.Context, encodedBootstrap string, stdin []byte) (adpwsh.Result, error)
	// close releases the shared HTTP transport's idle connections.
	close() error
}

func randUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// endTransport wraps go-psrp's *wsman.Client (Command/Receive/Signal/Delete are
// promoted) but supplies the two things go-psrp's WinRS support gets wrong,
// discovered by lab bisection (see docs/superpowers/analysis/
// 2026-08-27-winrm-cold-stdin-spike.md):
//
//   - Create: go-psrp's wsman.Client.Create hardcodes the *PSRP* RunspacePool
//     stream body ("stdin pr" / "stdout") and reuses it for WinRS shells too. A
//     WinRS cmd shell with "stdin pr" declared makes the server ACCEPT every
//     Send (returns <rsp:SendResponse/>) yet never route the bytes to the
//     process's stdin. A cmd shell needs <rsp:InputStreams>stdin</> and
//     <rsp:OutputStreams>stdout stderr</>. Removing "pr" is the decisive fix.
//   - closeStdin: go-psrp's Send never sets End="true", so stdin is never closed;
//     a process reading to EOF (our bootstrap's [Console]::In.ReadToEnd) blocks
//     forever. A separate empty Stream with End="true" signals EOF.
//
// Everything else (auth, encryption, Command, Receive, Signal, Delete) is
// go-psrp, consumed unchanged, via its public wsman/transport/auth packages.
type endTransport struct {
	*wsman.Client
	tr        *transport.HTTPTransport
	endpoint  string
	sessionID string
	idle      time.Duration
}

// Create posts a correct WinRS cmd-shell body and parses the returned EPR. It
// ignores the go-psrp options/creationXML args on purpose: this transport only
// ever creates one-shot WinRS cmd shells.
func (e *endTransport) Create(ctx context.Context, _ map[string]string, _ string) (*wsman.EndpointReference, error) {
	idle := int(e.idle.Seconds())
	if idle <= 0 {
		idle = 180
	}
	shellID := strings.ToUpper(randUUID())
	env := wsman.NewEnvelope().
		WithAction(wsman.ActionCreate).
		WithTo(e.endpoint).
		WithResourceURI(wsman.ResourceURIWinRS).
		WithMessageID("uuid:" + randUUID()).
		WithReplyTo(wsman.AddressAnonymous).
		WithMaxEnvelopeSize(512000).
		WithOperationTimeout("PT60S").
		WithSessionID(e.sessionID).
		WithLocale("en-US").
		WithDataLocale("en-US").
		WithShellNamespace().
		WithOption("WINRS_NOPROFILE", "TRUE")
	env.WithBody([]byte(fmt.Sprintf(`<rsp:Shell ShellId="%s" xmlns:rsp="%s">
  <rsp:InputStreams>stdin</rsp:InputStreams>
  <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>
  <rsp:IdleTimeOut>PT%dS</rsp:IdleTimeOut>
</rsp:Shell>`, shellID, wsman.NsShell, idle)))
	raw, err := env.Marshal()
	if err != nil {
		return nil, fmt.Errorf("winrm.cold: marshal create: %w", err)
	}
	resp, err := e.tr.Post(ctx, e.endpoint, raw)
	if err != nil {
		return nil, fmt.Errorf("winrm.cold: create shell: %w", err)
	}
	var cr struct {
		ResourceCreated struct {
			Address             string `xml:"Address"`
			ReferenceParameters struct {
				ResourceURI string `xml:"ResourceURI"`
				Selectors   []struct {
					Name  string `xml:"Name,attr"`
					Value string `xml:",chardata"`
				} `xml:"SelectorSet>Selector"`
			} `xml:"ReferenceParameters"`
		} `xml:"Body>ResourceCreated"`
	}
	if err := xml.Unmarshal(resp, &cr); err != nil {
		return nil, fmt.Errorf("winrm.cold: parse create response: %w", err)
	}
	epr := &wsman.EndpointReference{
		Address:     cr.ResourceCreated.Address,
		ResourceURI: cr.ResourceCreated.ReferenceParameters.ResourceURI,
	}
	if epr.ResourceURI == "" {
		epr.ResourceURI = wsman.ResourceURIWinRS
	}
	for _, s := range cr.ResourceCreated.ReferenceParameters.Selectors {
		epr.Selectors = append(epr.Selectors, wsman.Selector{Name: s.Name, Value: s.Value})
	}
	if len(epr.Selectors) == 0 {
		return nil, fmt.Errorf("winrm.cold: create response carried no shell selector: %s", resp)
	}
	return epr, nil
}

// closeStdin sends a separate empty stdin Stream with End="true" to signal EOF.
func (e *endTransport) closeStdin(ctx context.Context, epr *wsman.EndpointReference, commandID string) error {
	env := wsman.NewEnvelope().
		WithAction(wsman.ActionSend).
		WithTo(e.endpoint).
		WithResourceURI(epr.ResourceURI).
		WithMessageID("uuid:" + randUUID()).
		WithReplyTo(wsman.AddressAnonymous).
		WithMaxEnvelopeSize(512000).
		WithOperationTimeout("PT60S").
		WithSessionID(e.sessionID).
		WithLocale("en-US").
		WithDataLocale("en-US").
		WithShellNamespace()
	for _, s := range epr.Selectors {
		env.WithSelector(s.Name, s.Value)
	}
	env.WithBody([]byte(fmt.Sprintf(
		`<rsp:Send xmlns:rsp="%s"><rsp:Stream Name="stdin" CommandId="%s" End="true"></rsp:Stream></rsp:Send>`,
		wsman.NsShell, commandID)))
	raw, err := env.Marshal()
	if err != nil {
		return fmt.Errorf("winrm.cold: marshal closeStdin: %w", err)
	}
	if _, err := e.tr.Post(ctx, e.endpoint, raw); err != nil {
		return fmt.Errorf("winrm.cold: close stdin: %w", err)
	}
	return nil
}

// newEndTransport builds the WinRS/Kerberos stack from cfg using go-psrp's public
// packages, mirroring how go-psrp's client.New wires Negotiate/Kerberos.
func newEndTransport(cfg Config) (*endTransport, error) {
	scheme := "http"
	if cfg.UseTLS {
		scheme = "https"
	}
	port := cfg.Port
	if port == 0 {
		if cfg.UseTLS {
			port = 5986
		} else {
			port = 5985
		}
	}
	endpoint := fmt.Sprintf("%s://%s:%d/wsman", scheme, cfg.Host, port)

	tr := transport.NewHTTPTransport(
		transport.WithTimeout(cfg.Timeout),
		transport.WithInsecureSkipVerify(cfg.InsecureSkipVerify),
	)
	creds := auth.Credentials{Username: cfg.Username, Password: cfg.Password, Domain: cfg.Domain}
	provider, err := auth.NewKerberosProvider(auth.KerberosProviderConfig{
		TargetSPN:    cfg.SPN,
		Realm:        cfg.Realm,
		Krb5ConfPath: cfg.Krb5ConfPath,
		KeytabPath:   cfg.KeytabPath,
		CCachePath:   cfg.CCachePath,
		Credentials:  &creds,
		UseSSO:       auth.SupportsSSO() && cfg.Username == "",
	})
	if err != nil {
		return nil, fmt.Errorf("winrm.cold: kerberos provider: %w", err)
	}
	tr.Client().Transport = auth.NewNegotiateAuth(provider).Transport(tr.Client().Transport)

	wc := wsman.NewClient(endpoint, tr)
	sess := "uuid:" + strings.ToUpper(randUUID())
	wc.SetSessionID(sess)
	return &endTransport{Client: wc, tr: tr, endpoint: endpoint, sessionID: sess, idle: cfg.IdleTimeout}, nil
}

// winrsColdExecutor is the live coldExecutor: it drives a real WinRS shell.
type winrsColdExecutor struct {
	et      *endTransport
	pwsh    string
	timeout time.Duration
}

func (x *winrsColdExecutor) exec(ctx context.Context, encodedBootstrap string, stdin []byte) (adpwsh.Result, error) {
	// A failure before closeStdin is provably pre-execution: the process blocks in
	// [Console]::In.ReadToEnd until EOF (closeStdin), so re-issuing the identical
	// op cannot double-run an AD write. Those are KindTransient (retryable). From
	// closeStdin onward it is not provably pre-execution, so KindTransport (no
	// retry) -- fail closed, matching the winrm warm path's mapExecuteError.
	shell, err := winrs.NewShell(ctx, x.et)
	if err != nil {
		return adpwsh.Result{}, &adpwsh.Error{Kind: adpwsh.KindTransient, Op: "winrm.cold.create", Err: err}
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), x.timeout)
		defer cancel()
		_ = shell.Close(cctx)
	}()

	proc, err := shell.Start(ctx, x.pwsh, "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedBootstrap)
	if err != nil {
		return adpwsh.Result{}, &adpwsh.Error{Kind: adpwsh.KindTransient, Op: "winrm.cold.command", Err: err}
	}
	if err := proc.Send(ctx, stdin); err != nil {
		return adpwsh.Result{}, &adpwsh.Error{Kind: adpwsh.KindTransient, Op: "winrm.cold.send", Err: err}
	}
	if err := x.et.closeStdin(ctx, shell.EPR(), proc.CommandID()); err != nil {
		return adpwsh.Result{}, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "winrm.cold.eof", Err: err}
	}
	if err := proc.Wait(ctx); err != nil {
		return adpwsh.Result{}, &adpwsh.Error{Kind: adpwsh.KindTransport, Op: "winrm.cold.wait", Err: err}
	}
	return adpwsh.Result{
		Stdout:   string(proc.Stdout()),
		Stderr:   string(proc.Stderr()),
		ExitCode: proc.ExitCode(),
	}, nil
}

func (x *winrsColdExecutor) close() error {
	x.et.tr.CloseIdleConnections()
	return nil
}
