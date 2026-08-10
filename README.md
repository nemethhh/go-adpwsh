# go-adpwsh

A Go library that drives Active Directory through the `ActiveDirectory`
PowerShell module — either on the Windows host the caller runs on, or on a
Windows jump box reached over SSH.

It is a separate repository from the Terraform provider that consumes it for one
reason: managing AD from Go is useful without Terraform, and a library that
cannot return a `diag.Diagnostics` is a library whose correctness rules cannot
quietly become someone else's problem. A test in this module fails the build if
any Terraform package enters the import graph, including through test imports.

## Topology

Two transports, one contract. Both invoke the same fixed command with the same
JSON payload on stdin, and both hand stdout, stderr and the exit code back
verbatim.

**On-host — `transport/local`.** The caller already runs on a domain-joined
Windows host, so the process holds a Kerberos TGT for whoever launched it and
there is no hop to authenticate.

```
caller (Windows host)
   └─ pwsh -EncodedCommand …   (payload on stdin)
        └─ Import-Module ActiveDirectory
             └─ ADWS :9389 ──▶ pinned DC
```

**Remote — `transport/ssh`.** The caller runs anywhere and reaches a Windows
jump box over SSH.

```
caller (anywhere)
   └─ ssh ──▶ jump box
                └─ pwsh -EncodedCommand …   (payload on stdin)
                     └─ Import-Module ActiveDirectory
                          └─ ADWS :9389 ──▶ pinned DC
```

On Windows, an SSH session authenticated by public key receives a network logon
token carrying no delegatable credentials, so onward authentication to ADWS
fails — the classic double hop. Over SSH that is worked around with an explicit
`Config.Credential`, which becomes `-Credential` on every cmdlet. On-host
execution removes the problem instead of working around it, and
`Config.Credential` remains available there for the case where the operations
must authenticate as some account other than the one that launched the process.

**Cost per operation, stated so it is not a surprise.** Every operation pays a
fresh `Import-Module ActiveDirectory`, roughly 1–3 seconds on Windows. This is
inherent to the one-shot-per-operation execution contract, and it is the same
for both transports. `Concurrency` bounds how many run at once — 4 by default,
because each is a real process with real memory cost.

## Example

```go
dir := fake.NewDirectory()
client, err := adpwsh.New(context.Background(), adpwsh.Config{Transport: dir.Transport()})
if err != nil {
    panic(err)
}
defer client.Close()

ou, err := client.OU.Create(context.Background(), adpwsh.OUSpec{
    Name:      "Staff",
    Container: client.DefaultNamingContext(),
})
if err != nil && !errors.Is(err, adpwsh.ErrReplication) {
    panic(err)
}
fmt.Println(ou.DN, ou.Protected)
// Output: OU=Staff,DC=corp,DC=local true
```

That example runs in this module's test suite against `transport/fake`, so the
whole library — and any consumer built on it — is testable with no Windows VM.

## What the module guarantees

These are enforced at the module boundary. A consumer cannot opt out of them.

- **Read-back after write.** `Create` and `Update` return the result of the same
  read `Get` performs, so an inconsistent result after apply is impossible by
  construction.
- **Delete verification.** `Delete` returns `nil` only after a re-read confirms
  the object is gone. A `Remove-AD*` that returns cleanly while the deletion was
  refused is an error, not a success.
- **A pinned domain controller.** `New` resolves one DC and every cmdlet for the
  client's lifetime carries `-Server <that DC>`. Without it a create lands on
  DC-A and the read-back hits DC-B and reports "not found".
- **Serialized writes per target.** A read-then-write delta has no
  compare-and-swap, so writes naming the same object are serialized. Writes
  naming different objects still run concurrently.
- **Fail-closed classification.** An unrecognized `(exception type, error code)`
  pair is `KindUnknown` and is never retried. Only `KindTransient` is retried:
  guessing that an unknown error is transient turns a permission problem into a
  hang.
- **No value ever becomes script text.** Scripts are constants selected by a
  closed set of op names and embedded at build time. Every value travels as JSON
  on stdin and is splatted into the cmdlet. There is no code path that formats a
  caller's value into PowerShell.
- **Secrets cannot be printed or marshalled.** `Secret` renders as `REDACTED`
  under every `fmt` verb and its `MarshalJSON` always fails, so a struct walk
  into a log line or a state file is a loud error rather than a leak. The
  payload is masked before a log line is constructed.
- **A replication timeout returns the model *and* the error.** The object
  exists; only the wait did not finish. Erroring without the model orphans the
  object, so `Create` and `Update` may return a non-nil model beside a non-nil
  `ErrReplication`. Persist the model and surface the error.

## Extension seams

- **`Transport`** is the only I/O seam. Three ship: `transport/local` (`pwsh` as
  a child process of the caller), `transport/ssh` (a Windows jump box), and
  `transport/fake` (a programmable double plus `fake.Directory`, a small
  in-memory AD). Envelope parsing, error classification, retry and the
  replication wait all live *above* it, which is why `transport/local` inherited
  every property above without restating one of them, and why a future WinRM
  transport will too. No transport can reinterpret an AD refusal as a transport
  failure.
- **`Catalog`** will be the schema seam. It is not in this release; adding
  `Config.Catalog` later is additive.

## Windows requirements

Both transports need the same things of the Windows machine that runs `pwsh`:

- A Windows **member server** — not a domain controller.
- `RSAT-AD-PowerShell` installed.
- PowerShell 7 (`pwsh`) on `PATH`. The scripts use `ConvertFrom-Json
  -AsHashtable` and the `?.` null-conditional operator, neither of which exists
  in Windows PowerShell 5.1.
- TCP 9389 open to the domain controller — the AD Web Services port the cmdlets
  use.

`transport/local` needs nothing further: the caller is already on that machine.

`transport/ssh` additionally needs OpenSSH Server running on it, and TCP 22 open
from wherever the caller runs. Host key verification is on by default;
`insecure_ignore_host_key` is an explicit opt-out, and setting two host-key
sources is a validation error rather than a silent precedence surprise.

## Stability

`v0.x`. The module takes `v1` only after the lab answers the ranged-read
question for group membership and the acceptance suite passes against a real
domain. Until then, minor versions may change the surface.

Membership (`GetMembers`/`AddMembers`/`RemoveMembers`/`SetMembers`), the
`Catalog` interface, the generic `Object` sub-client, and tier-2
`Attributes map[string]any` are deliberately absent from this release.

## Licence

MIT.
