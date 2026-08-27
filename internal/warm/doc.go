// Package warm is the transport-agnostic warm-runspace engine: a pool of
// persistent PSRP executors with an idle reaper and a one-shot,
// pre-execution-only retry. It is keyed on the Executor interface so any
// transport (WinRM via go-psrp, or SSH/local via go-psrpcore out-of-proc) can
// reuse the same hardened pool/retry/reap logic. Detection of dead shells and
// transient failures is injected via Classifier; payload embedding via Wrapper.
package warm
