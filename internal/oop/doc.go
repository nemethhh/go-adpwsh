// Package oop drives PowerShell's OutOfProcess PSRP framing over an arbitrary
// byte stream (an SSH subsystem channel to `pwsh -sshs`, or a local child
// process's stdio to `pwsh -SSHServerMode`), exposing an io.ReadWriter +
// MultiplexedTransport for github.com/smnsjas/go-psrpcore/runspace.
//
// It is a port of go-psrp's HVSocket scaffolding with one required change,
// proven on the lab: the client must NOT send a DataAck for the server's Data.
// The -sshs/stdio server (OutOfProcessMediatorBase) throws
// `An unknown element "DataAck" was received` and closes the pipe if it does.
// See the transport-execution-mode design spec, section 15.
package oop
