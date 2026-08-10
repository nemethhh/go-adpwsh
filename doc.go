// Package adpwsh drives Active Directory through the ActiveDirectory PowerShell
// module running on a Windows jump box.
//
// It knows nothing about Terraform. Every correctness rule it enforces —
// read-back after write, delete verification, pinned domain controller,
// serialized writes, fail-closed error classification, and the invariant that
// no value ever becomes PowerShell script text — is a guarantee made at the
// module boundary, so no consumer can opt out of it.
package adpwsh
