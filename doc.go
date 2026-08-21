// Package adpwsh drives Active Directory through the ActiveDirectory PowerShell
// module running on a Windows jump box.
//
// It knows nothing about Terraform. Every correctness rule it enforces —
// read-back after write, delete verification, pinned domain controller,
// serialized writes, fail-closed error classification, and the invariant that
// no value ever becomes PowerShell script text — is a guarantee made at the
// module boundary, so no consumer can opt out of it.
//
// The read surface includes bounded, class-scoped search: OU.Search,
// Group.Search and User.Search each take a Query (an LDAP filter built through
// the exported EscapeFilter/Equal/And helpers, a search base, a scope and a
// size limit) and return typed results. It is not an arbitrary directory API —
// there is no generic object search, and object mutation remains
// get-by-identity only.
package adpwsh
