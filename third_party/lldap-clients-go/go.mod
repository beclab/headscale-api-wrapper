// Vendored copy of github.com/beclab/lldap/clients/go (the LLDAP Go
// SDK) pinned into this repo via a local `replace` in ../../go.mod.
//
// Why vendored: the SDK's read-only-snapshot client lives on the
// upstream `go-sync-sdk-dev` branch and is not yet published to a
// proxy-resolvable tag / default branch, so `go get` cannot fetch it.
// The sources under client/ are a verbatim copy; once the SDK ships in
// a released tag, drop this directory and the replace directive and
// depend on the module directly (the import path is already identical).
module github.com/beclab/lldap/clients/go

go 1.21

require github.com/nats-io/nats.go v1.37.0

require (
	github.com/klauspost/compress v1.17.2 // indirect
	github.com/nats-io/nkeys v0.4.7 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	golang.org/x/crypto v0.18.0 // indirect
	golang.org/x/sys v0.16.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)
