# headscale-api-wrapper

## Split DNS synchronization

Set `SPLIT_DNS_RESOLVERS_FILE` to enable JSON publication, for example
`/var/lib/headscale/bootstrap/split-resolvers.json`. Configure Headscale's
`dns.split_resolvers_path` to read the same shared file. This replaces the old
line-based `SPLIT_DNS_ZONES_FILE` output; `OLARES_DNS_ZONE` no longer overrides
User zones.

`TAILSCALE_IP_FILE` defaults to `/var/lib/headscale/bootstrap/tailscale.ip`.
The Tailscale sync container must publish its verified IPv4 there atomically.
The wrapper lists/watches User `bytetrade.io/zone` annotations and watches the
parent directories of the IP and output files for immediate reconciliation,
including atomic replacement and creation. A 30-second periodic check repairs
missed events and retries directory watches, including while the User API is down.
No output is published before the first successful User list.

Output matches Headscale's domain-to-resolvers format:

```json
{"alice.olares.com":["100.64.0.2"]}
```

Missing/invalid IP or failed User requests preserve the previous configuration.
A successfully observed empty zone set publishes `{}` without requiring an IP.
Missing, corrupted or stale JSON is repaired from the latest user snapshot and
valid IP. Writes use same-directory atomic replacement; mount the directory,
not a single file. Files use the existing writer's `0640` permissions, so both
services must share a readable group. The writer needs directory write access.

This does not change Headscale startup behavior: versions that require the file
at startup still need initialization or the planned missing-file startup fix.
