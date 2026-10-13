# Headscale API Wrapper Specification

This document describes the APIs exposed by `headscale-api-wrapper` to other Olares components. Here, "external" means callers outside the wrapper process. These APIs must remain internal to the cluster through Kubernetes Services and NetworkPolicies and must not be exposed directly to the public internet.

This specification describes the current working-tree implementation, including
the Olares user and LAN group endpoints. It does not imply that an already
deployed image supports them. All JSON request bodies use `Content-Type:
application/json`. Response examples below use the common envelope unless
explicitly described as the contents of `data`.

## 1. API categories

| Category | Caller | Port | Path prefix | Credential |
| --- | --- | --- | --- | --- |
| Auth key | Vault/LarePass call chain | `9000` | `/headscale` | Olares AccessToken |
| User device management | Settings and user-service | `8000` | `/headscale` | Olares AccessToken |
| Olares user listing | Settings owner | `8000` | `/headscale/olares-users` | Owner AccessToken |
| Reusable LAN groups | Settings owner | `8000` | `/headscale/policy/lan-groups` | Owner AccessToken |
| Exit-node access management | Settings owner | `8000` | `/headscale/policy/exit-users` | Olares AccessToken |
| Subnet-router management | Settings owner | `8000` | `/headscale/policy/subnet-router/routes`, `/headscale/policy/subnet-router/access` | Olares AccessToken |
| Platform policy management | app-service | `8000` | `/internal/policy` | Kubernetes ServiceAccount token |
| Self-device access | Authenticated Olares user | `8000` | `/headscale/policy/self-mesh` | Olares AccessToken |
| Shared Tailscale enrollment | Internal Tailscale | `8000` | `/bootstrap/tailscale-authkey` | Dedicated Kubernetes ServiceAccount token |

Recommended in-cluster addresses:

- Auth key: `http://headscale-authkey-svc.os-network:9000`
- User device and platform policy APIs: `http://headscale-server-svc.os-network:8000`

## 2. Common response format

Headscale HTTP calls have a 10-second timeout. After authentication, policy
handlers have a shared 30-second operation budget covering lock acquisition
and downstream calls, including batch user lookups. Client cancellation also
cancels lock waits and those calls. Lock-wait timeout returns HTTP 504;
downstream failures retain the endpoint's error response. A write timeout does
not prove that Headscale rejected the write: read the current state before
retrying. This is an HTTP-operation budget, not a hard timeout for local disk I/O.

All wrapper APIs use the following response envelope, except successful bootstrap
key issuance, which returns plain text (section 4.2):

```json
{
  "code": 0,
  "message": "",
  "data": {}
}
```

- `code = 0`: success.
- `code = 1001`: request, authentication, or Headscale call failure.
- Callers must check both the HTTP status and `code`.

Common HTTP status codes:

- `200`: success.
- `400`: invalid request body or port format.
- `401`: missing or invalid AccessToken or ServiceAccount token.
- `403`: the node does not belong to the current user, the user is not the Olares owner, or the ServiceAccount is not authorized.
- `409`: the current policy structure cannot be modified safely.
- `500`: the wrapper failed to read or parse state.
- `502`: a Headscale API call failed.

Status codes are not uniform across all handlers: device/preauthkey upstream
failures can return `500`; subnet route/file failures return `502`; target
Olares user lookup failures (including Kubernetes errors) currently return
`400` during authorization writes. Owner lookup failures and user-list lookup
failures return `502`. A referenced LAN group cannot be deleted (`409`).
Unregistered paths use Gin's default `404`, which is not the JSON envelope.

## 3. Olares user authentication

All `/headscale/*` requests, including owner management requests, must include:

```http
X-Authorization: Bearer <olares-access-token>
```

The wrapper sends the AccessToken to the LLDAP token verification endpoint and uses the returned `username` as the Headscale username.

`X-BFL-USER` is used only for diagnostics. It does not select the Headscale user and cannot override the username in the AccessToken.

Owner endpoints additionally require the authenticated Olares User annotation
`bytetrade.io/owner-role: owner`; `admin` is not sufficient. Credentials checked
by an intermediate system-server/provider are separate from this wrapper's
`X-Authorization` header. Do not substitute a ServiceAccount token for the
Olares AccessToken on these endpoints.

## 4. Auth key API

### 4.1 Get a pre-auth key

```http
GET /headscale/preauthkey
```

Port: `9000`

Behavior:

1. Verify the Olares AccessToken.
2. Find the Headscale user with the same name, creating it if it does not exist.
3. Create a reusable, non-ephemeral pre-auth key that is valid for 24 hours.

Request body: none.

On success, `data` retains the response structure from the Headscale create pre-auth key API. For example:

```json
{
  "code": 0,
  "message": "",
  "data": {
    "preAuthKey": {
      "id": "21",
      "key": "hskey-auth-...",
      "reusable": true,
      "ephemeral": false,
      "expiration": "2026-09-25T10:00:00Z",
      "user": {
        "name": "alice"
      }
    }
  }
}
```

### 4.2 Issue an internal Tailscale bootstrap key

```http
POST /bootstrap/tailscale-authkey
Authorization: Bearer <projected-service-account-token>
```

Port: `8000`. In-cluster URL:
`http://headscale-server-svc.os-network:8000/bootstrap/tailscale-authkey`.
No request body is required; callers cannot override issuance settings.

TokenReview must authenticate exactly
`system:serviceaccount:os-network:tailscale` with audience `headscale-bootstrap`.
This endpoint does not use an Olares AccessToken or the app-service policy audience.

Each successful request creates a non-reusable, non-ephemeral key, valid for
5 minutes, with `aclTags: ["tag:olares"]` and no ordinary user association.
HTTP 200 returns the key directly as `text/plain; charset=utf-8`, without a JSON
envelope. Responses include `Cache-Control: no-store` and `Pragma: no-cache`.
Missing/invalid credentials return 401, a different authenticated ServiceAccount
returns 403, and upstream failures or invalid key responses return 502, using
the JSON envelope. Headscale response bodies are not included in these errors.

Requests are not deduplicated: retries may create additional short-lived keys.
No legacy-key expiration or deletion job runs. This endpoint does not change
the reusable 24-hour user preauthkey API in section 4.1. Callers must not log keys.

## 5. User and owner management APIs

These APIs run on port `8000`. Device operations in sections 5.1–5.3 only
operate on nodes owned by the authenticated Headscale user. Sections 5.4–5.6
are owner-only management APIs and may authorize other Olares users.

### 5.1 List nodes owned by the current user

```http
POST /headscale/node
Content-Type: application/json
```

Request body:

```json
{}
```

The wrapper fetches all nodes from Headscale and returns only nodes whose `node.user.name` matches the authenticated username.

Success `data` contains `{"nodes":[...]}` with Headscale node objects preserved.
An empty `id` also selects listing; a non-empty `id` selects deletion.
Delete and rename return the upstream response in `data`, not a `changed` flag.

### 5.2 Delete a node owned by the current user

```http
POST /headscale/node
Content-Type: application/json
```

Request body:

```json
{
  "id": "12"
}
```

When `id` is present, this endpoint deletes the node instead of listing nodes. The wrapper verifies ownership first and returns `403` for a node owned by another user.

### 5.3 Rename a node owned by the current user

```http
POST /headscale/node/rename
Content-Type: application/json
```

Request body:

```json
{
  "id": "12",
  "name": "macbook-pro"
}
```

Both `id` and `name` are required. The wrapper verifies ownership before applying the change.

The user-facing APIs do not support transferring nodes between users or assigning arbitrary tags. This prevents users from bypassing shared-Headscale ACL isolation by changing node ownership or tags.

### 5.4 Manage exit-node users

Only the authenticated Olares owner may manage the users allowed to use the
Olares exit node. The wrapper verifies the AccessToken username and requires
the matching Olares User to have `bytetrade.io/owner-role: owner`.

```http
GET /headscale/policy/exit-users
PUT /headscale/policy/exit-users/:username
DELETE /headscale/policy/exit-users/:username
```

- `GET` lists the authorized Olares usernames.
- `PUT` grants exit-node access and always ensures that the matching Headscale
  user exists, including when the policy membership is already unchanged.
- `DELETE` revokes exit-node access.
- `:username` is the Olares username without the trailing `@` used by
  Headscale policy aliases.
- Repeating the same grant or revoke is a successful no-op. `changed` is
  omitted when false because this response field uses `omitempty`.

PUT and DELETE take no request body. Success `data` contains `users`,
`revision`, optional `updatedAt`, and `changed: true` only when membership
changed. `revision` is a digest, not an optimistic-concurrency token.

The wrapper changes only `groups["group:exit-users"]`. It refuses the update
if the managed group or its single canonical `autogroup:internet:*` ACL rule is
missing or ambiguous. Headscale validates, stores, and reloads the updated
database policy immediately; no pod restart is required.

### 5.5 Subnet routes and access (owner only)

These are independent GET/PUT endpoints. Both use the authenticated Olares
owner's AccessToken; PUT replaces only the addressed resource. Unknown request
fields, missing arrays and null arrays are rejected.

```http
GET /headscale/policy/subnet-router/routes
PUT /headscale/policy/subnet-router/routes
```

```json
{"routes":["192.168.1.0/24"]}
```

Routes must be non-overlapping RFC1918 IPv4 prefixes. Cluster ranges from
`OLARES_CLUSTER_CIDRS` are forbidden. Non-empty updates fail closed if that
configuration is missing or invalid; `{"routes":[]}` still clears routes.
Exact `tag:olares` auto-approval entries are managed by this API, except the
`10.255.255.254/32` compatibility marker. Other approvers and exit-node
approval remain unchanged. Conflicting unmanaged entries are rejected.

The policy is saved before the shared route file is atomically updated.
If the file update fails, retry the same PUT to repair it. GET and PUT return
`routes` and `inSync`; PUT also returns `changed`. **inSync only compares
policy and route file, not live advertisement, approval or client connectivity.**
Saving or clearing routes never changes access rules.

Example PUT success:

```json
{"code":0,"message":"","data":{"routes":["192.168.1.0/24"],"inSync":true,"changed":true}}
```

GET returns the same `data` without `changed`. PUT replaces all routes managed
by this endpoint, not just routes for one user. Publication by Tailscale is
asynchronous; this response does not wait for advertisement or client updates.

```http
GET /headscale/policy/subnet-router/access
PUT /headscale/policy/subnet-router/access
```

```json
{
  "access": [
    {
      "users": ["alice"],
      "target": "192.168.1.10/32",
      "protocol": "tcp",
      "ports": ["445", "5000-5010"]
    },
    {
      "users": ["bob"],
      "target": "192.168.1.20",
      "protocol": "tcp",
      "ports": ["22"]
    }
  ]
}
```

Each rule accepts `users` and optional `groups` (LAN group names without a
prefix). At least one user or group is required. Users and groups are ORed,
not intersected. For example:

```json
{"access":[{"users":["alice"],"groups":["nas-users"],"target":"192.168.31.10/32","protocol":"tcp","ports":["445"]}]}
```

Targets accept private IPv4 addresses or CIDRs,
not hosts aliases; cluster overlap is rejected independently of configured
routes. Protocol is TCP or UDP. Ports support 1–65535, inclusive ranges, or
a sole `"*"`. `users` may be empty or omitted when `groups` is non-empty;
both sources empty is invalid. Ports must be non-empty. Limits: 256 rules and 256 port
entries per rule; request bodies are limited to 1 MiB.

Access may be saved before routes exist. GET returns `access`; PUT also returns
`changed`. Saving access never reads/writes the route file or changes approvers.
`{"access":[]}` revokes managed subnet access only.

Referenced groups must already exist. Group names are supplied as `nas-users`,
not `group:nas-users` or `group:lan-nas-users`; the latter is the generated
policy key. Group-only rules are supported:

```json
{"access":[{"users":[],"groups":["nas-users"],"target":"192.168.31.10/32","protocol":"udp","ports":["53"]}]}
```

PUT returns `data: {"access":[...],"changed":true}`; GET omits `changed`.
Rules, users, groups and ports may be normalized/reordered. Bare IPv4 targets
become `/32`; empty `groups` is omitted from responses. There is no per-rule
DELETE or stable rule ID: read the list, edit it, then PUT the complete list.
Saving does not alter reusable group membership or exit-node membership.

New managed ACLs carry `"#managed-by": "olares-subnet-access"`; no per-rule
marker group is created. Sources are direct user aliases and reusable
`group:lan-<name>` references. Legacy `group:subnet-access-*` rules remain
readable and are rewritten on access PUT; obsolete marker groups are removed
only when no policy section references them. The ownership field is not a
stable rule ID. The legacy
`group:subnet-users` broad ACL is readable and is replaced on the next access
PUT. Legacy GET may return an empty protocol (old all-protocol semantics);
choose TCP/UDP explicitly when replacing it. Other policy rules are preserved
and remain additive. Olares host LAN addresses are not automatically excluded:
authorizing them can also permit host services on the specified ports.

The previous combined `/policy/subnet-router` endpoint is removed. Callers and
the Olares provider ClusterRole must permit both new paths for GET/PUT.
No revision-based optimistic concurrency is implemented; saves of the same
resource are last-write-wins. Wrapper writes share the existing policy mutex;
multiple wrapper replicas or external policy writers require coordination.

### 5.6 Olares users and reusable LAN groups (owner only)

```http
GET /headscale/olares-users
GET /headscale/policy/lan-groups
PUT /headscale/policy/lan-groups/:name
DELETE /headscale/policy/lan-groups/:name
```

All endpoints require an authenticated owner. User listing returns
`data.users: [{"username":"alice"}]` from Olares User CRs, including users
without Headscale accounts; it never returns User CR annotations or tokens.
Results are sorted by username; there are no client pagination parameters.
The wrapper collects Kubernetes pages internally. Nickname, email, role and
VPN registration status are not returned by this endpoint.
The wrapper ServiceAccount needs `get` and `list` on
`users.iam.kubesphere.io`. The deployment/provider permissions must allow
these new paths and methods; this repository change does not update those
deployment resources.

Group PUT uses `{"users":["alice","bob"]}` and creates or replaces that group's
members. An empty array revokes membership but retains the group. Names are
1–40 lowercase letters, digits or hyphens, starting with a letter. The reserved
policy namespace is `group:lan-<name>`. GET returns
`data.groups: [{"name":"nas-users","users":["alice","bob"]}]`.
Groups can be referenced by multiple access rules. Group deletion returns 409
while the group is referenced anywhere in the policy. Group changes, access
changes and other policy writers share the process-wide policy mutex.

Example creation/update:

```http
PUT /headscale/policy/lan-groups/nas-users
Content-Type: application/json
```

```json
{"users":["alice","bob"]}
```

Success:

```json
{"code":0,"message":"","data":{"name":"nas-users","users":["alice","bob"],"changed":true}}
```

Members are trimmed, deduplicated and sorted. Group PUT rejects unknown fields,
missing/null `users`, and bodies exceeding 1 MiB. Members are Olares usernames,
not Headscale IDs or policy aliases; nested groups are not supported. This API
does not rename groups. GET lists all `group:lan-*` groups, not exit-node or
internal marker groups.

DELETE takes no body and returns `data: {"changed":true}`. An absent,
unreferenced group returns `changed: false`. Deletion does not cascade to
rules; remove references first. Updating members affects every referencing
rule without requiring a separate access-rule save.

Exit grants, LAN group membership writes and subnet access saves validate
target usernames against Olares before granting access. Missing Olares users
and lookup failures reject the update. Existing Olares users may have their
Headscale identities created on demand. Revoking exit access and clearing
rules remain possible for deleted users. No automatic user-deletion cleanup
or stable-user-ID migration is introduced here. Application port policy remains
an internal, globally replacing API.

### 5.7 Same-user device access

```http
GET /headscale/policy/self-mesh
PUT /headscale/policy/self-mesh
```

Any authenticated Olares user may read or change their own setting; owner
privileges are not required. The username comes only from the AccessToken.

PUT body:

```json
{"enabled":true}
```

The body must contain only a boolean `enabled`; missing/null values, unknown
fields, trailing JSON and bodies larger than 4096 bytes are rejected with 400.
Use `false` to disable access. GET has no request body.

Success example:

```json
{"code":0,"message":"","data":{"enabled":true,"changed":true}}
```

GET and unchanged PUT return `changed: false`. The wrapper changes only the
current user's membership in `group:self-mesh`; enabling creates the matching
Headscale user if needed. Other users' memberships remain unchanged. The
preinstalled canonical ACL must accept `group:self-mesh` to
`autogroup:self:*` with no protocol restriction, and the group must exist.
Missing, customized or duplicate managed rules produce 409 rather than being
silently replaced. Policy updates take effect without a Headscale restart.
This grants network access between the user's devices, not access to the
tagged shared Olares node, and does not implement client file-transfer features.

## 6. Platform policy management APIs

These APIs are intended only for app-service and run on port `8000`.

Requests must include the app-service Kubernetes ServiceAccount token:

```http
Authorization: Bearer <service-account-token>
```

The wrapper verifies the token through Kubernetes TokenReview and requires this identity by default:

```text
system:serviceaccount:os-framework:os-internal
```

The caller must use a projected ServiceAccount token with the dedicated `headscale-policy` audience. The wrapper sends the same audience in the TokenReview request, so the normal Kubernetes API token is rejected.

The expected namespace and ServiceAccount can be overridden with:

- `POLICY_CLIENT_NAMESPACE`
- `POLICY_CLIENT_SERVICE_ACCOUNT`
- `POLICY_TOKEN_AUDIENCE`

### 6.1 Read the application port policy

```http
GET /internal/policy/application-ports
```

Example response:

```json
{
  "code": 0,
  "message": "",
  "data": {
    "defaultPorts": {
      "tcp": ["53", "80", "443", "18088"],
      "udp": ["53"]
    },
    "applicationPorts": [
      {
        "user": "alice",
        "tcp": ["445", "5000"],
        "udp": ["5353"]
      }
    ],
    "effectivePorts": [
      {
        "user": "alice",
        "tcp": ["53", "80", "443", "5000", "18088"],
        "udp": ["53", "5353"]
      }
    ],
    "revision": "sha256:...",
    "updatedAt": "2026-09-24T10:00:00Z",
    "inSync": true
  }
}
```

Field definitions:

- `defaultPorts`: platform ports available to every Headscale member.
- `applicationPorts`: dynamic ports declared by Applications and aggregated by Olares user.
- `effectivePorts`: the union of default and dynamic ports for users with dynamic entries. Users not present in this array still receive `defaultPorts`.
- `revision`: a digest of normalized `applicationPorts`.
- `updatedAt`: the last Headscale policy update time.
- `inSync`: whether the default and dynamic rules in the database match the wrapper's canonical structure.

### 6.2 Replace the application port policy

```http
PUT /internal/policy/application-ports
Content-Type: application/json
```

Request body:

```json
{
  "applicationPorts": [
    {
      "user": "alice",
      "tcp": ["445", "5000", "6000-6010"],
      "udp": ["5353"]
    },
    {
      "user": "bob",
      "tcp": ["8080"],
      "udp": []
    }
  ]
}
```

Update semantics:

- This is a full replacement, not an incremental patch.
- Replacement is global across users; there is currently no per-user PUT.
- Dynamic application ports for users omitted from the request are removed.
- `applicationPorts: []` removes all dynamic application ports while preserving platform default ports.
- Duplicate entries for the same user are merged and deduplicated.
- Platform default ports are removed from dynamic entries even if the request includes them.
- The wrapper ensures that a matching Headscale user exists before writing the policy.
- If the content is unchanged and the existing rules are canonical, the wrapper does not write to Headscale again.

Supported port formats:

- Single port: `"443"`
- Inclusive range: `"6000-6010"`
- Every numeric port must be within `1..65535`.
- Wildcard `"*"` is rejected for application ports (unlike subnet access).

The success response has the same structure as GET and also includes:

```json
{
  "changed": true
}
```

`changed` indicates whether this request actually updated the Headscale policy.

## 7. Platform default ports

The wrapper currently manages these default ports:

```text
TCP: 53, 80, 443, 18088
UDP: 53
```

They correspond to this Headscale policy rule:

```json
{
  "action": "accept",
  "src": ["autogroup:member"],
  "proto": "tcp",
  "dst": ["tag:olares:53,80,443,18088"]
}
```

Dynamic application rules are generated per user. For example:

```json
{
  "action": "accept",
  "src": ["alice@"],
  "proto": "tcp",
  "dst": ["tag:olares:445,5000"]
}
```

During a read-modify-write operation, the wrapper preserves unrelated ACLs, groups, tag owners, auto-approvers, and policy fields it does not recognize.

## 8. Removed and unsupported APIs

The shared Headscale architecture no longer exposes these legacy capabilities:

- `/inner/*` forwarding endpoints.
- Reading the Headscale control URL.
- Registering nodes through the management API.
- Transferring a node to another Headscale user.
- Assigning arbitrary tags to a node through a user-facing API.
- The old combined `/headscale/policy/subnet-router` endpoint and the old
  `/headscale/node/approve_routes` endpoint.
- Automatic Olares user-deletion cleanup, a cleanup API, or stable-user-ID
  mapping. Current authorization identities are usernames.
- A generic policy-editing API or DNS/group-renaming API.

New callers must not depend on these legacy APIs.
