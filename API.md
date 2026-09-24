# Headscale API Wrapper Specification

This document describes the APIs exposed by `headscale-api-wrapper` to other Olares components. Here, "external" means callers outside the wrapper process. These APIs must remain internal to the cluster through Kubernetes Services and NetworkPolicies and must not be exposed directly to the public internet.

## 1. API categories

| Category | Caller | Port | Path prefix | Credential |
| --- | --- | --- | --- | --- |
| Auth key | Vault/LarePass call chain | `9000` | `/headscale` | Olares AccessToken |
| User device management | Settings and user-service | `8000` | `/headscale` | Olares AccessToken |
| Platform policy management | app-service | `8000` | `/internal/policy` | Kubernetes ServiceAccount token |

Recommended in-cluster addresses:

- Auth key: `http://headscale-authkey-svc.os-network:9000`
- User device and platform policy APIs: `http://headscale-server-svc.os-network:8000`

## 2. Common response format

All wrapper APIs use the following response envelope:

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
- `403`: the node does not belong to the current user, or the ServiceAccount is not authorized.
- `409`: the current policy structure cannot be modified safely.
- `500`: the wrapper failed to read or parse state.
- `502`: a Headscale API call failed.

## 3. Olares user authentication

Auth key and user device management requests must include:

```http
X-Authorization: Bearer <olares-access-token>
```

The wrapper sends the AccessToken to the LLDAP token verification endpoint and uses the returned `username` as the Headscale username.

`X-BFL-USER` is used only for diagnostics. It does not select the Headscale user and cannot override the username in the AccessToken.

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

## 5. User device management APIs

These APIs run on port `8000` and may operate only on nodes owned by the Headscale user identified by the AccessToken.

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

### 5.4 Approve routes for a node owned by the current user

```http
POST /headscale/node/approve_routes
Content-Type: application/json
```

Request body:

```json
{
  "id": "12",
  "routes": ["192.168.1.0/24"]
}
```

- `id` is required.
- `routes` is the complete list of approved routes.
- `routes: []` clears all approved routes for the node.
- The wrapper verifies ownership before applying the change.

The user-facing APIs do not support transferring nodes between users or assigning arbitrary tags. This prevents users from bypassing shared-Headscale ACL isolation by changing node ownership or tags.

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

New callers must not depend on these legacy APIs.
