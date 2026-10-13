# Device interconnection for the current user

`GET /headscale/policy/self-mesh` returns the authenticated user's membership
in `group:self-mesh`. `PUT` accepts exactly `{"enabled":true}` or
`{"enabled":false}`. Both endpoints use the existing `X-Authorization` session
verification. All user roles may use them; there is no target-user parameter.
`X-BFL-USER` cannot select another user's settings.

Example response:

```json
{"code":0,"message":"","data":{"enabled":true,"changed":true}}
```

`changed` is false on reads and idempotent updates. Responses do not expose other
users' membership. Changes use the Headscale policy API, without a restart.

The deployment must preinstall an empty `group:self-mesh` and the rule:

```json
{"action":"accept","src":["group:self-mesh"],"dst":["autogroup:self:*"]}
```

Missing or unexpected managed rules return HTTP 409. Invalid request bodies
return 400, invalid sessions 401, and downstream failures 502. Updates preserve
other users, ACLs and policy fields, and use the existing process-wide policy
lock (as with other policy endpoints, this is not a distributed lock).

This toggles this rule's grant only. Other independently configured ACLs can
still permit device access. Target services and their authentication/firewalls
remain necessary. Frontend integration and live device connectivity verification
are separate from this wrapper change.
