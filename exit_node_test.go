package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

const exitNodeTestPolicy = `{
  "groups": {
    "group:admins": ["owner@"],
    "group:exit-users": ["bob@", "alice@"]
  },
  "acls": [
    {"action":"accept","src":["group:exit-users"],"dst":["autogroup:internet:*"]},
    {"action":"accept","src":["autogroup:member"],"proto":"tcp","dst":["tag:olares:80"]}
  ],
  "tagOwners": {"tag:olares":["group:admins"]}
}`

func TestExitUsersGrantAndRevokePreservePolicy(t *testing.T) {
	document, err := parsePolicyDocument([]byte(exitNodeTestPolicy))
	if err != nil {
		t.Fatal(err)
	}

	users, changed, err := document.setExitUser("carol", true)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || !reflect.DeepEqual(users, []string{"alice", "bob", "carol"}) {
		t.Fatalf("grant returned users=%v changed=%v", users, changed)
	}

	users, changed, err = document.setExitUser("bob", false)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || !reflect.DeepEqual(users, []string{"alice", "carol"}) {
		t.Fatalf("revoke returned users=%v changed=%v", users, changed)
	}

	encoded, err := document.marshal()
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"tagOwners", "acls"} {
		if _, ok := fields[field]; !ok {
			t.Fatalf("field %q was removed", field)
		}
	}
	groups, err := document.policyGroups()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(groups["group:admins"], []string{"owner@"}) {
		t.Fatalf("unrelated group changed: %v", groups["group:admins"])
	}
	if !reflect.DeepEqual(groups[exitUsersGroup], []string{"alice@", "carol@"}) {
		t.Fatalf("exit users = %v", groups[exitUsersGroup])
	}
}

func TestExitUsersUpdateIsIdempotent(t *testing.T) {
	document, err := parsePolicyDocument([]byte(exitNodeTestPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if _, changed, err := document.setExitUser("alice", true); err != nil || !changed {
		t.Fatalf("first canonicalizing update changed=%v err=%v", changed, err)
	}
	if _, changed, err := document.setExitUser("alice", true); err != nil || changed {
		t.Fatalf("idempotent grant changed=%v err=%v", changed, err)
	}
	if _, changed, err := document.setExitUser("nobody", false); err != nil || changed {
		t.Fatalf("idempotent revoke changed=%v err=%v", changed, err)
	}
}

func TestExitUsersRejectUnsafePolicyShapes(t *testing.T) {
	tests := []string{
		`{"groups":{"group:exit-users":[]},"acls":[]}`,
		`{"groups":{},"acls":[{"action":"accept","src":["group:exit-users"],"dst":["autogroup:internet:*"]}]}`,
		`{"groups":{"group:exit-users":[]},"acls":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:internet:*"]}]}`,
		`{"groups":{"group:exit-users":[]},"acls":[{"action":"accept","src":["group:exit-users"],"dst":["autogroup:internet:*"]},{"action":"accept","src":["alice@"],"dst":["autogroup:internet:*"]}]}`,
	}
	for _, policy := range tests {
		document, err := parsePolicyDocument([]byte(policy))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := document.exitUsers(); err == nil {
			t.Fatalf("expected policy to be rejected: %s", policy)
		}
	}
}

func TestPolicyGroupsRejectsNull(t *testing.T) {
	document, err := parsePolicyDocument([]byte(`{"groups":null,"acls":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := document.policyGroups(); err == nil {
		t.Fatal("accepted null groups")
	}
}

func TestExitUsersRejectNonUserMembers(t *testing.T) {
	document, err := parsePolicyDocument([]byte(`{
      "groups":{"group:exit-users":["group:admins"]},
      "acls":[{"action":"accept","src":["group:exit-users"],"dst":["autogroup:internet:*"]}]
    }`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := document.exitUsers(); err == nil {
		t.Fatal("expected a nested group member to be rejected")
	}
}
