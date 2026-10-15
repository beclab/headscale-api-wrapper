package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestLANUsersAndGroupsRoundTrip(t *testing.T) {
	p := subnetFixture(t)
	groups, _ := p.policyGroups()
	groups[lanGroupPrefix+"nas-users"] = []string{"alice@", "bob@"}
	p.fields["groups"], _ = json.Marshal(groups)
	rules := []subnetAccessRule{{Users: []string{"pip"}, Groups: []string{"nas-users"}, Target: "192.168.31.10/32", Protocol: "udp", Ports: []string{"53"}}}
	if err := p.replaceSubnetAccess(rules); err != nil {
		t.Fatal(err)
	}
	raw, err := p.marshal()
	if err != nil {
		t.Fatal(err)
	}
	p, err = parsePolicyDocument(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.subnetAccess()
	if err != nil || !reflect.DeepEqual(got, rules) {
		t.Fatalf("round trip: %#v %v", got, err)
	}
	groups, _ = p.policyGroups()
	if _, ok := groups[subnetAccessGroupPrefix+"0"]; ok {
		t.Fatal("unexpected marker group")
	}
	acl := p.ACLs[len(p.ACLs)-1]
	if !markedSubnetACL(acl) || len(acl.Src) != 2 {
		t.Fatal("missing metadata or unexpected source")
	}
	if !containsString(acl.Src, "pip@") || !containsString(acl.Src, lanGroupPrefix+"nas-users") {
		t.Fatal("missing actual selectors")
	}
	if err = p.replaceSubnetAccess(nil); err != nil {
		t.Fatal(err)
	}
	groups, _ = p.policyGroups()
	if len(groups[lanGroupPrefix+"nas-users"]) != 2 {
		t.Fatal("clearing rules deleted reusable group")
	}
}
func TestLANRejectMissingGroup(t *testing.T) {
	p := subnetFixture(t)
	err := p.replaceSubnetAccess([]subnetAccessRule{{Groups: []string{"missing"}, Target: "192.168.1.10/32", Protocol: "tcp", Ports: []string{"22"}}})
	if err == nil {
		t.Fatal("missing group accepted")
	}
}
func TestLANGroupOnlyRule(t *testing.T) {
	t.Setenv("OLARES_CLUSTER_CIDRS", "10.233.64.0/18,10.233.0.0/18")
	_, err := normalizeSubnetAccess([]subnetAccessRule{{Groups: []string{"nas-users"}, Target: "192.168.1.10", Protocol: "tcp", Ports: []string{"22"}}}, true)
	if err != nil {
		t.Fatal(err)
	}
}
func TestOlaresUserValidation(t *testing.T) {
	old := lookupOlaresUser
	t.Cleanup(func() { lookupOlaresUser = old })
	lookupOlaresUser = func(_ context.Context, u string) (bool, error) {
		if u == "unavailable" {
			return false, errors.New("unavailable")
		}
		return u == "alice", nil
	}
	if err := validateOlaresUsers(context.Background(), []string{"alice"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"outsider", "unavailable"} {
		if validateOlaresUsers(context.Background(), []string{name}) == nil {
			t.Fatal("accepted", name)
		}
	}
}

func TestOlaresUserAvailableForAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{"created without VPN", `{"status":{"state":"Created"}}`, true},
		{"creating", `{"status":{"state":"Creating"}}`, false},
		{"failed", `{"status":{"state":"Failed"}}`, false},
		{"missing status", `{}`, false},
		{"deleting", `{"metadata":{"deletionTimestamp":"2026-10-12T00:00:00Z"},"status":{"state":"Created"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var user olaresUser
			if err := json.Unmarshal([]byte(tc.raw), &user); err != nil {
				t.Fatal(err)
			}
			if got := user.availableForAuthorization(); got != tc.want {
				t.Fatalf("available = %v, want %v", got, tc.want)
			}
		})
	}
}
func TestGroupReferenceDetection(t *testing.T) {
	key := lanGroupPrefix + "nas"
	for _, v := range []any{map[string]any{"src": []any{key}}, map[string]any{"dst": []any{key + ":53"}}, map[string]any{"ssh": []any{map[string]any{"src": []any{key}}}}} {
		if !referencesGroup(v, key) {
			t.Fatal("missed reference")
		}
	}
	if referencesGroup([]any{key + "-other"}, key) {
		t.Fatal("prefix collision")
	}
}
