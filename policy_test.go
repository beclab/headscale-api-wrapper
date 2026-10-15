package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

const testPolicy = `{
  // Fields unrelated to service ports must survive a rewrite.
  "groups": {"group:admins": []},
  "tagOwners": {"tag:olares": ["group:admins"]},
  "acls": [
    {"action":"accept","src":["autogroup:member"],"proto":"tcp","dst":["tag:olares:80,443,53,18088"]},
    {"action":"accept","src":["autogroup:member"],"proto":"udp","dst":["tag:olares:53"]},
    {"action":"accept","src":["alice@"],"proto":"tcp","dst":["tag:olares:445"]},
    {"action":"accept","src":["group:self-mesh"],"dst":["autogroup:self:*"],"futureField":{"keep":true}}
  ],
  "autoApprovers": {"exitNode":["tag:olares"]}
}`

func TestPolicyApplicationPortsRoundTrip(t *testing.T) {
	document, err := parsePolicyDocument([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}

	application, err := document.managedApplicationPorts()
	if err != nil {
		t.Fatal(err)
	}
	wantApplication := []userProtocolPorts{{User: "alice", protocolPorts: protocolPorts{TCP: []string{"445"}, UDP: []string{}}}}
	if !reflect.DeepEqual(application, wantApplication) {
		t.Fatalf("application ports = %#v, want %#v", application, wantApplication)
	}

	desired := []userProtocolPorts{
		{User: "alice", protocolPorts: protocolPorts{TCP: []string{"445", "5000"}}},
		{User: "bob", protocolPorts: protocolPorts{UDP: []string{"5353"}}},
	}
	desired, err = normalizeUserProtocolPorts(desired)
	if err != nil {
		t.Fatal(err)
	}
	document.setManagedApplicationPorts(desired)
	encoded, err := document.marshal()
	if err != nil {
		t.Fatal(err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"groups", "tagOwners", "autoApprovers"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("field %q was removed", key)
		}
	}
	var encodedACLs []map[string]json.RawMessage
	if err := json.Unmarshal(fields["acls"], &encodedACLs); err != nil {
		t.Fatal(err)
	}
	foundUnknown := false
	for _, acl := range encodedACLs {
		if _, ok := acl["futureField"]; ok {
			foundUnknown = true
		}
	}
	if !foundUnknown {
		t.Fatal("unknown ACL field was removed")
	}

	reparsed, err := parsePolicyDocument(encoded)
	if err != nil {
		t.Fatal(err)
	}
	gotApplication, err := reparsed.managedApplicationPorts()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotApplication, desired) {
		t.Fatalf("rewritten application ports = %#v, want %#v", gotApplication, desired)
	}
}

func TestNormalizeUsers(t *testing.T) {
	got, err := normalizeUserProtocolPorts([]userProtocolPorts{
		{User: "alice", protocolPorts: protocolPorts{TCP: []string{"5000,443", "22", "6000-6010"}, UDP: []string{"53"}}},
		{User: "alice", protocolPorts: protocolPorts{TCP: []string{"05000"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []userProtocolPorts{{User: "alice", protocolPorts: protocolPorts{TCP: []string{"22", "443", "5000", "6000-6010"}, UDP: []string{"53"}}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("application ports = %#v, want %#v", got, want)
	}
}

func TestApplicationPortsJSONContract(t *testing.T) {
	applicationPorts := []userProtocolPorts{{
		User:          "alice",
		protocolPorts: protocolPorts{TCP: []string{"445"}, UDP: []string{"5353"}},
	}}
	encoded, err := json.Marshal(applicationPortsRequest{ApplicationPorts: &applicationPorts})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"applicationPorts":[{"user":"alice","tcp":["445"],"udp":["5353"]}]}`
	if string(encoded) != want {
		t.Fatalf("JSON = %s, want %s", encoded, want)
	}
}

func TestApplicationPortsRequestRequiresExplicitArray(t *testing.T) {
	for _, body := range []string{`{}`, `{"applicationPorts":null}`} {
		var request applicationPortsRequest
		if err := json.Unmarshal([]byte(body), &request); err != nil {
			t.Fatal(err)
		}
		if request.ApplicationPorts != nil {
			t.Fatalf("body %s produced a non-nil applicationPorts", body)
		}
	}

	var request applicationPortsRequest
	if err := json.Unmarshal([]byte(`{"applicationPorts":[]}`), &request); err != nil {
		t.Fatal(err)
	}
	if request.ApplicationPorts == nil {
		t.Fatal("an explicit empty applicationPorts array must be preserved")
	}
}

func TestRejectWildcardApplicationPorts(t *testing.T) {
	entries, err := normalizeUserProtocolPorts([]userProtocolPorts{{
		User:          "alice",
		protocolPorts: protocolPorts{TCP: []string{"*"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := rejectWildcardApplicationPorts(entries); err == nil {
		t.Fatal("expected wildcard application ports to be rejected")
	}
}

func TestApplicationRulesDoNotRequireDefaultRules(t *testing.T) {
	document, err := parsePolicyDocument([]byte(`{
      "acls": [
        {"action":"accept","src":["alice@"],"proto":"tcp","dst":["tag:olares:445"]}
      ]
    }`))
	if err != nil {
		t.Fatal(err)
	}
	ports, err := document.managedApplicationPorts()
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 1 || ports[0].User != "alice" {
		t.Fatalf("application ports = %#v", ports)
	}
}

func TestClearingApplicationPortsPreservesDefaultsAndUnrelatedRules(t *testing.T) {
	document, err := parsePolicyDocument([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	document.setManagedApplicationPorts(nil)

	application, err := document.managedApplicationPorts()
	if err != nil {
		t.Fatal(err)
	}
	if len(application) != 0 {
		t.Fatalf("application ports = %#v, want empty", application)
	}

	encoded, err := document.marshal()
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	var acls []policyACL
	if err := json.Unmarshal(fields["acls"], &acls); err != nil {
		t.Fatal(err)
	}
	foundUnrelated := false
	for _, acl := range acls {
		if reflect.DeepEqual(acl.Src, []string{"group:self-mesh"}) {
			foundUnrelated = true
		}
	}
	if !foundUnrelated {
		t.Fatalf("unrelated ACL was removed: %s", encoded)
	}
}
