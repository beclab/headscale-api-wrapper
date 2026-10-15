package main

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSubnetRequestsRejectCombinedOrMissingState(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		body    string
		handler gin.HandlerFunc
	}{
		{`{"routes":[],"users":["alice"]}`, putSubnetRoutes},
		{`{"routes":null}`, putSubnetRoutes},
		{`{}`, putSubnetRoutes},
		{`{"access":null}`, putSubnetAccess},
		{`{"access":[]} {}`, putSubnetAccess},
		{`{"access":[{"users":["alice"],"target":"192.168.1.10","protocol":"tcp","ports":["445"],"typo":true}]}`, putSubnetAccess},
	} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("PUT", "/", strings.NewReader(tc.body))
		tc.handler(c)
		if w.Code != 400 {
			t.Fatalf("%s: status %d", tc.body, w.Code)
		}
	}
}

func subnetFixture(t *testing.T) *policyDocument {
	t.Helper()
	p, err := parsePolicyDocument([]byte(`{"groups":{"group:subnet-users":["alice@"]},"acls":[{"action":"accept","src":["group:subnet-users"],"dst":["192.168.1.0/24:*"]},{"action":"accept","src":["autogroup:member"],"proto":"tcp","dst":["tag:olares:443"]}],"autoApprovers":{"routes":{"192.168.1.0/24":["tag:olares"],"10.255.255.254/32":["tag:olares"],"192.168.99.0/24":["tag:other"]},"exitNode":["tag:olares"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSubnetIndependentUpdates(t *testing.T) {
	p := subnetFixture(t)
	before, _ := json.Marshal(p.ACLs)
	groups := string(p.fields["groups"])
	if err := p.replaceSubnetRoutes([]string{"192.168.2.0/24"}); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(p.ACLs)
	if string(before) != string(after) || groups != string(p.fields["groups"]) {
		t.Fatal("routes modified access")
	}
	a, _ := p.policyAutoApprovers()
	if len(a.ExitNode) != 1 || len(a.Routes[subnetMarker]) != 1 || len(a.Routes["192.168.99.0/24"]) != 1 {
		t.Fatal("unrelated approvals lost")
	}
	approvals := string(p.fields["autoApprovers"])
	rules := []subnetAccessRule{{Users: []string{"bob"}, Target: "192.168.3.10/32", Protocol: "tcp", Ports: []string{"445", "5000-5010"}}}
	if err := p.replaceSubnetAccess(rules); err != nil {
		t.Fatal(err)
	}
	if approvals != string(p.fields["autoApprovers"]) {
		t.Fatal("access modified routes")
	}
	got, err := p.subnetAccess()
	if err != nil || !reflect.DeepEqual(got, rules) {
		t.Fatalf("roundtrip: %#v %v", got, err)
	}
	for _, acl := range p.ACLs {
		if containsString(acl.Src, subnetUsersGroup) {
			t.Fatal("legacy broad access retained")
		}
	}
	if err := p.replaceSubnetAccess(nil); err != nil {
		t.Fatal(err)
	}
	got, err = p.subnetAccess()
	if err != nil || len(got) != 0 {
		t.Fatal("clear failed", err)
	}
	if approvals != string(p.fields["autoApprovers"]) {
		t.Fatal("clear access modified routes")
	}
}

func TestSubnetAccessValidation(t *testing.T) {
	t.Setenv("OLARES_CLUSTER_CIDRS", "10.233.64.0/18,10.233.0.0/18")
	base := subnetAccessRule{Users: []string{"bob", "alice", "bob"}, Target: "192.168.1.10", Protocol: "TCP", Ports: []string{"445", "5000-5010"}}
	got, err := normalizeSubnetAccess([]subnetAccessRule{base}, true)
	if err != nil || got[0].Target != "192.168.1.10/32" || got[0].Protocol != "tcp" || len(got[0].Users) != 2 {
		t.Fatal(got, err)
	}
	for _, target := range []string{"10.233.0.1", "10.0.0.0/8", "8.8.8.8", "nas", "::1"} {
		r := base
		r.Target = target
		if _, err := normalizeSubnetAccess([]subnetAccessRule{r}, true); err == nil {
			t.Fatal("accepted", target)
		}
	}
	for _, ports := range [][]string{nil, {"0"}, {"65536"}, {"5000-445"}, {"*", "445"}, {"445,5000"}} {
		r := base
		r.Ports = ports
		if _, err := normalizeSubnetAccess([]subnetAccessRule{r}, true); err == nil {
			t.Fatal("accepted", ports)
		}
	}
	t.Setenv("OLARES_CLUSTER_CIDRS", "")
	if _, err := normalizeSubnetAccess(nil, true); err != nil {
		t.Fatal("cannot revoke without CIDR config")
	}
}

func TestSubnetRoutesReadIndependentOfACL(t *testing.T) {
	p := subnetFixture(t)
	if err := p.replaceSubnetAccess(nil); err != nil {
		t.Fatal(err)
	}
	routes, err := p.subnetRoutes()
	if err != nil || !reflect.DeepEqual(routes, []string{"192.168.1.0/24"}) {
		t.Fatal(routes, err)
	}
}

func TestSubnetAccessMarkerMigration(t *testing.T) {
	for _, referenced := range []bool{false, true} {
		p, err := parsePolicyDocument([]byte(`{"groups":{"group:subnet-access-0":[],"group:lan-dns-users":["alice@"]},"acls":[{"action":"accept","src":["group:subnet-access-0","group:lan-dns-users"],"proto":"udp","dst":["192.168.31.0/24:53"]},{"action":"accept","src":["bob@"],"proto":"tcp","dst":["192.168.31.1/32:22"]}]}`))
		if err != nil {
			t.Fatal(err)
		}
		if referenced {
			p.fields["grants"] = json.RawMessage(`[{"src":["group:subnet-access-0"],"dst":["192.168.31.1"],"ip":["tcp:22"]}]`)
		}
		rules, err := p.subnetAccess()
		if err != nil || len(rules) != 1 {
			t.Fatalf("legacy read: %v %v", rules, err)
		}
		if err := p.replaceSubnetAccess(rules); err != nil {
			t.Fatal(err)
		}
		groups, _ := p.policyGroups()
		if _, exists := groups["group:subnet-access-0"]; exists != referenced {
			t.Fatal("incorrect marker cleanup")
		}
		if len(p.ACLs) != 2 || p.ACLs[0].Src[0] != "bob@" || !markedSubnetACL(p.ACLs[1]) {
			t.Fatal("unmanaged rule changed or missing metadata")
		}
		raw, _ := p.marshal()
		p, err = parsePolicyDocument(raw)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.subnetAccess()
		if err != nil || !reflect.DeepEqual(got, rules) {
			t.Fatalf("migrated read: %#v %v", got, err)
		}
		if err := p.replaceSubnetAccess(rules); err != nil {
			t.Fatal(err)
		}
		again, _ := p.marshal()
		if string(raw) != string(again) {
			t.Fatal("replacement is not idempotent")
		}
	}
}
