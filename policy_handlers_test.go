package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// policyTestBackend provides the small part of the Headscale API used by the
// policy handlers. Keeping it in-process makes these tests deterministic and
// avoids requiring a cluster or a real API key.
type policyTestBackend struct {
	policy string
	users  map[string]string
	writes int
}

func newPolicyTestBackend(t *testing.T, policy string, users ...string) *policyTestBackend {
	t.Helper()
	b := &policyTestBackend{policy: policy, users: make(map[string]string)}
	for i, name := range users {
		b.users[name] = fmt.Sprintf("%d", i+1)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/policy" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]string{"policy": b.policy})
		case r.URL.Path == "/policy" && r.Method == http.MethodPut:
			var body struct {
				Policy string `json:"policy"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "invalid policy request", http.StatusBadRequest)
				return
			}
			b.policy = body.Policy
			b.writes++
			_ = json.NewEncoder(w).Encode(map[string]string{"policy": b.policy})
		case r.URL.Path == "/user" && r.Method == http.MethodGet:
			type user struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			list := make([]user, 0, len(b.users))
			for name, id := range b.users {
				list = append(list, user{ID: id, Name: name})
			}
			sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
			_ = json.NewEncoder(w).Encode(map[string]any{"users": list})
		case r.URL.Path == "/user" && r.Method == http.MethodPost:
			var body struct {
				Name string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
				http.Error(w, "invalid user request", http.StatusBadRequest)
				return
			}
			if _, exists := b.users[body.Name]; !exists {
				b.users[body.Name] = fmt.Sprintf("%d", len(b.users)+1)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	oldURL, oldHeaders := url, headers
	url, headers = server.URL, map[string]string{}
	t.Cleanup(func() {
		url, headers = oldURL, oldHeaders
		server.Close()
	})
	return b
}

func TestApplicationPortsHTTPReplacementAndIdempotency(t *testing.T) {
	gin.SetMode(gin.TestMode)
	backend := newPolicyTestBackend(t, `{"groups":{},"acls":[
{"action":"accept","src":["autogroup:member"],"proto":"tcp","dst":["tag:olares:443"]},
{"action":"accept","src":["alice@"],"proto":"tcp","dst":["tag:olares:445"]}
]}`, "alice")
	router := gin.New()
	router.GET("/application-ports", getApplicationPorts)
	router.PUT("/application-ports", putApplicationPorts)

	request := func(method, body string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/application-ports", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(recorder, req)
		return recorder
	}

	if recorder := request(http.MethodGet, ""); recorder.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder := request(http.MethodPut, `{"applicationPorts":[{"user":"alice","tcp":["5000"],"udp":[]}]}`); recorder.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if backend.writes != 1 || !strings.Contains(backend.policy, `tag:olares:5000`) || !strings.Contains(backend.policy, `tag:olares:443`) {
		t.Fatalf("unexpected policy write count or content: writes=%d policy=%s", backend.writes, backend.policy)
	}
	if recorder := request(http.MethodPut, `{"applicationPorts":[{"user":"alice","tcp":["5000"],"udp":[]}]}`); recorder.Code != http.StatusOK {
		t.Fatalf("idempotent PUT status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if backend.writes != 1 {
		t.Fatalf("idempotent PUT wrote policy again: writes=%d", backend.writes)
	}
	if recorder := request(http.MethodPut, `{"applicationPorts":[{"user":"alice","tcp":["*"],"udp":[]}]}`); recorder.Code != http.StatusBadRequest {
		t.Fatalf("wildcard status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if backend.writes != 1 {
		t.Fatal("invalid request changed policy")
	}
}

func TestSubnetRouteHTTPReplacementPreservesMarker(t *testing.T) {
	gin.SetMode(gin.TestMode)
	backend := newPolicyTestBackend(t, `{"groups":{},"acls":[],"autoApprovers":{"routes":{"10.255.255.254/32":["tag:olares"],"192.168.31.0/24":["tag:olares"],"192.168.99.0/24":["tag:other"]}}}`)
	routeFile := filepath.Join(t.TempDir(), "subnet-routes")
	t.Setenv("SUBNET_ROUTES_FILE", routeFile)
	t.Setenv("OLARES_CLUSTER_CIDRS", "10.233.0.0/16")
	router := gin.New()
	router.GET("/routes", getSubnetRoutes)
	router.PUT("/routes", putSubnetRoutes)

	request := func(method, body string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/routes", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(recorder, req)
		return recorder
	}
	if recorder := request(http.MethodGet, ""); recorder.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder := request(http.MethodPut, `{"routes":["192.168.40.0/24"]}`); recorder.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if backend.writes != 1 || !strings.Contains(backend.policy, `192.168.40.0/24`) || !strings.Contains(backend.policy, `10.255.255.254/32`) || !strings.Contains(backend.policy, `192.168.99.0/24`) {
		t.Fatalf("route replacement changed unrelated policy: writes=%d policy=%s", backend.writes, backend.policy)
	}
	file, err := os.ReadFile(routeFile)
	if err != nil || string(file) != "192.168.40.0/24\n" {
		t.Fatalf("route file=%q err=%v", file, err)
	}
}

func TestLANGroupHTTPCreateListAndDelete(t *testing.T) {
	gin.SetMode(gin.TestMode)
	backend := newPolicyTestBackend(t, `{"groups":{},"acls":[]}`, "alice")
	oldLookup := lookupOlaresUser
	lookupOlaresUser = func(_ context.Context, username string) (bool, error) { return username == "alice", nil }
	t.Cleanup(func() { lookupOlaresUser = oldLookup })
	router := gin.New()
	router.PUT("/groups/:name", putLanGroup)
	router.GET("/groups", getLanGroups)
	router.DELETE("/groups/:name", deleteLanGroup)

	put := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/groups/nas-users", strings.NewReader(`{"users":["alice"]}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(put, req)
	if put.Code != http.StatusOK || !strings.Contains(put.Body.String(), `"nas-users"`) {
		t.Fatalf("create status=%d body=%s", put.Code, put.Body.String())
	}

	list := httptest.NewRecorder()
	router.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/groups", nil))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"users":["alice"]`) {
		t.Fatalf("list status=%d body=%s", list.Code, list.Body.String())
	}

	del := httptest.NewRecorder()
	router.ServeHTTP(del, httptest.NewRequest(http.MethodDelete, "/groups/nas-users", nil))
	if del.Code != http.StatusOK || backend.writes != 2 {
		t.Fatalf("delete status=%d writes=%d body=%s", del.Code, backend.writes, del.Body.String())
	}
	var got response
	if err := json.Unmarshal(del.Body.Bytes(), &got); err != nil || !reflect.DeepEqual(got.Data, map[string]any{"changed": true}) {
		t.Fatalf("delete response=%#v err=%v", got.Data, err)
	}
}
