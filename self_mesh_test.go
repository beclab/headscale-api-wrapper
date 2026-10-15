package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

const meshPolicy = `{"groups":{"group:self-mesh":["bob@"],"group:exit-users":["bob@"]},"acls":[{"action":"accept","src":["group:self-mesh"],"dst":["autogroup:self:*"]},{"action":"accept","src":["bob@"],"dst":["tag:olares:443"]}],"tagOwners":{"tag:olares":["owner@"]},"future":{"keep":true}}`

func TestSelfMeshHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	stored := meshPolicy
	writes := 0
	failWrite := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/policy":
			if r.Method == http.MethodPut {
				if failWrite {
					http.Error(w, "failed", 502)
					return
				}
				var body struct {
					Policy string `json:"policy"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				stored = body.Policy
				writes++
			}
			json.NewEncoder(w).Encode(map[string]string{"policy": stored})
		case "/user":
			fmt.Fprint(w, `{"users":[{"id":"1","name":"alice"}]}`)
		default:
			t.Errorf("unexpected upstream request %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer backend.Close()
	oldURL, oldVerify := url, verifySessionToken
	url = backend.URL
	verifySessionToken = func(ctx context.Context, token string) (tokenClaims, error) {
		if token != "alice-session" {
			return tokenClaims{}, fmt.Errorf("invalid session")
		}
		return tokenClaims{Username: "alice"}, nil
	}
	defer func() { url = oldURL; verifySessionToken = oldVerify }()
	router := gin.New()
	group := router.Group("/policy", requireAuthenticatedUser())
	group.GET("/self-mesh", getSelfMesh)
	group.PUT("/self-mesh", putSelfMesh)
	request := func(method, body, token string, code int) selfMeshState {
		t.Helper()
		req := httptest.NewRequest(method, "/policy/self-mesh", strings.NewReader(body))
		req.Header.Set("X-Authorization", token)
		req.Header.Set("X-BFL-USER", "bob") // Never authorizes editing Bob.
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != code {
			t.Fatalf("%s %s: status %d body %s", method, body, rec.Code, rec.Body.String())
		}
		var result struct {
			Data selfMeshState `json:"data"`
		}
		if code == 200 {
			if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
		}
		return result.Data
	}
	request("GET", "", "", 401)
	if s := request("GET", "", "alice-session", 200); s.Enabled {
		t.Fatal("new user enabled")
	}
	for _, body := range []string{`{}`, `{"enabled":null}`, `{"enabled":"true"}`, `{"enabled":true,"username":"bob"}`, `{"enabled":true} {}`, `{`} {
		request("PUT", body, "alice-session", 400)
	}
	if writes != 0 {
		t.Fatal("invalid input wrote policy")
	}
	if s := request("PUT", `{"enabled":true}`, "alice-session", 200); !s.Enabled || !s.Changed {
		t.Fatalf("enable: %+v", s)
	}
	if s := request("PUT", `{"enabled":true}`, "alice-session", 200); !s.Enabled || s.Changed {
		t.Fatalf("repeat enable: %+v", s)
	}
	if writes != 1 {
		t.Fatalf("writes=%d", writes)
	}
	if s := request("GET", "", "alice-session", 200); !s.Enabled || s.Changed {
		t.Fatalf("read: %+v", s)
	}
	failWrite = true
	request("PUT", `{"enabled":false}`, "alice-session", 502)
	if s := request("GET", "", "alice-session", 200); !s.Enabled {
		t.Fatal("failed write reported disabled")
	}
	failWrite = false
	if s := request("PUT", `{"enabled":false}`, "alice-session", 200); s.Enabled || !s.Changed {
		t.Fatalf("disable: %+v", s)
	}
	request("PUT", `{"enabled":false}`, "alice-session", 200)
	if writes != 2 {
		t.Fatalf("writes=%d", writes)
	}
	var got, want interface{}
	json.Unmarshal([]byte(stored), &got)
	json.Unmarshal([]byte(meshPolicy), &want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unrelated policy changed: %s", stored)
	}
	stored = `{"groups":{"group:self-mesh":[]},"acls":[]}`
	request("PUT", `{"enabled":true}`, "alice-session", 409)
	if writes != 2 {
		t.Fatal("unsafe policy written")
	}
}

func TestSelfMeshRejectUnexpectedRules(t *testing.T) {
	for _, policy := range []string{
		strings.Replace(meshPolicy, `"autogroup:self:*"`, `"*:*"`, 1),
		strings.Replace(meshPolicy, `"action":"accept"`, `"action":"deny"`, 1),
		strings.Replace(meshPolicy, `"src":["group:self-mesh"]`, `"src":["group:self-mesh","bob@"]`, 1),
		strings.Replace(meshPolicy, `"group:self-mesh":["bob@"]`, `"group:self-mesh":["group:admins"]`, 1),
		strings.Replace(meshPolicy, `"acls":[`, `"acls":[{"action":"accept","src":["group:self-mesh"],"dst":["autogroup:self:*"]},`, 1),
	} {
		doc, err := parsePolicyDocument([]byte(policy))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := doc.selfMeshMembers(); err == nil {
			t.Fatalf("accepted unsafe policy: %s", policy)
		}
	}
}
