package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beclab/lldap/clients/go/client"
)

func TestHeadscaleUserSourceInitialLoadCreatesAndSafelyDeletes(t *testing.T) {
	var mu sync.Mutex
	users := map[string]string{"alice": "1", "stale": "2"}
	policy := `{
  "acls": [
    {"action":"accept","src":["stale@"],"dst":["tag:olares:22"]},
    {"action":"accept","src":["alice@","stale@"],"dst":["tag:olares:443"]}
  ],
  "groups": {"group:exit-users":["stale@"],"group:admins":["alice@"]},
  "tagOwners": {"tag:olares":["stale@","group:admins"]}
}`
	policyUpdated := false
	nodeDeletedAfterPolicy := false
	deletedAfterPolicy := false

	mux := http.NewServeMux()
	mux.HandleFunc("/readonly/snapshot", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"users":[{"id":"admin"},{"id":"alice"},{"id":"bob"}]}`))
	})
	mux.HandleFunc("/api/v1/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			items := make([]headscaleUser, 0, len(users))
			for name, id := range users {
				items = append(items, headscaleUser{ID: id, Name: name})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"users": items})
		case http.MethodPost:
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			users[body["name"]] = "3"
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/user/2", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		deletedAfterPolicy = policyUpdated
		delete(users, "stale")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v1/node", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nodes":[{"id":"9","user":{"name":"stale"}},{"id":"10","user":{"name":"tagged-devices"}}]}`))
	})
	mux.HandleFunc("/api/v1/node/9", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		mu.Lock()
		nodeDeletedAfterPolicy = policyUpdated
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v1/policy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]string{"policy": policy})
			return
		}
		if r.Method == http.MethodPut {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			policy = body["policy"]
			policyUpdated = true
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	restoreURL := url
	url = server.URL + "/api/v1"
	defer func() { url = restoreURL }()
	cfg := userSyncConfig{
		readonlyURL: server.URL,
		interval:    time.Hour,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := (&headscaleUserSource{cfg: cfg}).Start(ctx); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	_, bobExists := users["bob"]
	_, staleExists := users["stale"]
	finalPolicy := policy
	mu.Unlock()
	if !bobExists || staleExists {
		t.Fatalf("unexpected users after reconciliation: %#v", users)
	}
	if !deletedAfterPolicy {
		t.Fatal("stale user was deleted before policy references were removed")
	}
	if !nodeDeletedAfterPolicy {
		t.Fatal("stale user's node was not deleted after policy references were removed")
	}
	if strings.Contains(finalPolicy, `"stale@"`) {
		t.Fatalf("stale user remains in policy: %s", finalPolicy)
	}
}

func TestHeadscaleUserSourcePreservesUnsupportedUsernameAndContinuesReconcile(t *testing.T) {
	var mu sync.Mutex
	users := map[string]string{"bad@name": "1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			items := make([]headscaleUser, 0, len(users))
			for name, id := range users {
				items = append(items, headscaleUser{ID: id, Name: name})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"users": items})
		case http.MethodPost:
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			users[body["name"]] = "2"
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	restoreURL := url
	url = server.URL + "/api/v1"
	defer func() { url = restoreURL }()
	source := &headscaleUserSource{}
	// "bad@name" cannot be represented safely in policy. Its presence in LLDAP
	// must preserve the existing Headscale identity while bob is still created.
	if err := source.reconcileSnapshot(context.Background(), []client.User{
		{ID: "admin"},
		{ID: "bad@name"},
		{ID: "bob"},
	}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	_, bobExists := users["bob"]
	_, unsupportedExists := users["bad@name"]
	mu.Unlock()
	if !bobExists {
		t.Fatal("valid user was not created alongside an unsupported LLDAP id")
	}
	if !unsupportedExists {
		t.Fatal("unsupported LLDAP user id was mistaken for a deleted user")
	}
}

func TestHeadscaleUserSourceApplyChangesCreatesAndDeletes(t *testing.T) {
	var mu sync.Mutex
	users := map[string]string{"stale": "2"}
	policy := `{"acls":[{"action":"accept","src":["stale@"],"dst":["tag:olares:22"]}],"groups":{}}`
	policyUpdated := false
	deleted := false

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			items := make([]headscaleUser, 0, len(users))
			for name, id := range users {
				items = append(items, headscaleUser{ID: id, Name: name})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"users": items})
		case http.MethodPost:
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			users[body["name"]] = "3"
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/user/2", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		mu.Lock()
		deleted = policyUpdated
		delete(users, "stale")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v1/node", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nodes":[]}`))
	})
	mux.HandleFunc("/api/v1/policy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]string{"policy": policy})
			return
		}
		if r.Method == http.MethodPut {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			policy = body["policy"]
			policyUpdated = true
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	restoreURL := url
	url = server.URL + "/api/v1"
	defer func() { url = restoreURL }()

	source := &headscaleUserSource{}
	if err := source.applyChanges(context.Background(), client.Changes{
		UsersAdded:   []client.User{{ID: "bob"}},
		UsersRemoved: []client.User{{ID: "stale"}},
	}); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	_, bobExists := users["bob"]
	_, staleExists := users["stale"]
	mu.Unlock()
	if !bobExists {
		t.Fatal("applyChanges did not create the added user")
	}
	if staleExists || !deleted {
		t.Fatal("applyChanges did not delete the removed user after policy cleanup")
	}
}

func TestHeadscaleUserSourceConcurrentCreateIsIdempotent(t *testing.T) {
	var mu sync.Mutex
	listCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			listCalls++
			if listCalls == 1 {
				_, _ = w.Write([]byte(`{"users":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{"users":[{"id":"7","name":"alice"}]}`))
		case http.MethodPost:
			// Simulate another request creating the same user between the list and
			// create calls. The subsequent lookup is the source of truth.
			w.WriteHeader(http.StatusConflict)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	restoreURL := url
	url = server.URL + "/api/v1"
	defer func() { url = restoreURL }()
	source := &headscaleUserSource{}
	current := make(map[string]headscaleUser)
	if err := source.ensureUsers(context.Background(), []client.User{{ID: "alice"}}, current); err != nil {
		t.Fatal(err)
	}
	if got := current["alice"].ID; got != "7" {
		t.Fatalf("created user id = %q, want 7", got)
	}
}

func TestHeadscaleUserSourceRejectsIncompleteSnapshotBeforeMutation(t *testing.T) {
	mutated := false
	mux := http.NewServeMux()
	mux.HandleFunc("/readonly/snapshot", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"users":[{"id":"alice"}]}`))
	})
	mux.HandleFunc("/api/v1/user", func(w http.ResponseWriter, _ *http.Request) {
		mutated = true
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	restoreURL := url
	url = server.URL + "/api/v1"
	defer func() { url = restoreURL }()
	cfg := userSyncConfig{readonlyURL: server.URL, interval: time.Hour}
	if err := (&headscaleUserSource{cfg: cfg}).Start(context.Background()); err == nil {
		t.Fatal("expected incomplete snapshot to be rejected")
	}
	if mutated {
		t.Fatal("incomplete snapshot caused a Headscale mutation")
	}
}

func TestHeadscaleUserSourceRetriesInitialSnapshotWithoutBlockingStartup(t *testing.T) {
	var mu sync.Mutex
	snapshotCalls := 0
	userCreated := false
	created := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/readonly/snapshot", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		snapshotCalls++
		call := snapshotCalls
		mu.Unlock()
		if call == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"users":[{"id":"admin"},{"id":"alice"}]}`))
	})
	mux.HandleFunc("/api/v1/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			mu.Lock()
			exists := userCreated
			mu.Unlock()
			if exists {
				_, _ = w.Write([]byte(`{"users":[{"id":"1","name":"alice"}]}`))
			} else {
				_, _ = w.Write([]byte(`{"users":[]}`))
			}
		case http.MethodPost:
			mu.Lock()
			userCreated = true
			mu.Unlock()
			select {
			case created <- struct{}{}:
			default:
			}
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	restoreURL := url
	url = server.URL + "/api/v1"
	defer func() { url = restoreURL }()
	ctx, cancel := context.WithCancel(context.Background())
	source := &headscaleUserSource{cfg: userSyncConfig{
		readonlyURL: server.URL,
		interval:    10 * time.Millisecond,
	}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		source.startWithRetry(ctx)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("user sync did not stop after cancellation")
		}
	}()

	select {
	case <-created:
	case <-time.After(time.Second):
		t.Fatal("initial synchronization was not retried")
	}
	mu.Lock()
	calls := snapshotCalls
	mu.Unlock()
	if calls < 2 {
		t.Fatalf("snapshot calls = %d, want at least 2", calls)
	}
}

func TestNATSDriverRestartsAfterUnexpectedExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	attempts := 0
	go func() {
		defer close(done)
		runNATSDriverWithRetry(ctx, time.Millisecond, func() error {
			attempts++
			if attempts == 2 {
				cancel()
			}
			return errors.New("driver stopped")
		})
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("NATS driver supervisor did not retry")
	}
	if attempts != 2 {
		t.Fatalf("driver attempts = %d, want 2", attempts)
	}
}

func TestHeadscaleUserSourceFullReconcileDeletesRemovedUser(t *testing.T) {
	deleted := false
	adminDeleted := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/user", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"users":[{"id":"1","name":"admin"},{"id":"2","name":"bob"}]}`))
	})
	mux.HandleFunc("/api/v1/user/1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		adminDeleted = true
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v1/user/2", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		deleted = true
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v1/node", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nodes":[]}`))
	})
	mux.HandleFunc("/api/v1/policy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]string{"policy": `{"acls":[],"groups":{}}`})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	restoreURL := url
	url = server.URL + "/api/v1"
	defer func() { url = restoreURL }()
	source := &headscaleUserSource{}
	if err := source.reconcileSnapshot(context.Background(), []client.User{{ID: "admin"}}); err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("full reconciliation did not delete the removed user")
	}
	if adminDeleted {
		t.Fatal("full reconciliation deleted the LLDAP bootstrap admin")
	}
}

func TestHeadscaleUserSourceRejectsSurroundingWhitespaceInUserID(t *testing.T) {
	source := &headscaleUserSource{}
	_, _, err := source.validateSnapshot([]client.User{{ID: lldapBootstrapAdmin}, {ID: " alice "}})
	if err == nil {
		t.Fatal("expected surrounding whitespace in LLDAP user id to be rejected")
	}
}

func TestRemoveUserReferences(t *testing.T) {
	document, err := parsePolicyDocument([]byte(`{
  "acls":[
    {"action":"accept","src":["alice@"],"dst":["tag:olares:22"]},
    {"action":"accept","src":["alice@","bob@"],"dst":["tag:olares:443"]},
    {"action":"accept","src":["bob@"],"dst":["alice@:443","alice@:80-90","alice@:*","alice2@:443"]}
  ],
  "groups":{"group:test":["alice@","bob@"]},
  "autoApprovers":{"routes":{"10.0.0.0/24":["alice@","tag:olares"]}}
}`))
	if err != nil {
		t.Fatal(err)
	}
	if !document.removeUserReferences("alice") {
		t.Fatal("expected policy change")
	}
	encoded, err := document.marshal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"alice@"`) || strings.Contains(string(encoded), `"alice@:`) {
		t.Fatalf("alias remains after cleanup: %s", encoded)
	}
	if !strings.Contains(string(encoded), `"bob@"`) || !strings.Contains(string(encoded), `"alice2@:443"`) {
		t.Fatalf("unrelated alias was removed: %s", encoded)
	}
	if len(document.ACLs) != 2 || !reflect.DeepEqual(document.ACLs[0].Src, []string{"bob@"}) ||
		!reflect.DeepEqual(document.ACLs[1].Dst, []string{"alice2@:443"}) {
		t.Fatalf("ACL cleanup result = %#v", document.ACLs)
	}
}
