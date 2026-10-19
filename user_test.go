package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestResolveUserIDStringWithCreateConcurrentCreate(t *testing.T) {
	var stateMu sync.Mutex
	created := false
	successfulCreates := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/user" {
			http.NotFound(w, r)
			return
		}

		stateMu.Lock()
		defer stateMu.Unlock()

		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			if created {
				_, _ = w.Write([]byte(`{"users":[{"id":"42","name":"alice"}]}`))
			} else {
				_, _ = w.Write([]byte(`{"users":[]}`))
			}
		case http.MethodPost:
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["name"] != "alice" {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if created {
				http.Error(w, "already exists", http.StatusConflict)
				return
			}
			created = true
			successfulCreates++
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	oldURL, oldHeaders := url, headers
	url, headers = server.URL+"/api/v1", map[string]string{}
	defer func() {
		url, headers = oldURL, oldHeaders
	}()

	const requests = 20
	errCh := make(chan error, requests)
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			uid, err := resolveUserIDStringWithCreate(context.Background(), "alice", true)
			if err != nil {
				errCh <- err
				return
			}
			if uid != "42" {
				errCh <- fmt.Errorf("got user id %q, want 42", uid)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	stateMu.Lock()
	defer stateMu.Unlock()
	if successfulCreates != 1 {
		t.Fatalf("got %d successful creates, want 1", successfulCreates)
	}
}

func TestResolveUserIDStringDoesNotCreate(t *testing.T) {
	created := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/user" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"users":[]}`))
		case http.MethodPost:
			created = true
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	oldURL, oldHeaders := url, headers
	url, headers = server.URL+"/api/v1", map[string]string{}
	defer func() {
		url, headers = oldURL, oldHeaders
	}()

	if _, err := resolveUserIDString(context.Background(), "alice"); err == nil {
		t.Fatal("expected missing synchronized user to be rejected")
	}
	if created {
		t.Fatal("ordinary user lookup created a Headscale user")
	}
}
