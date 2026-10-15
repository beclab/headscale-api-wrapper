package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeviceHelpersFilterOwnershipAndUseRESTPaths(t *testing.T) {
	nodes := []map[string]any{
		{"id": "1", "name": "alice-laptop", "user": map[string]string{"name": "alice"}},
		{"id": "2", "name": "bob-laptop", "user": map[string]string{"name": "bob"}},
	}
	deleted := ""
	renamed := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/node" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"nodes": nodes})
		case strings.HasPrefix(r.URL.Path, "/node/") && r.Method == http.MethodDelete:
			deleted = strings.TrimPrefix(r.URL.Path, "/node/")
			_ = json.NewEncoder(w).Encode(map[string]any{"deleted": deleted})
		case strings.HasPrefix(r.URL.Path, "/node/") && r.Method == http.MethodPost:
			renamed = r.URL.EscapedPath()
			_ = json.NewEncoder(w).Encode(map[string]any{"renamed": renamed})
		default:
			http.NotFound(w, r)
		}
	}))
	oldURL, oldHeaders := url, headers
	url, headers = server.URL, map[string]string{}
	t.Cleanup(func() {
		url, headers = oldURL, oldHeaders
		server.Close()
	})

	ctx := context.Background()
	filtered, err := getDevicesForUser(ctx, "alice")
	if err != nil || len(filtered.Nodes) != 1 {
		t.Fatalf("filtered nodes=%d err=%v", len(filtered.Nodes), err)
	}
	if owns, err := userOwnsNode(ctx, "alice", "1"); err != nil || !owns {
		t.Fatalf("alice ownership=%t err=%v", owns, err)
	}
	if owns, err := userOwnsNode(ctx, "alice", "2"); err != nil || owns {
		t.Fatalf("foreign ownership=%t err=%v", owns, err)
	}

	if _, err := renameDevice(ctx, "1", "alice mac"); err != nil {
		t.Fatal(err)
	}
	if renamed != "/node/1/rename/alice%20mac" {
		t.Fatalf("rename path=%q", renamed)
	}
	if _, err := removeDevice(ctx, "1"); err != nil {
		t.Fatal(err)
	}
	if deleted != "1" {
		t.Fatalf("deleted node=%q", deleted)
	}
}
