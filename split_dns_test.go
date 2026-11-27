package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func userJSON(name, zone string) string {
	return fmt.Sprintf(`{"metadata":{"name":%q,"annotations":{"bytetrade.io/zone":%q}}}`, name, zone)
}

func readZonesFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestSyncSplitDNSZonesListsThenAppliesWatchEvents(t *testing.T) {
	var watchQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("watch") == "1" {
			watchQuery = r.URL.RawQuery
			for _, event := range []string{
				`{"type":"ADDED","object":` + userJSON("bob", " Bob.Olares.com ") + `}`,
				`{"type":"MODIFIED","object":` + userJSON("carol", "bad zone") + `}`,
				`{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"8"}}}`,
				`{"type":"DELETED","object":` + userJSON("alice", "alice.olares.com") + `}`,
			} {
				fmt.Fprintln(w, event)
			}
			return
		}
		fmt.Fprintf(w, `{"metadata":{"resourceVersion":"7"},"items":[%s,%s]}`,
			userJSON("alice", "alice.olares.com"), userJSON("pending", ""))
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "split-dns-zones")
	api := &olaresUserAPI{endpoint: server.URL, token: "token", transport: &http.Transport{}}
	if err := syncTestUserZones(context.Background(), api, path); err != nil {
		t.Fatal(err)
	}
	if got := readZonesFile(t, path); got != "{\"bob.olares.com\":[\"100.64.0.2\"]}\n" {
		t.Fatalf("zones = %q", got)
	}
	if want := "watch=1&allowWatchBookmarks=true&timeoutSeconds=300&resourceVersion=7"; watchQuery != want {
		t.Fatalf("watch query = %q, want %q", watchQuery, want)
	}
}

func TestSyncSplitDNSZonesKeepsFileWhenListFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "split-dns-zones")
	if err := os.WriteFile(path, []byte("alice.olares.com\n"), 0640); err != nil {
		t.Fatal(err)
	}
	api := &olaresUserAPI{endpoint: server.URL, token: "token", transport: &http.Transport{}}
	if err := syncTestUserZones(context.Background(), api, path); err == nil {
		t.Fatal("expected list failure")
	}
	if got := readZonesFile(t, path); got != "alice.olares.com\n" {
		t.Fatalf("zones = %q", got)
	}
}

func TestPublishSplitDNSZonesSkipsUnchangedContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "split-dns-zones")
	if err := publishSplitDNSZones(path, testIPFile(t), nil); err != nil {
		t.Fatal(err)
	}
	if got := readZonesFile(t, path); got != "{}\n" {
		t.Fatalf("empty zones = %q", got)
	}
	if err := publishSplitDNSZones(path, testIPFile(t), []string{"alice.olares.com"}); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishSplitDNSZones(path, testIPFile(t), []string{"alice.olares.com"}); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("unchanged zones replaced the file")
	}
}

func TestSplitDNSZonesRejectsInvalidDomains(t *testing.T) {
	zones := map[string]string{
		"valid": " A-b.Example.com ", "duplicate": "a-b.example.com",
		"leading": "-foo.example.com", "trailing": "foo-.example.com",
		"longLabel":  strings.Repeat("a", 64) + ".example.com",
		"longName":   strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 62),
		"emptyLabel": "foo..com", "single": "localhost",
	}
	if got := splitDNSZones(zones); !reflect.DeepEqual(got, []string{"a-b.example.com"}) {
		t.Fatalf("zones = %q", got)
	}
}

func TestSyncSplitDNSZonesRejectsMalformedList(t *testing.T) {
	for _, body := range []string{
		`{}`, `null`, `{"items":[]}`,
		`{"metadata":{"resourceVersion":"7"},"items":[{}]}`,
	} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, body)
			}))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "zones")
			if err := os.WriteFile(path, []byte("old.example.com\n"), 0640); err != nil {
				t.Fatal(err)
			}
			api := &olaresUserAPI{endpoint: server.URL, transport: &http.Transport{}}
			defer api.transport.CloseIdleConnections()
			if err := syncTestUserZones(context.Background(), api, path); err == nil {
				t.Fatal("expected invalid list error")
			}
			if got := readZonesFile(t, path); got != "old.example.com\n" {
				t.Fatalf("zones = %q", got)
			}
		})
	}
}

func syncTestUserZones(ctx context.Context, api *olaresUserAPI, path string) error {
	ipPath := filepath.Join(filepath.Dir(path), "tailscale.ip")
	if err := os.WriteFile(ipPath, []byte("100.64.0.2\n"), 0644); err != nil {
		return err
	}
	publisher := &splitDNSPublisher{path: path, ipPath: ipPath}
	return syncSplitDNSZones(ctx, api, publisher.update)
}

func testIPFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tailscale.ip")
	if err := os.WriteFile(path, []byte("100.64.0.2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSplitDNSInvalidIPPreservesOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolvers.json")
	ipPath := testIPFile(t)
	zones := []string{"alice.olares.com"}
	if err := publishSplitDNSZones(path, ipPath, zones); err != nil {
		t.Fatal(err)
	}
	before := readZonesFile(t, path)
	for _, invalid := range []string{"", "bad", "::1", "0.0.0.0", "100.64.0.2\n100.64.0.3"} {
		if err := os.WriteFile(ipPath, []byte(invalid), 0644); err != nil {
			t.Fatal(err)
		}
		if err := publishSplitDNSZones(path, ipPath, zones); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
		if got := readZonesFile(t, path); got != before {
			t.Fatalf("overwrote good output: %s", got)
		}
	}
	if err := os.Remove(ipPath); err != nil {
		t.Fatal(err)
	}
	if err := publishSplitDNSZones(path, ipPath, zones); err == nil {
		t.Fatal("accepted missing IP")
	}
	if err := publishSplitDNSZones(path, ipPath, nil); err != nil {
		t.Fatal(err)
	}
	if got := readZonesFile(t, path); got != "{}\n" {
		t.Fatal(got)
	}
}

func TestSplitDNSPeriodicIPUpdateAndRepair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolvers.json")
	ipPath := testIPFile(t)
	publisher := &splitDNSPublisher{path: path, ipPath: ipPath}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); publisher.run(ctx, 5*time.Millisecond) }()
	defer func() { cancel(); <-done }()
	publisher.mu.Lock()
	publisher.publishLocked()
	publisher.mu.Unlock()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("published before first list")
	}
	publisher.update([]string{"alice.olares.com"})
	if err := os.WriteFile(ipPath, []byte("100.64.0.3"), 0644); err != nil {
		t.Fatal(err)
	}
	want := "{\"alice.olares.com\":[\"100.64.0.3\"]}\n"
	wait := func() {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			data, err := os.ReadFile(path)
			if err == nil && string(data) == want {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("periodic reconciliation did not produce expected JSON")
	}
	wait()
	for _, stale := range []string{"broken", "{}"} {
		if err := os.WriteFile(path, []byte(stale), 0644); err != nil {
			t.Fatal(err)
		}
		wait()
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	wait()
}

// A one-hour fallback makes these checks depend on filesystem notifications.
func TestSplitDNSWatchAtomicReplacementAndCreation(t *testing.T) {
	dir := t.TempDir()
	path, ipPath := filepath.Join(dir, "resolvers.json"), filepath.Join(dir, "tailscale.ip")
	publisher := &splitDNSPublisher{path: path, ipPath: ipPath}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); publisher.run(ctx, time.Hour) }()
	defer func() { cancel(); <-done }()
	publisher.update([]string{"alice.olares.com"})
	wait := func(ip string) {
		t.Helper()
		want := fmt.Sprintf("{\"alice.olares.com\":[%q]}\n", ip)
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			data, err := os.ReadFile(path)
			if err == nil && string(data) == want {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("watch did not publish %s", want)
	}
	for _, ip := range []string{"100.64.0.2", "100.64.0.3", "100.64.0.4"} {
		if err := replaceFile(ipPath, []byte(ip)); err != nil {
			t.Fatal(err)
		}
		wait(ip)
	}
	// Replacing the output must not lose its watch or cause a rewrite loop.
	if err := replaceFile(path, []byte("broken")); err != nil {
		t.Fatal(err)
	}
	wait("100.64.0.4")
	if err := os.Remove(ipPath); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(ipPath, []byte("100.64.0.5")); err != nil {
		t.Fatal(err)
	}
	wait("100.64.0.5")
}
