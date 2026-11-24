package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	neturl "net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	olaresZoneAnnotation        = "bytetrade.io/zone"
	splitDNSWatchTimeoutSeconds = 300
	splitDNSRetryInterval       = time.Second
)

var replaceSplitDNSZonesFile = replaceFile

var splitDNSLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

// splitDNSPublisher serializes user snapshots and periodic disk reconciliation.
// No output is written until a complete user list has been received.
type splitDNSPublisher struct {
	mu           sync.Mutex
	path, ipPath string
	zones        []string
	ready        bool
}

func (p *splitDNSPublisher) update(zones []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.zones = append([]string(nil), zones...)
	p.ready = true
	p.publishLocked()
}

func (p *splitDNSPublisher) publishLocked() {
	if p.ready {
		if err := publishSplitDNSZones(p.path, p.ipPath, p.zones); err != nil {
			log.Printf("split DNS publish failed; keeping previous configuration: %v", err)
		}
	}
}

func (p *splitDNSPublisher) run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	watcher, err := fsnotify.NewWatcher()
	var events <-chan fsnotify.Event
	var watchErrors <-chan error
	if err != nil {
		log.Printf("split DNS watcher unavailable; using periodic reconciliation: %v", err)
	} else {
		defer watcher.Close()
		events, watchErrors = watcher.Events, watcher.Errors
	}
	// Watch directories, not inodes: publishers atomically rename files into place.
	// Retry missing/recreated directories on each reconciliation tick.
	addWatches := func() {
		if watcher == nil {
			return
		}
		dirs := map[string]bool{filepath.Dir(p.ipPath): true, filepath.Dir(p.path): true}
		for dir := range dirs {
			if err := watcher.Add(dir); err != nil {
				log.Printf("split DNS watch directory %q: %v; will retry", dir, err)
			}
		}
	}
	reconcile := func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.publishLocked()
	}
	addWatches()
	// Close the gap between the first user snapshot and installing the watches.
	reconcile()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			name := filepath.Clean(event.Name)
			if name == filepath.Clean(p.ipPath) || name == filepath.Clean(p.path) {
				reconcile()
			}
		case err, ok := <-watchErrors:
			if !ok {
				watchErrors = nil
				continue
			}
			log.Printf("split DNS watch failed: %v; reconciling", err)
			reconcile()
		case <-ticker.C:
			addWatches()
			reconcile()
		}
	}
}

// startSplitDNSZoneSync publishes Headscale's domain-to-resolvers JSON.
// User zones are the only domain source; IP changes are reconciled independently.
func startSplitDNSZoneSync(ctx context.Context) error {
	path := strings.TrimSpace(os.Getenv("SPLIT_DNS_RESOLVERS_FILE"))
	if path == "" {
		return nil
	}
	ipPath := strings.TrimSpace(os.Getenv("TAILSCALE_IP_FILE"))
	if ipPath == "" {
		ipPath = "/var/lib/headscale/bootstrap/tailscale.ip"
	}
	if path == ipPath {
		return errors.New("split DNS output and Tailscale IP input must differ")
	}
	publisher := &splitDNSPublisher{path: path, ipPath: ipPath}
	go publisher.run(ctx, 30*time.Second)
	go func() {
		for ctx.Err() == nil {
			api, err := newOlaresUserAPI()
			if err == nil {
				err = syncSplitDNSZones(ctx, api, publisher.update)
				api.transport.CloseIdleConnections()
			}
			if err != nil && ctx.Err() == nil {
				log.Printf("split DNS user sync failed: %v; retrying in %s", err, splitDNSRetryInterval)
			}
			if !waitForUserSyncRetry(ctx, splitDNSRetryInterval) {
				return
			}
		}
	}()
	return nil
}

// syncSplitDNSZones publishes the zones of a fresh user list, then applies watch
// events until the watch ends. Each call relists, so events missed between two
// watches cannot leave the file stale. A failed list returns before writing, so
// the previous zones stay in place.
func syncSplitDNSZones(ctx context.Context, api *olaresUserAPI, publish func([]string)) error {
	resp, err := api.get(ctx, "", 30*time.Second)
	if err != nil {
		return fmt.Errorf("list Olares users: %w", err)
	}
	var list struct {
		Items    []olaresUser `json:"items"`
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("status %d", resp.StatusCode)
	} else {
		err = json.NewDecoder(resp.Body).Decode(&list)
	}
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("list Olares users: %w", err)
	}
	if strings.TrimSpace(list.Metadata.ResourceVersion) == "" {
		return errors.New("list Olares users: missing resourceVersion")
	}
	zones := make(map[string]string, len(list.Items))
	for _, user := range list.Items {
		if strings.TrimSpace(user.Metadata.Name) == "" {
			return errors.New("list Olares users: missing user name")
		}
		zones[user.Metadata.Name] = user.Metadata.Annotations[olaresZoneAnnotation]
	}
	publish(splitDNSZones(zones))

	// The client timeout covers the streamed body, so a silently dropped
	// connection still ends the watch shortly after the server-side timeout.
	resp, err = api.get(ctx, fmt.Sprintf("?watch=1&allowWatchBookmarks=true&timeoutSeconds=%d&resourceVersion=%s",
		splitDNSWatchTimeoutSeconds, neturl.QueryEscape(list.Metadata.ResourceVersion)),
		(splitDNSWatchTimeoutSeconds+30)*time.Second)
	if err != nil {
		return fmt.Errorf("watch Olares users: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("watch Olares users: status %d", resp.StatusCode)
	}
	decoder := json.NewDecoder(resp.Body)
	for {
		var event struct {
			Type   string          `json:"type"`
			Object json.RawMessage `json:"object"`
		}
		if err := decoder.Decode(&event); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read Olares user watch: %w", err)
		}
		if err := applyOlaresUserEvent(zones, event.Type, event.Object); err != nil {
			return err
		}
		publish(splitDNSZones(zones))
	}
}

// applyOlaresUserEvent updates the user-to-zone map. An ERROR event (for example
// 410 Gone for an expired resourceVersion) ends the watch so the caller relists.
func applyOlaresUserEvent(zones map[string]string, eventType string, object json.RawMessage) error {
	switch eventType {
	case "ADDED", "MODIFIED", "DELETED":
	case "ERROR":
		var status struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(object, &status)
		return fmt.Errorf("Olares user watch error: code=%d message=%q", status.Code, status.Message)
	default:
		return nil
	}
	var user olaresUser
	if err := json.Unmarshal(object, &user); err != nil {
		return fmt.Errorf("decode Olares user watch event: %w", err)
	}
	if strings.TrimSpace(user.Metadata.Name) == "" {
		return errors.New("Olares user watch event: missing user name")
	}
	if eventType == "DELETED" {
		delete(zones, user.Metadata.Name)
	} else {
		zones[user.Metadata.Name] = user.Metadata.Annotations[olaresZoneAnnotation]
	}
	return nil
}

// splitDNSZones skips invalid zones so one bad annotation cannot drop every
// other zone. Each DNS label must fit in 63 bytes, with no leading/trailing dash.
func splitDNSZones(zones map[string]string) []string {
	set := make(map[string]struct{}, len(zones))
	for _, zone := range zones {
		zone = strings.ToLower(strings.TrimSpace(zone))
		if validSplitDNSZone(zone) {
			set[zone] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for zone := range set {
		result = append(result, zone)
	}
	sort.Strings(result)
	return result
}

func validSplitDNSZone(zone string) bool {
	if len(zone) > 253 {
		return false
	}
	labels := strings.Split(zone, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) > 63 || !splitDNSLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

// publishSplitDNSZones compares against disk so missing or stale files heal even
// without user events. Empty zones explicitly clear routes without needing an IP.
func publishSplitDNSZones(path, ipPath string, zones []string) error {
	resolvers := make(map[string][]string, len(zones))
	if len(zones) > 0 {
		raw, err := os.ReadFile(ipPath)
		if err != nil {
			return fmt.Errorf("read Tailscale IP: %w", err)
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(string(raw)))
		if err != nil || !addr.Is4() || !addr.IsGlobalUnicast() {
			return errors.New("Tailscale IP file must contain one unicast IPv4 address")
		}
		for _, zone := range zones {
			resolvers[zone] = []string{addr.String()}
		}
	}
	data, err := json.Marshal(resolvers)
	if err != nil {
		return fmt.Errorf("encode split DNS resolvers: %w", err)
	}
	data = append(data, '\n')
	current, err := os.ReadFile(path)
	if err == nil && bytes.Equal(current, data) {
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read split DNS resolvers file: %w", err)
	}
	if err := replaceSplitDNSZonesFile(path, data); err != nil {
		return fmt.Errorf("write split DNS resolvers file: %w", err)
	}
	log.Printf("split DNS resolvers published: zones=%d sha256=%x", len(zones), sha256.Sum256(data))
	return nil
}
