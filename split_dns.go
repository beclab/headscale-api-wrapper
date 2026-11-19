package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	olaresZoneAnnotation        = "bytetrade.io/zone"
	splitDNSWatchTimeoutSeconds = 300
	splitDNSRetryInterval       = time.Second
)

var replaceSplitDNSZonesFile = replaceFile

var splitDNSLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

// startSplitDNSZoneSync keeps SPLIT_DNS_ZONES_FILE equal to the split DNS zones
// Headscale must route to the shared node, one per line. It uses the same rules
// as the render-dns-config initContainer: OLARES_DNS_ZONE (the Pod annotation)
// wins, otherwise every Olares user's zone annotation is used.
func startSplitDNSZoneSync(ctx context.Context) error {
	path := strings.TrimSpace(os.Getenv("SPLIT_DNS_ZONES_FILE"))
	if path == "" {
		return nil
	}
	var globalZones []string
	if global := os.Getenv("OLARES_DNS_ZONE"); global != "" {
		zones, err := parseGlobalSplitDNSZones(global)
		if err != nil {
			return err
		}
		globalZones = zones
	}

	go func() {
		for ctx.Err() == nil {
			var err error
			if globalZones != nil {
				if err = publishSplitDNSZones(path, globalZones); err == nil {
					return
				}
			} else {
				var api *olaresUserAPI
				if api, err = newOlaresUserAPI(); err == nil {
					err = syncSplitDNSZones(ctx, api, path)
					api.transport.CloseIdleConnections()
				}
			}
			if err != nil && ctx.Err() == nil {
				log.Printf("split DNS zone sync failed: %v; retrying in %s", err, splitDNSRetryInterval)
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
func syncSplitDNSZones(ctx context.Context, api *olaresUserAPI, path string) error {
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
	if err := publishSplitDNSZones(path, splitDNSZones(zones)); err != nil {
		return err
	}

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
		if err := publishSplitDNSZones(path, splitDNSZones(zones)); err != nil {
			return err
		}
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

// parseGlobalSplitDNSZones rejects any invalid entry, like the initContainer,
// because a partly wrong global zone is a configuration error.
func parseGlobalSplitDNSZones(value string) ([]string, error) {
	zones := map[string]string{}
	for _, item := range strings.Split(value, ",") {
		zone := strings.ToLower(strings.TrimSpace(item))
		if zone == "" {
			continue
		}
		if !validSplitDNSZone(zone) {
			return nil, fmt.Errorf("invalid OLARES_DNS_ZONE entry %q", item)
		}
		zones[zone] = zone
	}
	if len(zones) == 0 {
		return nil, errors.New("OLARES_DNS_ZONE has no zones")
	}
	return splitDNSZones(zones), nil
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

// publishSplitDNSZones rewrites the file only when the zone set changed; most
// user updates (status, avatar, entrance IP) do not touch the zone annotation.
func publishSplitDNSZones(path string, zones []string) error {
	var data []byte
	if len(zones) > 0 {
		data = []byte(strings.Join(zones, "\n") + "\n")
	}
	current, err := os.ReadFile(path)
	if err == nil && bytes.Equal(current, data) {
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read split DNS zones file: %w", err)
	}
	if err := replaceSplitDNSZonesFile(path, data); err != nil {
		return fmt.Errorf("write split DNS zones file: %w", err)
	}
	log.Printf("split DNS zones updated: zones=%q", zones)
	return nil
}
