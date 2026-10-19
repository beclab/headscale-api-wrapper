package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/beclab/lldap/clients/go/client"
	resty "github.com/go-resty/resty/v2"
)

const (
	defaultUserSyncInterval = 30 * time.Second
	defaultNATSDurable      = "headscale-users"
	lldapBootstrapAdmin     = "admin"
	natsDriverRetryInterval = 2 * time.Second
)

type userSyncConfig struct {
	readonlyURL string
	interval    time.Duration
	natsURL     string
	natsUser    string
	natsPass    string
	natsStream  string
	natsDurable string
}

type headscaleUserSource struct {
	cfg userSyncConfig
	mu  sync.Mutex
}

type headscaleUser struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// startHeadscaleUserSync validates configuration synchronously, then starts the
// directory synchronization in the background. A temporarily unavailable
// dependency must not prevent the wrapper's HTTP APIs from starting.
func startHeadscaleUserSync(ctx context.Context) error {
	readonlyURL := strings.TrimRight(strings.TrimSpace(os.Getenv("LLDAP_READONLY_URL")), "/")
	if readonlyURL == "" {
		return nil
	}
	interval := defaultUserSyncInterval
	if value := strings.TrimSpace(os.Getenv("HEADSCALE_USER_SYNC_INTERVAL")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil || parsed <= 0 {
			return fmt.Errorf("invalid HEADSCALE_USER_SYNC_INTERVAL %q", value)
		}
		interval = parsed
	}
	stream := strings.TrimSpace(os.Getenv("NATS_STREAM"))
	if stream == "" {
		stream = client.DefaultStreamName
	}
	durable := strings.TrimSpace(os.Getenv("NATS_DURABLE"))
	if durable == "" {
		durable = defaultNATSDurable
	}

	source := &headscaleUserSource{cfg: userSyncConfig{
		readonlyURL: readonlyURL,
		interval:    interval,
		natsURL:     strings.TrimSpace(os.Getenv("NATS_URL")),
		natsUser:    strings.TrimSpace(os.Getenv("NATS_USERNAME")),
		natsPass:    os.Getenv("NATS_PASSWORD"),
		natsStream:  stream,
		natsDurable: durable,
	}}
	go source.startWithRetry(ctx)
	return nil
}

// startWithRetry keeps retrying the initial full reconcile until it succeeds.
// Each attempt remains fail-closed: Start validates the complete snapshot
// before changing Headscale, while a failed attempt only delays synchronization.
func (s *headscaleUserSource) startWithRetry(ctx context.Context) {
	for {
		if err := s.Start(ctx); err == nil {
			return
		} else if ctx.Err() == nil {
			log.Printf("Headscale user sync initialization failed: %v; retrying in %s", err, s.cfg.interval)
		} else {
			return
		}

		if !waitForUserSyncRetry(ctx, s.cfg.interval) {
			return
		}
	}
}

// Start mirrors Router's LldapSource.Start. Init returns the complete initial
// directory as UsersAdded and establishes the SDK baseline used by Run. The
// initial load is a full reconcile (creates + sweep). After that, the NATS
// path applies SDK diffs like Router's applyChanges; the no-NATS path keeps
// doing full snapshot reconciles.
func (s *headscaleUserSource) Start(ctx context.Context) error {
	lldap := client.New(client.Config{BaseURL: s.cfg.readonlyURL})
	changes, err := lldap.Init(ctx, nil, nil)
	if err != nil {
		return fmt.Errorf("initial LLDAP snapshot: %w", err)
	}
	// Empty baseline → the whole directory arrives as UsersAdded. Full
	// reconcile also sweeps Headscale users that vanished while we were down
	// (Init cannot surface those as UsersRemoved).
	if err := s.reconcileSnapshot(ctx, changes.UsersAdded); err != nil {
		return fmt.Errorf("reconcile initial LLDAP users: %w", err)
	}

	if s.cfg.natsURL != "" {
		s.startNATSDriver(ctx, lldap)
	} else {
		s.startResyncDriver(ctx, lldap)
	}
	log.Printf("Headscale user sync ready: nats=%t interval=%s", s.cfg.natsURL != "", s.cfg.interval)
	return nil
}

// startNATSDriver mirrors Router: NATS messages are triggers only; the SDK
// diffs snapshots and delivers Changes to OnChanges. Membership events are
// ignored — Headscale sync only cares about user existence.
func (s *headscaleUserSource) startNATSDriver(ctx context.Context, lldap *client.Client) {
	opts := client.Options{
		NATSURL:        s.cfg.natsURL,
		NATSUser:       s.cfg.natsUser,
		NATSPass:       s.cfg.natsPass,
		Durable:        s.cfg.natsDurable,
		StreamName:     s.cfg.natsStream,
		Subjects:       []string{client.SubjectUsers},
		ResyncInterval: s.cfg.interval,
		OnChanges: func(callbackCtx context.Context, ch client.Changes) error {
			return s.applyChanges(callbackCtx, ch)
		},
	}
	go runNATSDriverWithRetry(ctx, natsDriverRetryInterval, func() error { return lldap.Run(ctx, opts) })
}

func runNATSDriverWithRetry(ctx context.Context, retryInterval time.Duration, run func() error) {
	for ctx.Err() == nil {
		err := run()
		if ctx.Err() != nil {
			return
		}
		log.Printf("Headscale user sync NATS driver stopped: %v; retrying in %s", err, retryInterval)
		if !waitForUserSyncRetry(ctx, retryInterval) {
			return
		}
	}
}

func waitForUserSyncRetry(ctx context.Context, interval time.Duration) bool {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// startResyncDriver is the no-NATS path (same as Router): a local ticker that
// periodically re-fetches the LLDAP snapshot and reconciles Headscale.
func (s *headscaleUserSource) startResyncDriver(ctx context.Context, lldap *client.Client) {
	go func() {
		ticker := time.NewTicker(s.cfg.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				snapshot, err := lldap.Snapshot(ctx)
				if err != nil {
					if ctx.Err() == nil {
						log.Printf("Headscale user sync snapshot failed: %v", err)
					}
					continue
				}
				if err := s.reconcileSnapshot(ctx, snapshot.Users); err != nil && ctx.Err() == nil {
					log.Printf("Headscale user sync reconcile failed: %v", err)
				}
			}
		}
	}()
}

// applyChanges mirrors Router's LldapSource.applyChanges: apply one SDK diff
// idempotently. Returns the first error so client.Run keeps its baseline and
// re-delivers the same diff on the next reconcile.
func (s *headscaleUserSource) applyChanges(ctx context.Context, ch client.Changes) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	needEnsure := len(ch.UsersAdded) > 0 || len(ch.UsersUpdated) > 0
	needRemove := len(ch.UsersRemoved) > 0
	if !needEnsure && !needRemove {
		return nil
	}

	current, err := listHeadscaleUsers(ctx)
	if err != nil {
		return err
	}

	for _, u := range ch.UsersAdded {
		note(s.ensureOneUser(ctx, u.ID, current))
	}
	for _, up := range ch.UsersUpdated {
		note(s.ensureOneUser(ctx, up.New.ID, current))
	}
	// MembersAdded/Removed are intentionally ignored: Headscale has no role
	// projection from lldap_admin membership.

	removed := make([]string, 0, len(ch.UsersRemoved))
	for _, u := range ch.UsersRemoved {
		name := strings.TrimSpace(u.ID)
		if name == "" || name == lldapBootstrapAdmin {
			continue
		}
		removed = append(removed, name)
	}
	if len(removed) > 0 {
		note(s.removeUsersFromCurrent(ctx, removed, current))
	}
	return firstErr
}

func (s *headscaleUserSource) ensureOneUser(ctx context.Context, id string, current map[string]headscaleUser) error {
	name, ok, err := s.syncedName(id)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if _, exists := current[name]; exists {
		return nil
	}
	uid, err := resolveUserIDStringWithCreate(ctx, name, true)
	if err != nil {
		return err
	}
	current[name] = headscaleUser{ID: uid, Name: name}
	log.Printf("Headscale user sync created user: name=%q", name)
	return nil
}

// reconcileSnapshot is the full-set path used for Init and the no-NATS ticker
// (same role as Router's reconcileFromSnapshot / startup sweep).
func (s *headscaleUserSource) reconcileSnapshot(ctx context.Context, users []client.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	desiredUsers, desired, err := s.validateSnapshot(users)
	if err != nil {
		return err
	}
	current, err := listHeadscaleUsers(ctx)
	if err != nil {
		return err
	}
	if err := s.ensureUsers(ctx, desiredUsers, current); err != nil {
		return err
	}
	removed := make([]string, 0)
	for name := range current {
		if name == lldapBootstrapAdmin {
			continue
		}
		if _, exists := desired[name]; exists {
			continue
		}
		removed = append(removed, name)
	}
	return s.removeUsersFromCurrent(ctx, removed, current)
}

func (s *headscaleUserSource) ensureUsers(ctx context.Context, users []client.User, current map[string]headscaleUser) error {
	created := 0
	for _, user := range users {
		name, ok, err := s.syncedName(user.ID)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if _, exists := current[name]; exists {
			continue
		}
		id, err := resolveUserIDStringWithCreate(ctx, name, true)
		if err != nil {
			return err
		}
		current[name] = headscaleUser{ID: id, Name: name}
		created++
	}
	if created > 0 {
		log.Printf("Headscale user sync created users: count=%d", created)
	}
	return nil
}

func (s *headscaleUserSource) removeUsersFromCurrent(ctx context.Context, names []string, current map[string]headscaleUser) error {
	stale := make([]string, 0, len(names))
	for _, name := range names {
		if _, exists := current[name]; exists {
			stale = append(stale, name)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	sort.Strings(stale)

	operationCtx, cancel := context.WithTimeout(ctx, policyOperationTimeout)
	defer cancel()
	select {
	case policyUpdateMu <- struct{}{}:
		defer unlockPolicy()
	case <-operationCtx.Done():
		return fmt.Errorf("wait for policy operation lock: %w", operationCtx.Err())
	}
	if err := removeUsersFromPolicy(operationCtx, stale); err != nil {
		return err
	}
	deletedNodes, err := removeNodesOwnedByUsers(operationCtx, stale)
	if err != nil {
		return err
	}
	for _, name := range stale {
		if err := deleteHeadscaleUser(operationCtx, current[name].ID); err != nil {
			return fmt.Errorf("delete synchronized user %q: %w", name, err)
		}
	}
	log.Printf("Headscale user sync deleted users: users=%d nodes=%d", len(stale), deletedNodes)
	return nil
}

func (s *headscaleUserSource) syncedName(id string) (string, bool, error) {
	name := strings.TrimSpace(id)
	if name == "" {
		return "", false, errors.New("LLDAP snapshot contains an empty user id")
	}
	if name != id {
		return "", false, fmt.Errorf("LLDAP user id %q contains surrounding whitespace", id)
	}
	if name == lldapBootstrapAdmin {
		return "", false, nil
	}
	// Do not let one unsupported directory name block syncing everyone else.
	// validateSnapshot still records the name as desired so an existing matching
	// Headscale user is preserved rather than mistaken for a deleted account.
	if err := validatePolicyUsername(name); err != nil {
		log.Printf("Headscale user sync will not create unsupported LLDAP user id %q: %v", name, err)
		return "", false, nil
	}
	return name, true, nil
}

func (s *headscaleUserSource) validateSnapshot(users []client.User) ([]client.User, map[string]struct{}, error) {
	seen := make(map[string]struct{}, len(users))
	desired := make(map[string]struct{}, len(users))
	filtered := make([]client.User, 0, len(users))
	hasAdmin := false
	for _, user := range users {
		name := strings.TrimSpace(user.ID)
		if name == "" {
			return nil, nil, errors.New("LLDAP snapshot contains an empty user id")
		}
		if name != user.ID {
			return nil, nil, fmt.Errorf("LLDAP user id %q contains surrounding whitespace", user.ID)
		}
		if _, exists := seen[name]; exists {
			return nil, nil, fmt.Errorf("LLDAP snapshot contains duplicate user id %q", name)
		}
		seen[name] = struct{}{}
		if name == lldapBootstrapAdmin {
			hasAdmin = true
			continue
		}
		// Directory presence protects an existing Headscale identity from
		// deletion even when its name cannot safely be represented in policy.
		desired[name] = struct{}{}
		synced, ok, err := s.syncedName(name)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			continue
		}
		user.ID = synced
		filtered = append(filtered, user)
	}
	if !hasAdmin {
		return nil, nil, errors.New("LLDAP snapshot is missing the built-in admin user")
	}
	return filtered, desired, nil
}

func listHeadscaleUsers(ctx context.Context) (map[string]headscaleUser, error) {
	var result struct {
		Users []headscaleUser `json:"users"`
	}
	resp, err := resty.New().SetTimeout(downstreamTimeout).R().SetContext(ctx).SetHeaders(headers).
		SetResult(&result).Get(url + "/user")
	if err != nil {
		return nil, restyRequestError("list users for synchronization", err)
	}
	if resp == nil || resp.StatusCode() != http.StatusOK {
		return nil, restyResponseError("list users for synchronization", resp)
	}
	users := make(map[string]headscaleUser, len(result.Users))
	for _, user := range result.Users {
		users[user.Name] = user
	}
	return users, nil
}

func deleteHeadscaleUser(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("refusing to delete a Headscale user with an empty id")
	}
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		return fmt.Errorf("refusing to delete a Headscale user with invalid id %q: %w", id, err)
	}
	resp, err := resty.New().SetTimeout(downstreamTimeout).R().SetContext(ctx).SetHeaders(headers).
		Delete(url + "/user/" + neturl.PathEscape(id))
	if err != nil {
		return restyRequestError("delete synchronized user", err)
	}
	if resp == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
		return restyResponseError("delete synchronized user", resp)
	}
	return nil
}

func removeNodesOwnedByUsers(ctx context.Context, users []string) (int, error) {
	targets := make(map[string]struct{}, len(users))
	for _, user := range users {
		targets[user] = struct{}{}
	}
	nodes, err := listDevices(ctx)
	if err != nil {
		return 0, fmt.Errorf("list nodes for synchronized-user removal: %w", err)
	}
	ids := make([]string, 0)
	for _, raw := range nodes.Nodes {
		var node nodeIdentity
		if err := json.Unmarshal(raw, &node); err != nil {
			return 0, fmt.Errorf("decode node for synchronized-user removal: %w", err)
		}
		if _, remove := targets[node.User.Name]; remove {
			ids = append(ids, node.ID)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		if _, err := removeDevice(ctx, id); err != nil {
			return 0, fmt.Errorf("delete node %q for removed synchronized user: %w", id, err)
		}
	}
	return len(ids), nil
}

func removeUsersFromPolicy(ctx context.Context, users []string) error {
	policy, err := getHeadscalePolicy(ctx)
	if err != nil {
		return err
	}
	document, err := parsePolicyDocument([]byte(policy.Policy))
	if err != nil {
		return err
	}
	changed := false
	for _, user := range users {
		changed = document.removeUserReferences(user) || changed
	}
	if !changed {
		return nil
	}
	encoded, err := document.marshal()
	if err != nil {
		return err
	}
	return setHeadscalePolicy(ctx, string(encoded))
}

func (p *policyDocument) removeUserReferences(username string) bool {
	alias := username + "@"
	changed := false
	retainedACLs := make([]policyACL, 0, len(p.ACLs))
	for _, acl := range p.ACLs {
		var srcChanged, dstChanged bool
		acl.Src, srcChanged = removeString(acl.Src, alias)
		acl.Dst, dstChanged = removeString(acl.Dst, alias)
		changed = changed || srcChanged || dstChanged
		if (srcChanged || dstChanged) && (len(acl.Src) == 0 || len(acl.Dst) == 0) {
			continue
		}
		retainedACLs = append(retainedACLs, acl)
	}
	p.ACLs = retainedACLs
	for key, raw := range p.fields {
		if key == "acls" {
			continue
		}
		var value interface{}
		if err := json.Unmarshal(raw, &value); err != nil {
			continue
		}
		updated, fieldChanged := removeAliasValue(value, alias)
		if !fieldChanged {
			continue
		}
		encoded, err := json.Marshal(updated)
		if err != nil {
			continue
		}
		p.fields[key] = encoded
		changed = true
	}
	return changed
}

func removeAliasValue(value interface{}, alias string) (interface{}, bool) {
	switch typed := value.(type) {
	case []interface{}:
		result := make([]interface{}, 0, len(typed))
		changed := false
		for _, item := range typed {
			if text, ok := item.(string); ok && isUserAliasReference(text, alias) {
				changed = true
				continue
			}
			updated, itemChanged := removeAliasValue(item, alias)
			changed = changed || itemChanged
			result = append(result, updated)
		}
		return result, changed
	case map[string]interface{}:
		changed := false
		for key, item := range typed {
			updated, itemChanged := removeAliasValue(item, alias)
			if itemChanged {
				typed[key] = updated
				changed = true
			}
		}
		return typed, changed
	default:
		return value, false
	}
}

func removeString(values []string, target string) ([]string, bool) {
	result := values[:0]
	changed := false
	for _, value := range values {
		if isUserAliasReference(value, target) {
			changed = true
			continue
		}
		result = append(result, value)
	}
	return result, changed
}

func isUserAliasReference(value, alias string) bool {
	return value == alias || strings.HasPrefix(value, alias+":")
}
