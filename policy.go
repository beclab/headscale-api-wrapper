package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	resty "github.com/go-resty/resty/v2"
	"github.com/tailscale/hujson"
)

var defaultApplicationServicePorts = protocolPorts{
	TCP: []string{"53", "80", "443", "18088"},
	UDP: []string{"53"},
}

type protocolPorts struct {
	TCP []string `json:"tcp"`
	UDP []string `json:"udp"`
}

type userProtocolPorts struct {
	User string `json:"user"`
	protocolPorts
}

type applicationPortsRequest struct {
	ApplicationPorts *[]userProtocolPorts `json:"applicationPorts"`
}

type applicationPortsState struct {
	DefaultPorts     protocolPorts       `json:"defaultPorts"`
	ApplicationPorts []userProtocolPorts `json:"applicationPorts"`
	EffectivePorts   []userProtocolPorts `json:"effectivePorts"`
	Revision         string              `json:"revision"`
	UpdatedAt        string              `json:"updatedAt,omitempty"`
	InSync           bool                `json:"inSync"`
	Changed          bool                `json:"changed,omitempty"`
}

type headscalePolicyResponse struct {
	Policy    string `json:"policy"`
	UpdatedAt string `json:"updatedAt"`
}

// policyACL retains unknown fields so upgrading Headscale cannot cause a
// read-modify-write to silently strip fields owned by a newer policy schema.
type policyACL struct {
	fields map[string]json.RawMessage
	Action string
	Src    []string
	Proto  string
	Dst    []string
}

func (acl *policyACL) UnmarshalJSON(data []byte) error {
	fields := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	type knownACL struct {
		Action string   `json:"action"`
		Src    []string `json:"src"`
		Proto  string   `json:"proto,omitempty"`
		Dst    []string `json:"dst"`
	}
	var known knownACL
	if err := json.Unmarshal(data, &known); err != nil {
		return err
	}
	acl.fields = fields
	acl.Action = known.Action
	acl.Src = known.Src
	acl.Proto = known.Proto
	acl.Dst = known.Dst
	return nil
}

func (acl policyACL) MarshalJSON() ([]byte, error) {
	fields := make(map[string]json.RawMessage, len(acl.fields))
	for key, value := range acl.fields {
		fields[key] = value
	}
	set := func(key string, value interface{}) error {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		fields[key] = encoded
		return nil
	}
	if err := set("action", acl.Action); err != nil {
		return nil, err
	}
	if err := set("src", acl.Src); err != nil {
		return nil, err
	}
	if acl.Proto == "" {
		delete(fields, "proto")
	} else if err := set("proto", acl.Proto); err != nil {
		return nil, err
	}
	if err := set("dst", acl.Dst); err != nil {
		return nil, err
	}
	return json.Marshal(fields)
}

type policyDocument struct {
	fields map[string]json.RawMessage
	ACLs   []policyACL
}

func getApplicationPorts(c *gin.Context) {
	policyUpdateMu.Lock()
	defer policyUpdateMu.Unlock()

	state, err := readApplicationPorts()
	if err != nil {
		c.JSON(http.StatusInternalServerError, response{Code: requestHeadscaleError, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response{Code: 0, Message: "", Data: state})
}

func putApplicationPorts(c *gin.Context) {
	var request applicationPortsRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, response{Code: requestHeadscaleError, Message: err.Error()})
		return
	}
	if request.ApplicationPorts == nil {
		c.JSON(http.StatusBadRequest, response{Code: requestHeadscaleError, Message: "applicationPorts must be an array"})
		return
	}
	requested, err := normalizeUserProtocolPorts(*request.ApplicationPorts)
	if err != nil {
		c.JSON(http.StatusBadRequest, response{Code: requestHeadscaleError, Message: err.Error()})
		return
	}
	if err := rejectWildcardApplicationPorts(requested); err != nil {
		c.JSON(http.StatusBadRequest, response{Code: requestHeadscaleError, Message: err.Error()})
		return
	}
	requested = subtractUserDefaultPorts(requested, defaultApplicationServicePorts)

	policyUpdateMu.Lock()
	defer policyUpdateMu.Unlock()

	current, document, err := loadApplicationPorts()
	if err != nil {
		c.JSON(http.StatusInternalServerError, response{Code: requestHeadscaleError, Message: err.Error()})
		return
	}

	changed := !current.InSync || !userProtocolPortsEqual(current.ApplicationPorts, requested)
	if changed {
		// Headscale resolves user aliases while validating the policy. Ensure each
		// real Olares owner has a corresponding Headscale user before referencing
		// owner@. User creation alone grants no network access.
		for _, entry := range requested {
			if _, err := resolveUserIDString(entry.User); err != nil {
				c.JSON(http.StatusBadGateway, response{Code: requestHeadscaleError, Message: fmt.Sprintf("ensure Headscale user %q: %v", entry.User, err)})
				return
			}
		}
		if err := document.setManagedApplicationPorts(defaultApplicationServicePorts, requested); err != nil {
			c.JSON(http.StatusConflict, response{Code: requestHeadscaleError, Message: err.Error()})
			return
		}
		encoded, err := document.marshal()
		if err != nil {
			c.JSON(http.StatusInternalServerError, response{Code: requestHeadscaleError, Message: err.Error()})
			return
		}
		updatedAt, err := setHeadscalePolicy(string(encoded))
		if err != nil {
			c.JSON(http.StatusBadGateway, response{Code: requestHeadscaleError, Message: err.Error()})
			return
		}
		current.UpdatedAt = updatedAt
	}

	current.DefaultPorts = cloneProtocolPorts(defaultApplicationServicePorts)
	current.ApplicationPorts = requested
	current.EffectivePorts = effectiveUserPorts(current.DefaultPorts, requested)
	current.Revision = userProtocolPortsRevision(requested)
	current.InSync = true
	current.Changed = changed
	c.JSON(http.StatusOK, response{Code: 0, Message: "", Data: current})
}

func readApplicationPorts() (applicationPortsState, error) {
	state, _, err := loadApplicationPorts()
	return state, err
}

func loadApplicationPorts() (applicationPortsState, *policyDocument, error) {
	policy, err := getHeadscalePolicy()
	if err != nil {
		return applicationPortsState{}, nil, err
	}
	document, err := parsePolicyDocument([]byte(policy.Policy))
	if err != nil {
		return applicationPortsState{}, nil, err
	}
	policyDefaults, application, err := document.managedApplicationPorts()
	if err != nil {
		return applicationPortsState{}, nil, err
	}
	defaults := cloneProtocolPorts(defaultApplicationServicePorts)
	return applicationPortsState{
		DefaultPorts:     defaults,
		ApplicationPorts: application,
		EffectivePorts:   effectiveUserPorts(defaults, application),
		Revision:         userProtocolPortsRevision(application),
		UpdatedAt:        policy.UpdatedAt,
		InSync: protocolPortsEqual(policyDefaults, defaults) &&
			document.applicationRulesCanonical(application),
	}, document, nil
}

func getHeadscalePolicy() (headscalePolicyResponse, error) {
	var result headscalePolicyResponse
	resp, err := resty.New().SetTimeout(10 * time.Second).R().
		SetHeaders(headers).
		SetResult(&result).
		Get(url + "/policy")
	if err != nil {
		return result, fmt.Errorf("get Headscale policy: %w", err)
	}
	if resp.StatusCode() != http.StatusOK {
		return result, fmt.Errorf("get Headscale policy: status %d: %s", resp.StatusCode(), resp.String())
	}
	if strings.TrimSpace(result.Policy) == "" {
		return result, errors.New("Headscale returned an empty policy")
	}
	return result, nil
}

func setHeadscalePolicy(policy string) (string, error) {
	var result headscalePolicyResponse
	resp, err := resty.New().SetTimeout(10 * time.Second).R().
		SetHeaders(headers).
		SetBody(map[string]string{"policy": policy}).
		SetResult(&result).
		Put(url + "/policy")
	if err != nil {
		return "", fmt.Errorf("set Headscale policy: %w", err)
	}
	if resp.StatusCode() != http.StatusOK {
		return "", fmt.Errorf("set Headscale policy: status %d: %s", resp.StatusCode(), resp.String())
	}
	return result.UpdatedAt, nil
}

func parsePolicyDocument(policy []byte) (*policyDocument, error) {
	standard, err := hujson.Standardize(policy)
	if err != nil {
		return nil, fmt.Errorf("parse Headscale HuJSON policy: %w", err)
	}
	fields := make(map[string]json.RawMessage)
	if err := json.Unmarshal(standard, &fields); err != nil {
		return nil, fmt.Errorf("decode Headscale policy: %w", err)
	}
	rawACLs, ok := fields["acls"]
	if !ok {
		return nil, errors.New("Headscale policy has no acls field")
	}
	var acls []policyACL
	if err := json.Unmarshal(rawACLs, &acls); err != nil {
		return nil, fmt.Errorf("decode Headscale policy acls: %w", err)
	}
	return &policyDocument{fields: fields, ACLs: acls}, nil
}

func (p *policyDocument) marshal() ([]byte, error) {
	acls, err := json.Marshal(p.ACLs)
	if err != nil {
		return nil, fmt.Errorf("encode Headscale policy acls: %w", err)
	}
	p.fields["acls"] = acls
	encoded, err := json.MarshalIndent(p.fields, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode Headscale policy: %w", err)
	}
	return encoded, nil
}

func (p *policyDocument) managedApplicationPorts() (protocolPorts, []userProtocolPorts, error) {
	tcpIndex, udpIndex, err := p.defaultRuleIndexes()
	if err != nil {
		return protocolPorts{}, nil, err
	}
	tcp, err := portsFromDestinations(p.ACLs[tcpIndex].Dst, "default TCP")
	if err != nil {
		return protocolPorts{}, nil, err
	}
	udp, err := portsFromDestinations(p.ACLs[udpIndex].Dst, "default UDP")
	if err != nil {
		return protocolPorts{}, nil, err
	}
	defaults, err := normalizeProtocolPorts(protocolPorts{TCP: tcp, UDP: udp})
	if err != nil {
		return protocolPorts{}, nil, err
	}

	byUser := make(map[string]protocolPorts)
	for _, acl := range p.ACLs {
		user, proto, managed := managedUserRule(acl)
		if !managed {
			continue
		}
		ports, err := portsFromDestinations(acl.Dst, user+" "+proto)
		if err != nil {
			return protocolPorts{}, nil, err
		}
		entry := byUser[user]
		if proto == "tcp" {
			entry.TCP = append(entry.TCP, ports...)
		} else {
			entry.UDP = append(entry.UDP, ports...)
		}
		byUser[user] = entry
	}
	application := make([]userProtocolPorts, 0, len(byUser))
	for user, ports := range byUser {
		normalized, err := normalizeProtocolPorts(ports)
		if err != nil {
			return protocolPorts{}, nil, fmt.Errorf("invalid managed ports for user %q: %w", user, err)
		}
		application = append(application, userProtocolPorts{User: user, protocolPorts: normalized})
	}
	application, err = normalizeUserProtocolPorts(application)
	return defaults, application, err
}

func (p *policyDocument) setManagedApplicationPorts(defaults protocolPorts, application []userProtocolPorts) error {
	tcpIndex, udpIndex, err := p.defaultRuleIndexes()
	if err != nil {
		return err
	}
	p.ACLs[tcpIndex].Dst = []string{"tag:olares:" + strings.Join(defaults.TCP, ",")}
	p.ACLs[udpIndex].Dst = []string{"tag:olares:" + strings.Join(defaults.UDP, ",")}

	retained := make([]policyACL, 0, len(p.ACLs)+len(application)*2)
	for _, acl := range p.ACLs {
		if _, _, managed := managedUserRule(acl); managed {
			continue
		}
		retained = append(retained, acl)
	}
	for _, entry := range application {
		if len(entry.TCP) > 0 {
			retained = append(retained, newManagedUserACL(entry.User, "tcp", entry.TCP))
		}
		if len(entry.UDP) > 0 {
			retained = append(retained, newManagedUserACL(entry.User, "udp", entry.UDP))
		}
	}
	p.ACLs = retained
	return nil
}

func (p *policyDocument) applicationRulesCanonical(application []userProtocolPorts) bool {
	expected := make(map[string]string)
	for _, entry := range application {
		if len(entry.TCP) > 0 {
			expected[entry.User+"\x00tcp"] = strings.Join(entry.TCP, ",")
		}
		if len(entry.UDP) > 0 {
			expected[entry.User+"\x00udp"] = strings.Join(entry.UDP, ",")
		}
	}
	actual := make(map[string]string)
	for _, acl := range p.ACLs {
		user, proto, managed := managedUserRule(acl)
		if !managed {
			continue
		}
		key := user + "\x00" + proto
		if _, duplicate := actual[key]; duplicate {
			return false
		}
		ports, err := portsFromDestinations(acl.Dst, user+" "+proto)
		if err != nil {
			return false
		}
		actual[key] = strings.Join(ports, ",")
	}
	if len(actual) != len(expected) {
		return false
	}
	for key, ports := range expected {
		if actual[key] != ports {
			return false
		}
	}
	return true
}

func (p *policyDocument) defaultRuleIndexes() (int, int, error) {
	tcpIndex, udpIndex := -1, -1
	for i, acl := range p.ACLs {
		if acl.Action != "accept" || len(acl.Src) != 1 || acl.Src[0] != "autogroup:member" || len(acl.Dst) != 1 || !strings.HasPrefix(acl.Dst[0], "tag:olares:") {
			continue
		}
		switch strings.ToLower(acl.Proto) {
		case "tcp":
			if tcpIndex != -1 {
				return -1, -1, errors.New("Headscale policy has multiple managed default TCP service rules")
			}
			tcpIndex = i
		case "udp":
			if udpIndex != -1 {
				return -1, -1, errors.New("Headscale policy has multiple managed default UDP service rules")
			}
			udpIndex = i
		}
	}
	if tcpIndex == -1 || udpIndex == -1 {
		return -1, -1, errors.New("Headscale policy is missing the managed default TCP or UDP service rule")
	}
	return tcpIndex, udpIndex, nil
}

func managedUserRule(acl policyACL) (string, string, bool) {
	if acl.Action != "accept" || len(acl.Src) != 1 || len(acl.Dst) != 1 || !strings.HasPrefix(acl.Dst[0], "tag:olares:") {
		return "", "", false
	}
	source := acl.Src[0]
	if !strings.HasSuffix(source, "@") || strings.HasPrefix(source, "autogroup:") {
		return "", "", false
	}
	proto := strings.ToLower(acl.Proto)
	if proto != "tcp" && proto != "udp" {
		return "", "", false
	}
	user := strings.TrimSuffix(source, "@")
	if validatePolicyUsername(user) != nil {
		return "", "", false
	}
	return user, proto, true
}

func newManagedUserACL(user, proto string, ports []string) policyACL {
	return policyACL{
		Action: "accept",
		Src:    []string{user + "@"},
		Proto:  proto,
		Dst:    []string{"tag:olares:" + strings.Join(ports, ",")},
	}
}

func portsFromDestinations(destinations []string, description string) ([]string, error) {
	if len(destinations) != 1 {
		return nil, fmt.Errorf("managed %s service rule must have exactly one destination", description)
	}
	const prefix = "tag:olares:"
	if !strings.HasPrefix(destinations[0], prefix) {
		return nil, fmt.Errorf("managed %s service rule has an unexpected destination", description)
	}
	value := strings.TrimPrefix(destinations[0], prefix)
	if value == "" {
		return nil, fmt.Errorf("managed %s service rule has no ports", description)
	}
	return strings.Split(value, ","), nil
}

func normalizeUserProtocolPorts(entries []userProtocolPorts) ([]userProtocolPorts, error) {
	byUser := make(map[string]protocolPorts)
	for _, entry := range entries {
		user := strings.TrimSpace(entry.User)
		if err := validatePolicyUsername(user); err != nil {
			return nil, err
		}
		ports, err := normalizeProtocolPorts(entry.protocolPorts)
		if err != nil {
			return nil, fmt.Errorf("invalid ports for user %q: %w", user, err)
		}
		current := byUser[user]
		current.TCP = append(current.TCP, ports.TCP...)
		current.UDP = append(current.UDP, ports.UDP...)
		byUser[user] = current
	}
	result := make([]userProtocolPorts, 0, len(byUser))
	for user, ports := range byUser {
		normalized, _ := normalizeProtocolPorts(ports)
		if len(normalized.TCP) == 0 && len(normalized.UDP) == 0 {
			continue
		}
		result = append(result, userProtocolPorts{User: user, protocolPorts: normalized})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].User < result[j].User })
	return result, nil
}

func rejectWildcardApplicationPorts(entries []userProtocolPorts) error {
	for _, entry := range entries {
		for _, port := range append(append([]string{}, entry.TCP...), entry.UDP...) {
			if port == "*" {
				return fmt.Errorf("application ports for user %q must not include wildcard ports", entry.User)
			}
		}
	}
	return nil
}

func validatePolicyUsername(user string) error {
	if user == "" {
		return errors.New("application port owner is empty")
	}
	if strings.ContainsAny(user, "@:") || strings.IndexFunc(user, unicode.IsSpace) >= 0 {
		return fmt.Errorf("application port owner %q is not a valid Headscale username", user)
	}
	return nil
}

func normalizeProtocolPorts(ports protocolPorts) (protocolPorts, error) {
	tcp, err := normalizePorts(ports.TCP)
	if err != nil {
		return protocolPorts{}, fmt.Errorf("invalid TCP ports: %w", err)
	}
	udp, err := normalizePorts(ports.UDP)
	if err != nil {
		return protocolPorts{}, fmt.Errorf("invalid UDP ports: %w", err)
	}
	return protocolPorts{TCP: tcp, UDP: udp}, nil
}

func normalizePorts(ports []string) ([]string, error) {
	set := make(map[string]struct{})
	for _, group := range ports {
		for _, raw := range strings.Split(group, ",") {
			port, err := normalizePortSpec(raw)
			if err != nil {
				return nil, err
			}
			if port == "*" {
				return []string{"*"}, nil
			}
			set[port] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for port := range set {
		result = append(result, port)
	}
	sort.Slice(result, func(i, j int) bool {
		leftStart, leftEnd := portSpecBounds(result[i])
		rightStart, rightEnd := portSpecBounds(result[j])
		if leftStart == rightStart {
			return leftEnd < rightEnd
		}
		return leftStart < rightStart
	})
	return result, nil
}

func normalizePortSpec(raw string) (string, error) {
	port := strings.TrimSpace(raw)
	if port == "" {
		return "", errors.New("empty port")
	}
	if port == "*" {
		return port, nil
	}
	parts := strings.Split(port, "-")
	if len(parts) > 2 || len(parts) == 2 && (parts[0] == "" || parts[1] == "") {
		return "", fmt.Errorf("%q must be a port or inclusive port range", port)
	}
	first, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil || first == 0 {
		return "", fmt.Errorf("%q must contain ports between 1 and 65535", port)
	}
	if len(parts) == 1 {
		return strconv.FormatUint(first, 10), nil
	}
	last, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil || last == 0 || first > last {
		return "", fmt.Errorf("%q must be an increasing port range between 1 and 65535", port)
	}
	return strconv.FormatUint(first, 10) + "-" + strconv.FormatUint(last, 10), nil
}

func portSpecBounds(spec string) (int, int) {
	parts := strings.Split(spec, "-")
	first, _ := strconv.Atoi(parts[0])
	if len(parts) == 1 {
		return first, first
	}
	last, _ := strconv.Atoi(parts[1])
	return first, last
}

func subtractUserDefaultPorts(entries []userProtocolPorts, defaults protocolPorts) []userProtocolPorts {
	result := make([]userProtocolPorts, 0, len(entries))
	for _, entry := range entries {
		ports := subtractProtocolPorts(entry.protocolPorts, defaults)
		if len(ports.TCP) == 0 && len(ports.UDP) == 0 {
			continue
		}
		result = append(result, userProtocolPorts{User: entry.User, protocolPorts: ports})
	}
	return result
}

func effectiveUserPorts(defaults protocolPorts, entries []userProtocolPorts) []userProtocolPorts {
	result := make([]userProtocolPorts, 0, len(entries))
	for _, entry := range entries {
		result = append(result, userProtocolPorts{User: entry.User, protocolPorts: mergeProtocolPorts(defaults, entry.protocolPorts)})
	}
	return result
}

func mergeProtocolPorts(left, right protocolPorts) protocolPorts {
	merged, _ := normalizeProtocolPorts(protocolPorts{
		TCP: append(append([]string{}, left.TCP...), right.TCP...),
		UDP: append(append([]string{}, left.UDP...), right.UDP...),
	})
	return merged
}

func subtractProtocolPorts(all, remove protocolPorts) protocolPorts {
	return protocolPorts{
		TCP: subtractPorts(all.TCP, remove.TCP),
		UDP: subtractPorts(all.UDP, remove.UDP),
	}
}

func subtractPorts(all, remove []string) []string {
	removed := make(map[string]struct{}, len(remove))
	for _, port := range remove {
		removed[port] = struct{}{}
	}
	result := make([]string, 0, len(all))
	for _, port := range all {
		if _, ok := removed[port]; !ok {
			result = append(result, port)
		}
	}
	return result
}

func cloneProtocolPorts(ports protocolPorts) protocolPorts {
	return protocolPorts{TCP: append([]string(nil), ports.TCP...), UDP: append([]string(nil), ports.UDP...)}
}

func protocolPortsEqual(left, right protocolPorts) bool {
	return strings.Join(left.TCP, ",") == strings.Join(right.TCP, ",") && strings.Join(left.UDP, ",") == strings.Join(right.UDP, ",")
}

func userProtocolPortsEqual(left, right []userProtocolPorts) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].User != right[i].User || !protocolPortsEqual(left[i].protocolPorts, right[i].protocolPorts) {
			return false
		}
	}
	return true
}

func userProtocolPortsRevision(ports []userProtocolPorts) string {
	encoded, _ := json.Marshal(ports)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}
