package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"
	resty "github.com/go-resty/resty/v2"
	"github.com/tailscale/hujson"
)

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
	ApplicationPorts []userProtocolPorts `json:"applicationPorts"`
}

type headscalePolicyResponse struct {
	Policy string `json:"policy"`
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
	cancel := beginPolicyOperation(c)
	defer cancel()
	if !lockPolicy(c) {
		return
	}
	defer unlockPolicy()

	state, err := readApplicationPorts(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, response{Code: requestHeadscaleError, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response{Code: 0, Message: "", Data: state})
}

func putApplicationPorts(c *gin.Context) {
	cancel := beginPolicyOperation(c)
	defer cancel()
	var request applicationPortsRequest
	if !bindJSON(c, &request, 1<<20) {
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
	if !lockPolicy(c) {
		return
	}
	defer unlockPolicy()

	policy, err := getHeadscalePolicy(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, response{Code: requestHeadscaleError, Message: err.Error()})
		return
	}
	document, err := parsePolicyDocument([]byte(policy.Policy))
	if err != nil {
		c.JSON(http.StatusInternalServerError, response{Code: requestHeadscaleError, Message: err.Error()})
		return
	}

	before, err := document.marshal()
	if err != nil {
		c.JSON(http.StatusInternalServerError, response{Code: requestHeadscaleError, Message: err.Error()})
		return
	}
	document.setManagedApplicationPorts(requested)
	after, err := document.marshal()
	if err != nil {
		c.JSON(http.StatusInternalServerError, response{Code: requestHeadscaleError, Message: err.Error()})
		return
	}
	changed := !bytes.Equal(before, after)
	if changed {
		// Headscale resolves user aliases while validating the policy. Ensure each
		// real Olares owner has a corresponding Headscale user before referencing
		// owner@. User creation alone grants no network access.
		for _, entry := range requested {
			if _, err := resolveUserIDString(c.Request.Context(), entry.User); err != nil {
				c.JSON(http.StatusBadGateway, response{Code: requestHeadscaleError, Message: fmt.Sprintf("ensure Headscale user %q: %v", entry.User, err)})
				return
			}
		}
		err = setHeadscalePolicy(c.Request.Context(), string(after))
		if err != nil {
			c.JSON(http.StatusBadGateway, response{Code: requestHeadscaleError, Message: err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, response{Code: 0, Message: "", Data: struct{}{}})
	logMutation(c, "application-ports.put", changed, fmt.Sprintf("users=%d", len(requested)))
}

func readApplicationPorts(ctx context.Context) (applicationPortsState, error) {
	policy, err := getHeadscalePolicy(ctx)
	if err != nil {
		return applicationPortsState{}, err
	}
	document, err := parsePolicyDocument([]byte(policy.Policy))
	if err != nil {
		return applicationPortsState{}, err
	}
	application, err := document.managedApplicationPorts()
	if err != nil {
		return applicationPortsState{}, err
	}
	return applicationPortsState{
		ApplicationPorts: application,
	}, nil
}

func getHeadscalePolicy(ctx context.Context) (headscalePolicyResponse, error) {
	var result headscalePolicyResponse
	resp, err := resty.New().SetTimeout(downstreamTimeout).R().SetContext(ctx).
		SetHeaders(headers).
		SetResult(&result).
		Get(url + "/policy")
	if err != nil {
		return result, restyRequestError("get Headscale policy", err)
	}
	if resp == nil || resp.StatusCode() != http.StatusOK {
		return result, restyResponseError("get Headscale policy", resp)
	}
	if strings.TrimSpace(result.Policy) == "" {
		return result, errors.New("Headscale returned an empty policy")
	}
	return result, nil
}

func setHeadscalePolicy(ctx context.Context, policy string) error {
	resp, err := resty.New().SetTimeout(downstreamTimeout).R().SetContext(ctx).
		SetHeaders(headers).
		SetBody(map[string]string{"policy": policy}).
		Put(url + "/policy")
	if err != nil {
		return restyRequestError("set Headscale policy", err)
	}
	if resp == nil || resp.StatusCode() != http.StatusOK {
		return restyResponseError("set Headscale policy", resp)
	}
	return nil
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

func (p *policyDocument) managedApplicationPorts() ([]userProtocolPorts, error) {
	byUser := make(map[string]protocolPorts)
	for _, acl := range p.ACLs {
		user, proto, managed := managedUserRule(acl)
		if !managed {
			continue
		}
		ports, err := portsFromDestinations(acl.Dst, user+" "+proto)
		if err != nil {
			return nil, err
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
			return nil, fmt.Errorf("invalid managed ports for user %q: %w", user, err)
		}
		application = append(application, userProtocolPorts{User: user, protocolPorts: normalized})
	}
	application, err := normalizeUserProtocolPorts(application)
	return application, err
}

func (p *policyDocument) setManagedApplicationPorts(application []userProtocolPorts) {
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
		return errors.New("policy username is empty")
	}
	if strings.ContainsAny(user, "@:") || strings.IndexFunc(user, unicode.IsSpace) >= 0 {
		return fmt.Errorf("policy username %q is not a valid Headscale username", user)
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
