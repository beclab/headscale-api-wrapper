package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

const subnetAccessGroupPrefix = "group:subnet-access-"
const subnetMarker = "10.255.255.254/32"

type subnetAccessRule struct {
	Users    []string `json:"users"`
	Groups   []string `json:"groups,omitempty"`
	Target   string   `json:"target"`
	Protocol string   `json:"protocol"`
	Ports    []string `json:"ports"`
}

// Reject misspelled fields instead of silently treating a combined request as
// a partial update. Each endpoint replaces only its own configuration.
func bindSubnetRequest(c *gin.Context, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20))
	dec.DisallowUnknownFields()
	err := dec.Decode(dst)
	if err == nil {
		var extra any
		if dec.Decode(&extra) != io.EOF {
			err = errors.New("expected one JSON object")
		}
	}
	if err != nil {
		subnetBadRequest(c, err)
		return false
	}
	return true
}

func subnetBadRequest(c *gin.Context, err error) {
	c.JSON(http.StatusBadRequest, response{Code: requestHeadscaleError, Message: err.Error()})
}

func loadSubnetDocument(ctx context.Context) (*policyDocument, error) {
	policy, err := getHeadscalePolicy(ctx)
	if err != nil {
		return nil, err
	}
	p, err := parsePolicyDocument([]byte(policy.Policy))
	if err != nil {
		return nil, &policyShapeError{err: err}
	}
	return p, nil
}

func saveSubnetDocument(ctx context.Context, p *policyDocument) error {
	raw, err := p.marshal()
	if err != nil {
		return err
	}
	_, err = setHeadscalePolicy(ctx, string(raw))
	return err
}

// Exact tag:olares route approvers are owned by this API, except the
// LarePass compatibility marker. Other approvers and exitNode are preserved.
func (p *policyDocument) subnetRoutes() ([]string, error) {
	a, err := p.policyAutoApprovers()
	if err != nil {
		return nil, err
	}
	routes := []string{}
	for route, tags := range a.Routes {
		if route != subnetMarker && stringSlicesEqual(tags, []string{"tag:olares"}) {
			routes = append(routes, route)
		}
	}
	routes, _, err = normalizeSubnetRoutePrefixes(routes)
	return routes, err
}

func (p *policyDocument) replaceSubnetRoutes(routes []string) error {
	a, err := p.policyAutoApprovers()
	if err != nil {
		return err
	}
	if a.Routes == nil {
		a.Routes = map[string][]string{}
	}
	for route, tags := range a.Routes {
		if route != subnetMarker && stringSlicesEqual(tags, []string{"tag:olares"}) {
			delete(a.Routes, route)
		}
	}
	for _, route := range routes {
		if _, exists := a.Routes[route]; exists {
			return fmt.Errorf("route %s has unmanaged approvers", route)
		}
		a.Routes[route] = []string{"tag:olares"}
	}
	raw, err := json.Marshal(a)
	if err == nil {
		p.fields["autoApprovers"] = raw
	}
	return err
}

func getSubnetRoutes(c *gin.Context) {
	cancel := beginPolicyOperation(c)
	defer cancel()
	if !lockPolicy(c) {
		return
	}
	defer unlockPolicy()
	p, err := loadSubnetDocument(c.Request.Context())
	if err != nil {
		writeSubnetRouterError(c, err)
		return
	}
	routes, err := p.subnetRoutes()
	if err != nil {
		writeSubnetRouterError(c, &policyShapeError{err: err})
		return
	}
	file, err := readSubnetRoutesFile()
	if err != nil {
		writeSubnetRouterError(c, err)
		return
	}
	c.JSON(200, response{Data: gin.H{"routes": routes, "inSync": stringSlicesEqual(routes, file)}})
}

func putSubnetRoutes(c *gin.Context) {
	cancel := beginPolicyOperation(c)
	defer cancel()
	var req struct {
		Routes *[]string `json:"routes"`
	}
	if !bindSubnetRequest(c, &req) {
		return
	}
	if req.Routes == nil {
		subnetBadRequest(c, errors.New("routes must be an array"))
		return
	}
	routes, err := normalizeSubnetRoutes(*req.Routes)
	if err != nil {
		subnetBadRequest(c, err)
		return
	}
	if !lockPolicy(c) {
		return
	}
	defer unlockPolicy()
	p, err := loadSubnetDocument(c.Request.Context())
	if err != nil {
		writeSubnetRouterError(c, err)
		return
	}
	current, err := p.subnetRoutes()
	if err != nil {
		writeSubnetRouterError(c, &policyShapeError{err: err})
		return
	}
	changed := !stringSlicesEqual(current, routes)
	if changed {
		if err = p.replaceSubnetRoutes(routes); err != nil {
			writeSubnetRouterError(c, &policyShapeError{err: err})
			return
		}
		if err = saveSubnetDocument(c.Request.Context(), p); err != nil {
			writeSubnetRouterError(c, err)
			return
		}
	}
	fileChanged, err := writeSubnetRoutesFile(routes)
	if err != nil {
		writeSubnetRouterError(c, fmt.Errorf("policy saved but route file sync failed; retry PUT: %w", err))
		return
	}
	c.JSON(200, response{Data: gin.H{"routes": routes, "inSync": true, "changed": changed || fileChanged}})
}

func normalizeSubnetAccess(rules []subnetAccessRule, checkCluster bool) ([]subnetAccessRule, error) {
	if len(rules) > 256 {
		return nil, errors.New("at most 256 access rules are allowed")
	}
	out := make([]subnetAccessRule, 0, len(rules))
	for _, r := range rules {
		users, err := normalizeSubnetUsers(r.Users)
		if err != nil {
			return nil, err
		}
		groups := append([]string(nil), r.Groups...)
		sort.Strings(groups)
		for i, name := range groups {
			if !lanGroupName.MatchString(name) || (i > 0 && groups[i-1] == name) {
				return nil, errors.New("invalid or duplicate LAN group name")
			}
		}
		if len(users) == 0 && len(groups) == 0 {
			return nil, errors.New("each access rule needs users or groups")
		}
		target := strings.TrimSpace(r.Target)
		if ip, err := netip.ParseAddr(target); err == nil && ip.Is4() {
			target = netip.PrefixFrom(ip, 32).String()
		}
		var targets []string
		if checkCluster {
			targets, err = normalizeSubnetRoutes([]string{target})
		} else {
			targets, _, err = normalizeSubnetRoutePrefixes([]string{target})
		}
		if err != nil {
			return nil, err
		}
		proto := strings.ToLower(strings.TrimSpace(r.Protocol))
		if proto != "tcp" && proto != "udp" {
			return nil, errors.New("protocol must be tcp or udp")
		}
		if len(r.Ports) == 0 || len(r.Ports) > 256 {
			return nil, errors.New("ports must contain 1 to 256 entries")
		}
		for _, port := range r.Ports {
			port = strings.TrimSpace(port)
			if strings.Contains(port, ",") {
				return nil, errors.New("use separate array entries for ports")
			}
			if port == "*" && len(r.Ports) != 1 {
				return nil, errors.New("* must be the only port entry")
			}
			if _, err := normalizePortSpec(port); err != nil {
				return nil, err
			}
			if port != "*" {
				lo, _ := portSpecBounds(port)
				if lo < 1 {
					return nil, errors.New("ports must be between 1 and 65535")
				}
			}
		}
		ports, err := normalizePorts(r.Ports)
		if err != nil {
			return nil, err
		}
		out = append(out, subnetAccessRule{Users: users, Groups: groups, Target: targets[0], Protocol: proto, Ports: ports})
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := json.Marshal(out[i])
		b, _ := json.Marshal(out[j])
		return string(a) < string(b)
	})
	return out, nil
}

func managedSubnetGroup(s string) bool {
	return s == subnetUsersGroup || strings.HasPrefix(s, subnetAccessGroupPrefix)
}

// Read legacy broad rules too, so a caller can inspect them before replacing
// them. An empty protocol in a legacy response means the old all-protocol rule.
func (p *policyDocument) subnetAccess() ([]subnetAccessRule, error) {
	groups, err := p.policyGroups()
	if err != nil {
		return nil, err
	}
	result := []subnetAccessRule{}
	for _, acl := range p.ACLs {
		managed := false
		for _, src := range acl.Src {
			managed = managed || managedSubnetGroup(src)
		}
		if !managed {
			continue
		}
		if len(acl.Src) == 0 || acl.Action != "accept" {
			return nil, errors.New("unexpected managed subnet ACL")
		}
		for key := range acl.fields {
			if key != "action" && key != "src" && key != "dst" && key != "proto" {
				return nil, fmt.Errorf("unsupported managed subnet ACL field %s", key)
			}
		}
		members, ok := groups[acl.Src[0]]
		if !ok {
			return nil, errors.New("missing subnet access group")
		}
		users, err := normalizeSubnetUserAliases(members)
		if err != nil {
			return nil, err
		}
		refs := []string(nil)
		if !managedSubnetGroup(acl.Src[0]) {
			return nil, errors.New("invalid subnet marker position")
		}
		for _, src := range acl.Src[1:] {
			if strings.HasPrefix(src, lanGroupPrefix) {
				name := strings.TrimPrefix(src, lanGroupPrefix)
				if !lanGroupName.MatchString(name) {
					return nil, errors.New("invalid LAN group reference")
				}
				if _, ok := groups[src]; !ok {
					return nil, errors.New("missing LAN group")
				}
				refs = append(refs, name)
			} else {
				aliases, err := normalizeSubnetUserAliases([]string{src})
				if err != nil {
					return nil, err
				}
				users = append(users, aliases...)
			}
		}
		users, err = normalizeSubnetUsers(users)
		if err != nil {
			return nil, err
		}
		sort.Strings(refs)
		for _, dst := range acl.Dst {
			i := strings.LastIndex(dst, ":")
			if i < 0 {
				return nil, errors.New("invalid managed subnet destination")
			}
			result = append(result, subnetAccessRule{Users: users, Groups: refs, Target: dst[:i], Protocol: acl.Proto, Ports: strings.Split(dst[i+1:], ",")})
		}
	}
	return result, nil
}

func (p *policyDocument) replaceSubnetAccess(rules []subnetAccessRule) error {
	if _, err := p.subnetAccess(); err != nil {
		return err
	}
	groups, err := p.policyGroups()
	if err != nil {
		return err
	}
	// Keep retired groups empty rather than deleting references elsewhere.
	for name := range groups {
		if managedSubnetGroup(name) {
			groups[name] = []string{}
		}
	}
	retained := []policyACL{}
	for _, acl := range p.ACLs {
		if len(acl.Src) > 0 && managedSubnetGroup(acl.Src[0]) {
			continue
		}
		retained = append(retained, acl)
	}
	for i, r := range rules {
		group := fmt.Sprintf("%s%d", subnetAccessGroupPrefix, i)
		groups[group] = []string{} // Empty ownership marker; never grants access.
		sources := append([]string{group}, policyUserAliases(r.Users)...)
		for _, name := range r.Groups {
			if _, ok := groups[lanGroupPrefix+name]; !ok {
				return fmt.Errorf("LAN group %q does not exist", name)
			}
			sources = append(sources, lanGroupPrefix+name)
		}
		retained = append(retained, policyACL{Action: "accept", Src: sources, Proto: r.Protocol, Dst: []string{r.Target + ":" + strings.Join(r.Ports, ",")}})
	}
	raw, err := json.Marshal(groups)
	if err != nil {
		return err
	}
	p.fields["groups"] = raw
	p.ACLs = retained
	return nil
}

func getSubnetAccess(c *gin.Context) {
	cancel := beginPolicyOperation(c)
	defer cancel()
	if !lockPolicy(c) {
		return
	}
	defer unlockPolicy()
	p, err := loadSubnetDocument(c.Request.Context())
	if err != nil {
		writeSubnetRouterError(c, err)
		return
	}
	rules, err := p.subnetAccess()
	if err != nil {
		writeSubnetRouterError(c, &policyShapeError{err: err})
		return
	}
	c.JSON(200, response{Data: gin.H{"access": rules}})
}

func putSubnetAccess(c *gin.Context) {
	cancel := beginPolicyOperation(c)
	defer cancel()
	var req struct {
		Access *[]subnetAccessRule `json:"access"`
	}
	if !bindSubnetRequest(c, &req) {
		return
	}
	if req.Access == nil {
		subnetBadRequest(c, errors.New("access must be an array"))
		return
	}
	rules, err := normalizeSubnetAccess(*req.Access, true)
	if err != nil {
		subnetBadRequest(c, err)
		return
	}
	if !lockPolicy(c) {
		return
	}
	defer unlockPolicy()
	p, err := loadSubnetDocument(c.Request.Context())
	if err != nil {
		writeSubnetRouterError(c, err)
		return
	}
	current, err := p.subnetAccess()
	if err != nil {
		writeSubnetRouterError(c, &policyShapeError{err: err})
		return
	}
	changed := !reflect.DeepEqual(current, rules)
	allUsers := []string{}
	groups, err := p.policyGroups()
	if err != nil {
		writeSubnetRouterError(c, err)
		return
	}
	for _, r := range rules {
		allUsers = append(allUsers, r.Users...)
		for _, name := range r.Groups {
			members, ok := groups[lanGroupPrefix+name]
			if !ok {
				subnetBadRequest(c, fmt.Errorf("LAN group %q does not exist", name))
				return
			}
			users, err := normalizeSubnetUserAliases(members)
			if err != nil {
				writeSubnetRouterError(c, err)
				return
			}
			allUsers = append(allUsers, users...)
		}
	}
	allUsers, err = normalizeSubnetUsers(allUsers)
	if err != nil {
		subnetBadRequest(c, err)
		return
	}
	if err = validateOlaresUsers(c.Request.Context(), allUsers); err != nil {
		subnetBadRequest(c, err)
		return
	}
	if changed {
		for _, r := range rules {
			for _, user := range r.Users {
				if _, err = resolveUserIDString(c.Request.Context(), user); err != nil {
					writeSubnetRouterError(c, err)
					return
				}
			}
		}
		if err = p.replaceSubnetAccess(rules); err != nil {
			writeSubnetRouterError(c, &policyShapeError{err: err})
			return
		}
		if err = saveSubnetDocument(c.Request.Context(), p); err != nil {
			writeSubnetRouterError(c, err)
			return
		}
	}
	c.JSON(200, response{Data: gin.H{"access": rules, "changed": changed}})
}
