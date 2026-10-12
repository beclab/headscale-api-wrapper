package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	subnetUsersGroup        = "group:subnet-users"
	defaultSubnetRoutesFile = "/var/lib/headscale/bootstrap/subnet-routes"
)

type policyAutoApprovers struct {
	fields   map[string]json.RawMessage
	Routes   map[string][]string `json:"routes"`
	ExitNode []string            `json:"exitNode,omitempty"`
}

func (approvers *policyAutoApprovers) UnmarshalJSON(data []byte) error {
	fields := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	type knownAutoApprovers struct {
		Routes   map[string][]string `json:"routes"`
		ExitNode []string            `json:"exitNode,omitempty"`
	}
	var known knownAutoApprovers
	if err := json.Unmarshal(data, &known); err != nil {
		return err
	}
	approvers.fields = fields
	approvers.Routes = known.Routes
	approvers.ExitNode = known.ExitNode
	return nil
}

func (approvers policyAutoApprovers) MarshalJSON() ([]byte, error) {
	fields := make(map[string]json.RawMessage, len(approvers.fields)+2)
	for key, value := range approvers.fields {
		fields[key] = value
	}
	routes, err := json.Marshal(approvers.Routes)
	if err != nil {
		return nil, err
	}
	fields["routes"] = routes
	if approvers.ExitNode == nil {
		delete(fields, "exitNode")
	} else {
		exitNode, err := json.Marshal(approvers.ExitNode)
		if err != nil {
			return nil, err
		}
		fields["exitNode"] = exitNode
	}
	return json.Marshal(fields)
}

func writeSubnetRouterError(c *gin.Context, err error) {
	var shapeError *policyShapeError
	if errors.As(err, &shapeError) {
		c.JSON(http.StatusConflict, response{Code: requestHeadscaleError, Message: shapeError.Error()})
		return
	}
	c.JSON(http.StatusBadGateway, response{Code: requestHeadscaleError, Message: err.Error()})
}

func (p *policyDocument) policyAutoApprovers() (policyAutoApprovers, error) {
	raw, ok := p.fields["autoApprovers"]
	if !ok {
		return policyAutoApprovers{}, errors.New("Headscale policy has no autoApprovers field")
	}
	var autoApprovers policyAutoApprovers
	if err := json.Unmarshal(raw, &autoApprovers); err != nil {
		return policyAutoApprovers{}, fmt.Errorf("decode Headscale policy autoApprovers: %w", err)
	}
	return autoApprovers, nil
}

func normalizeSubnetRoutes(rawRoutes []string) ([]string, error) {
	routes, prefixes, err := normalizeSubnetRoutePrefixes(rawRoutes)
	if err != nil {
		return nil, err
	}
	if len(routes) == 0 {
		return routes, nil
	}

	forbidden, err := forbiddenRoutePrefixes()
	if err != nil {
		return nil, err
	}
	for _, prefix := range prefixes {
		for _, blocked := range forbidden {
			if prefixesOverlap(prefix, blocked) {
				return nil, fmt.Errorf("subnet route %q overlaps forbidden cluster network %s", prefix, blocked)
			}
		}
	}
	return routes, nil
}

func normalizeSubnetRoutePrefixes(rawRoutes []string) ([]string, []netip.Prefix, error) {
	set := make(map[string]netip.Prefix, len(rawRoutes))
	for _, raw := range rawRoutes {
		value := strings.TrimSpace(raw)
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() {
			return nil, nil, fmt.Errorf("subnet route %q must be an IPv4 CIDR", raw)
		}
		prefix = prefix.Masked()
		if !isPrivateSubnetRoute(prefix) {
			return nil, nil, fmt.Errorf("subnet route %q must be fully contained in an RFC1918 private network", raw)
		}
		set[prefix.String()] = prefix
	}

	routes := make([]string, 0, len(set))
	for route := range set {
		routes = append(routes, route)
	}
	sort.Slice(routes, func(i, j int) bool {
		left, _ := netip.ParsePrefix(routes[i])
		right, _ := netip.ParsePrefix(routes[j])
		if left.Addr().Compare(right.Addr()) == 0 {
			return left.Bits() < right.Bits()
		}
		return left.Addr().Compare(right.Addr()) < 0
	})
	for i := 0; i < len(routes); i++ {
		left, _ := netip.ParsePrefix(routes[i])
		for j := i + 1; j < len(routes); j++ {
			right, _ := netip.ParsePrefix(routes[j])
			if prefixesOverlap(left, right) {
				return nil, nil, fmt.Errorf("subnet routes %s and %s overlap; use the smallest required prefixes", left, right)
			}
		}
	}
	prefixes := make([]netip.Prefix, 0, len(routes))
	for _, route := range routes {
		prefix, _ := netip.ParsePrefix(route)
		prefixes = append(prefixes, prefix)
	}
	return routes, prefixes, nil
}

func isPrivateSubnetRoute(prefix netip.Prefix) bool {
	for _, private := range []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	} {
		if prefix.Bits() >= private.Bits() && private.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func forbiddenRoutePrefixes() ([]netip.Prefix, error) {
	const environmentName = "OLARES_CLUSTER_CIDRS"
	value := strings.TrimSpace(os.Getenv(environmentName))
	if value == "" {
		return nil, fmt.Errorf("%s is required", environmentName)
	}
	return parseForbiddenRoutePrefixes(value, environmentName)
}

func parseForbiddenRoutePrefixes(value, source string) ([]netip.Prefix, error) {
	parts := strings.Split(value, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		entry := strings.TrimSpace(part)
		if entry == "" {
			return nil, fmt.Errorf("%s contains an empty CIDR", source)
		}
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q in %s: %w", entry, source, err)
		}
		if !prefix.Addr().Is4() {
			return nil, fmt.Errorf("CIDR %q in %s must be IPv4", entry, source)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("%s contains no CIDRs", source)
	}
	return prefixes, nil
}

func prefixesOverlap(left, right netip.Prefix) bool {
	return left.Addr().BitLen() == right.Addr().BitLen() &&
		(left.Contains(right.Addr()) || right.Contains(left.Addr()))
}

func normalizeSubnetUsers(users []string) ([]string, error) {
	set := make(map[string]struct{}, len(users))
	for _, raw := range users {
		username := strings.TrimSpace(raw)
		if err := validatePolicyUsername(username); err != nil {
			return nil, err
		}
		set[username] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for username := range set {
		result = append(result, username)
	}
	sort.Strings(result)
	return result, nil
}

func normalizeSubnetUserAliases(members []string) ([]string, error) {
	users := make([]string, 0, len(members))
	for _, member := range members {
		if !strings.HasSuffix(member, "@") {
			return nil, fmt.Errorf("%s member %q is not a Headscale user alias", subnetUsersGroup, member)
		}
		users = append(users, strings.TrimSuffix(member, "@"))
	}
	return normalizeSubnetUsers(users)
}

func policyUserAliases(users []string) []string {
	aliases := make([]string, len(users))
	for i, user := range users {
		aliases[i] = user + "@"
	}
	return aliases
}

func routesFromSubnetDestinations(destinations []string) ([]string, error) {
	routes := make([]string, 0, len(destinations))
	for _, destination := range destinations {
		if !strings.HasSuffix(destination, ":*") {
			return nil, fmt.Errorf("managed subnet destination %q must allow all ports", destination)
		}
		routes = append(routes, strings.TrimSuffix(destination, ":*"))
	}
	normalized, _, err := normalizeSubnetRoutePrefixes(routes)
	return normalized, err
}

func subnetDestinations(routes []string) []string {
	destinations := make([]string, len(routes))
	for i, route := range routes {
		destinations[i] = route + ":*"
	}
	return destinations
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func subnetRoutesFile() string {
	if path := strings.TrimSpace(os.Getenv("SUBNET_ROUTES_FILE")); path != "" {
		return path
	}
	return defaultSubnetRoutesFile
}

type subnetRoutesFormatError struct{ error }

func readSubnetRoutesFile() ([]string, error) {
	data, err := os.ReadFile(subnetRoutesFile())
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read subnet routes file: %w", err)
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return []string{}, nil
	}
	routes, _, err := normalizeSubnetRoutePrefixes(strings.Split(value, ","))
	if err != nil {
		return nil, &subnetRoutesFormatError{err}
	}
	return routes, err
}

func writeSubnetRoutesFile(routes []string) (bool, error) {
	current, err := readSubnetRoutesFile()
	var formatErr *subnetRoutesFormatError
	if err != nil && !errors.As(err, &formatErr) {
		return false, err
	}
	// A full replacement can repair malformed content, but not read failures.
	if err == nil && stringSlicesEqual(current, routes) {
		return false, nil
	}
	path := subnetRoutesFile()
	if err := os.MkdirAll(filepath.Dir(path), 0770); err != nil {
		return false, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".subnet-routes-*")
	if err != nil {
		return false, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0640); err != nil {
		temporary.Close()
		return false, err
	}
	if _, err := temporary.WriteString(strings.Join(routes, ",") + "\n"); err != nil {
		temporary.Close()
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return false, err
	}
	return true, nil
}
