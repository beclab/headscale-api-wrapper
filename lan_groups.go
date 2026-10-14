package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

const lanGroupPrefix = "group:lan-"

var lanGroupName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
var lookupOlaresUser = func(ctx context.Context, username string) (bool, error) {
	var user olaresUser
	found, err := readOlaresResource(ctx, "/"+neturl.PathEscape(username), &user)
	return found && user.availableForAuthorization(), err
}

func validateOlaresUsers(ctx context.Context, users []string) error {
	for _, u := range users {
		exists, err := lookupOlaresUser(ctx, u)
		if err != nil {
			return fmt.Errorf("verify Olares user %q: %w", u, err)
		}
		if !exists {
			return fmt.Errorf("Olares user %q does not exist or is not available for authorization", u)
		}
	}
	return nil
}

// Return only public identity fields, never the complete User CR annotations.
func getOlaresUsers(c *gin.Context) {
	cancel := beginPolicyOperation(c)
	defer cancel()
	users := []gin.H{}
	next := ""
	for {
		var page struct {
			Items    []olaresUser `json:"items"`
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
		}
		found, err := readOlaresResource(c.Request.Context(), "?limit=500&continue="+neturl.QueryEscape(next), &page)
		if err != nil || !found {
			c.JSON(http.StatusBadGateway, response{Code: requestHeadscaleError, Message: "cannot list Olares users"})
			return
		}
		for _, u := range page.Items {
			if !u.availableForAuthorization() {
				continue
			}
			users = append(users, gin.H{"username": u.Metadata.Name})
		}
		next = page.Metadata.Continue
		if next == "" {
			break
		}
	}
	sort.Slice(users, func(i, j int) bool { return users[i]["username"].(string) < users[j]["username"].(string) })
	c.JSON(200, response{Data: gin.H{"users": users}})
}

type lanGroup struct {
	Name  string   `json:"name"`
	Users []string `json:"users"`
}

func (p *policyDocument) lanGroups() ([]lanGroup, error) {
	groups, err := p.policyGroups()
	if err != nil {
		return nil, err
	}
	out := []lanGroup{}
	for name, members := range groups {
		if strings.HasPrefix(name, lanGroupPrefix) {
			users, err := normalizeSubnetUserAliases(members)
			if err != nil {
				return nil, err
			}
			out = append(out, lanGroup{Name: strings.TrimPrefix(name, lanGroupPrefix), Users: users})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
func getLanGroups(c *gin.Context) {
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
	groups, err := p.lanGroups()
	if err != nil {
		writeSubnetRouterError(c, &policyShapeError{err: err})
		return
	}
	c.JSON(200, response{Data: gin.H{"groups": groups}})
}
func putLanGroup(c *gin.Context) {
	cancel := beginPolicyOperation(c)
	defer cancel()
	name := c.Param("name")
	if !lanGroupName.MatchString(name) {
		subnetBadRequest(c, fmt.Errorf("invalid group name"))
		return
	}
	var req struct {
		Users *[]string `json:"users"`
	}
	if !bindJSON(c, &req, 1<<20) {
		return
	}
	if req.Users == nil {
		subnetBadRequest(c, fmt.Errorf("users must be an array"))
		return
	}
	users, err := normalizeSubnetUsers(*req.Users)
	if err != nil {
		subnetBadRequest(c, err)
		return
	}
	if err = validateOlaresUsers(c.Request.Context(), users); err != nil {
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
	groups, err := p.policyGroups()
	if err != nil {
		writeSubnetRouterError(c, &policyShapeError{err: err})
		return
	}
	aliases := policyUserAliases(users)
	changed := !reflect.DeepEqual(groups[lanGroupPrefix+name], aliases)
	for _, u := range users {
		if _, err = resolveUserIDString(c.Request.Context(), u); err != nil {
			writeSubnetRouterError(c, err)
			return
		}
	}
	if changed {
		groups[lanGroupPrefix+name] = aliases
		p.fields["groups"], _ = json.Marshal(groups)
		if err = saveSubnetDocument(c.Request.Context(), p); err != nil {
			writeSubnetRouterError(c, err)
			return
		}
	}
	c.JSON(200, response{Data: gin.H{"name": name, "users": users, "changed": changed}})
	logMutation(c, "lan-group.put", changed, fmt.Sprintf("group=%q users=%d", name, len(users)))
}
func deleteLanGroup(c *gin.Context) {
	cancel := beginPolicyOperation(c)
	defer cancel()
	name := c.Param("name")
	if !lanGroupName.MatchString(name) {
		subnetBadRequest(c, fmt.Errorf("invalid group name"))
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
	groups, err := p.policyGroups()
	if err != nil {
		writeSubnetRouterError(c, &policyShapeError{err: err})
		return
	}
	key := lanGroupPrefix + name
	// Check every policy field, including grants, SSH and tag owners, not only ACLs.
	raw, err := p.marshal()
	if err != nil {
		writeSubnetRouterError(c, err)
		return
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		writeSubnetRouterError(c, &policyShapeError{err: fmt.Errorf("decode Headscale policy: %w", err)})
		return
	}
	if g, ok := doc["groups"].(map[string]any); ok {
		delete(g, key)
	}
	if referencesGroup(doc, key) {
		c.JSON(409, response{Code: requestHeadscaleError, Message: "group is still referenced by policy"})
		return
	}
	_, changed := groups[key]
	if changed {
		delete(groups, key)
		p.fields["groups"], _ = json.Marshal(groups)
		if err = saveSubnetDocument(c.Request.Context(), p); err != nil {
			writeSubnetRouterError(c, err)
			return
		}
	}
	c.JSON(200, response{Data: gin.H{"changed": changed}})
	logMutation(c, "lan-group.delete", changed, fmt.Sprintf("group=%q", name))
}
func referencesGroup(v any, key string) bool {
	switch x := v.(type) {
	case string:
		return x == key || strings.HasPrefix(x, key+":")
	case []any:
		for _, item := range x {
			if referencesGroup(item, key) {
				return true
			}
		}
	case map[string]any:
		for _, item := range x {
			if referencesGroup(item, key) {
				return true
			}
		}
	}
	return false
}
