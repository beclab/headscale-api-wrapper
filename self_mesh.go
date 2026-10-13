package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const selfMeshGroup = "group:self-mesh"

type selfMeshState struct {
	Enabled bool `json:"enabled"`
	Changed bool `json:"changed"`
}

func getSelfMesh(c *gin.Context) { handleSelfMesh(c, false) }
func putSelfMesh(c *gin.Context) { handleSelfMesh(c, true) }

func handleSelfMesh(c *gin.Context, update bool) {
	username := c.GetString(authenticatedUserContextKey)
	if err := validatePolicyUsername(username); err != nil {
		c.JSON(http.StatusUnauthorized, response{Code: requestHeadscaleError, Message: "invalid authenticated user"})
		return
	}
	var request struct {
		Enabled *bool `json:"enabled"`
	}
	if update {
		decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 4096))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			c.JSON(http.StatusBadRequest, response{Code: requestHeadscaleError, Message: err.Error()})
			return
		}
		if err := decoder.Decode(new(interface{})); err != io.EOF || request.Enabled == nil {
			c.JSON(http.StatusBadRequest, response{Code: requestHeadscaleError, Message: "body must contain a boolean enabled field only"})
			return
		}
	}
	cancel := beginPolicyOperation(c)
	defer cancel()
	if !lockPolicy(c) {
		return
	}
	defer unlockPolicy()
	policy, err := getHeadscalePolicy(c.Request.Context())
	if err != nil {
		writeExitUsersError(c, err)
		return
	}
	document, err := parsePolicyDocument([]byte(policy.Policy))
	if err != nil {
		writeExitUsersError(c, &policyShapeError{err: err})
		return
	}
	members, err := document.selfMeshMembers()
	if err != nil {
		writeExitUsersError(c, &policyShapeError{err: err})
		return
	}
	state := selfMeshState{}
	for _, member := range members {
		if member == username+"@" {
			state.Enabled = true
		}
	}
	if update && state.Enabled != *request.Enabled {
		if *request.Enabled {
			// Headscale must know this identity before it can validate the alias.
			if _, err := resolveUserIDString(c.Request.Context(), username); err != nil {
				writeExitUsersError(c, err)
				return
			}
		}
		if err := document.setSelfMesh(username, *request.Enabled); err != nil {
			writeExitUsersError(c, &policyShapeError{err: err})
			return
		}
		encoded, err := document.marshal()
		if err != nil {
			c.JSON(http.StatusInternalServerError, response{Code: requestHeadscaleError, Message: err.Error()})
			return
		}
		if _, err := setHeadscalePolicy(c.Request.Context(), string(encoded)); err != nil {
			writeExitUsersError(c, err)
			return
		}
		state.Enabled, state.Changed = *request.Enabled, true
	}
	c.JSON(http.StatusOK, response{Code: 0, Message: "", Data: state})
}

// Only manage membership of the preinstalled self-only rule. Never silently
// turn a missing or customized ACL into an all-ports grant.
func (p *policyDocument) selfMeshMembers() ([]string, error) {
	found := false
	for _, acl := range p.ACLs {
		related := false
		for _, src := range acl.Src {
			if src == selfMeshGroup {
				related = true
			}
		}
		for _, dst := range acl.Dst {
			if strings.HasPrefix(dst, "autogroup:self") {
				related = true
			}
		}
		if !related {
			continue
		}
		if found || acl.Action != "accept" || acl.Proto != "" ||
			!stringSlicesEqual(acl.Src, []string{selfMeshGroup}) ||
			!stringSlicesEqual(acl.Dst, []string{"autogroup:self:*"}) {
			return nil, fmt.Errorf("Headscale policy has an unexpected or duplicate self-mesh rule")
		}
		found = true
	}
	if !found {
		return nil, fmt.Errorf("Headscale policy is missing the managed self-mesh rule")
	}
	groups, err := p.policyGroups()
	if err != nil {
		return nil, err
	}
	members, ok := groups[selfMeshGroup]
	if !ok {
		return nil, fmt.Errorf("Headscale policy has no %s group", selfMeshGroup)
	}
	for _, member := range members {
		if !strings.HasSuffix(member, "@") {
			return nil, fmt.Errorf("invalid self-mesh user alias %q", member)
		}
		if err := validatePolicyUsername(strings.TrimSuffix(member, "@")); err != nil {
			return nil, err
		}
	}
	return members, nil
}

func (p *policyDocument) setSelfMesh(username string, enabled bool) error {
	if err := validatePolicyUsername(username); err != nil {
		return err
	}
	members, err := p.selfMeshMembers()
	if err != nil {
		return err
	}
	next := make([]string, 0, len(members)+1)
	for _, member := range members {
		if member != username+"@" {
			next = append(next, member)
		}
	}
	if enabled {
		next = append(next, username+"@")
	}
	groups, err := p.policyGroups()
	if err != nil {
		return err
	}
	groups[selfMeshGroup] = next
	encoded, err := json.Marshal(groups)
	if err != nil {
		return err
	}
	p.fields["groups"] = encoded
	return nil
}
