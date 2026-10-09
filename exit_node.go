package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	exitUsersGroup      = "group:exit-users"
	exitNodeDestination = "autogroup:internet:*"
)

type exitUsersState struct {
	Users     []string `json:"users"`
	Revision  string   `json:"revision"`
	UpdatedAt string   `json:"updatedAt,omitempty"`
	Changed   bool     `json:"changed,omitempty"`
}

type policyShapeError struct {
	err error
}

func (e *policyShapeError) Error() string {
	return e.err.Error()
}

func getExitUsers(c *gin.Context) {
	policyUpdateMu.Lock()
	defer policyUpdateMu.Unlock()

	state, _, err := loadExitUsers()
	if err != nil {
		writeExitUsersError(c, err)
		return
	}
	c.JSON(http.StatusOK, response{Code: 0, Message: "", Data: state})
}

func grantExitUser(c *gin.Context) {
	updateExitUser(c, true)
}

func revokeExitUser(c *gin.Context) {
	updateExitUser(c, false)
}

func updateExitUser(c *gin.Context, grant bool) {
	username := strings.TrimSpace(c.Param("username"))
	if err := validatePolicyUsername(username); err != nil {
		c.JSON(http.StatusBadRequest, response{Code: requestHeadscaleError, Message: err.Error()})
		return
	}

	policyUpdateMu.Lock()
	defer policyUpdateMu.Unlock()

	state, document, err := loadExitUsers()
	if err != nil {
		writeExitUsersError(c, err)
		return
	}

	users, changed, err := document.setExitUser(username, grant)
	if err != nil {
		writeExitUsersError(c, &policyShapeError{err: err})
		return
	}
	if grant {
		// Headscale validates user aliases during policy updates. Creating the
		// corresponding user does not grant access by itself. Always ensure it
		// exists so an idempotent grant also repairs a missing identity record.
		if _, err := resolveUserIDString(username); err != nil {
			c.JSON(http.StatusBadGateway, response{
				Code:    requestHeadscaleError,
				Message: fmt.Sprintf("ensure Headscale user %q: %v", username, err),
			})
			return
		}
	}

	if changed {
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
		state.UpdatedAt = updatedAt
	}

	state.Users = users
	state.Revision = exitUsersRevision(users)
	state.Changed = changed
	c.JSON(http.StatusOK, response{Code: 0, Message: "", Data: state})
}

func loadExitUsers() (exitUsersState, *policyDocument, error) {
	policy, err := getHeadscalePolicy()
	if err != nil {
		return exitUsersState{}, nil, err
	}
	document, err := parsePolicyDocument([]byte(policy.Policy))
	if err != nil {
		return exitUsersState{}, nil, &policyShapeError{err: err}
	}
	users, _, err := document.exitUsers()
	if err != nil {
		return exitUsersState{}, nil, &policyShapeError{err: err}
	}
	return exitUsersState{
		Users:     users,
		Revision:  exitUsersRevision(users),
		UpdatedAt: policy.UpdatedAt,
	}, document, nil
}

func writeExitUsersError(c *gin.Context, err error) {
	var shapeError *policyShapeError
	if errors.As(err, &shapeError) {
		c.JSON(http.StatusConflict, response{Code: requestHeadscaleError, Message: shapeError.Error()})
		return
	}
	c.JSON(http.StatusBadGateway, response{Code: requestHeadscaleError, Message: err.Error()})
}

func (p *policyDocument) exitUsers() ([]string, bool, error) {
	if err := p.validateExitNodeRule(); err != nil {
		return nil, false, err
	}
	groups, err := p.policyGroups()
	if err != nil {
		return nil, false, err
	}
	members, ok := groups[exitUsersGroup]
	if !ok {
		return nil, false, fmt.Errorf("Headscale policy has no %s group", exitUsersGroup)
	}
	users, err := normalizeExitUsers(members)
	if err != nil {
		return nil, false, err
	}
	return users, stringSlicesEqual(members, exitUserAliases(users)), nil
}

func (p *policyDocument) setExitUser(username string, grant bool) ([]string, bool, error) {
	users, canonical, err := p.exitUsers()
	if err != nil {
		return nil, false, err
	}
	set := make(map[string]struct{}, len(users)+1)
	for _, user := range users {
		set[user] = struct{}{}
	}
	_, existed := set[username]
	if grant {
		set[username] = struct{}{}
	} else {
		delete(set, username)
	}
	users = users[:0]
	for user := range set {
		users = append(users, user)
	}
	sort.Strings(users)

	changed := !canonical || grant != existed
	if !changed {
		return users, false, nil
	}
	groups, err := p.policyGroups()
	if err != nil {
		return nil, false, err
	}
	groups[exitUsersGroup] = exitUserAliases(users)
	encoded, err := json.Marshal(groups)
	if err != nil {
		return nil, false, fmt.Errorf("encode Headscale policy groups: %w", err)
	}
	p.fields["groups"] = encoded
	return users, true, nil
}

func (p *policyDocument) policyGroups() (map[string][]string, error) {
	rawGroups, ok := p.fields["groups"]
	if !ok {
		return nil, errors.New("Headscale policy has no groups field")
	}
	groups := make(map[string][]string)
	if err := json.Unmarshal(rawGroups, &groups); err != nil {
		return nil, fmt.Errorf("decode Headscale policy groups: %w", err)
	}
	return groups, nil
}

func (p *policyDocument) validateExitNodeRule() error {
	found := false
	for _, acl := range p.ACLs {
		exitRelated := false
		for _, destination := range acl.Dst {
			if strings.HasPrefix(destination, "autogroup:internet") {
				exitRelated = true
				break
			}
		}
		if !exitRelated {
			continue
		}
		canonical := acl.Action == "accept" && acl.Proto == "" &&
			stringSlicesEqual(acl.Src, []string{exitUsersGroup}) &&
			stringSlicesEqual(acl.Dst, []string{exitNodeDestination})
		if !canonical || found {
			return errors.New("Headscale policy has an unexpected or duplicate exit-node access rule")
		}
		found = true
	}
	if !found {
		return errors.New("Headscale policy is missing the managed exit-node access rule")
	}
	return nil
}

func normalizeExitUsers(members []string) ([]string, error) {
	set := make(map[string]struct{}, len(members))
	for _, member := range members {
		if !strings.HasSuffix(member, "@") {
			return nil, fmt.Errorf("%s member %q is not a Headscale user alias", exitUsersGroup, member)
		}
		username := strings.TrimSuffix(member, "@")
		if err := validatePolicyUsername(username); err != nil {
			return nil, fmt.Errorf("invalid %s member %q: %w", exitUsersGroup, member, err)
		}
		set[username] = struct{}{}
	}
	users := make([]string, 0, len(set))
	for username := range set {
		users = append(users, username)
	}
	sort.Strings(users)
	return users, nil
}

func exitUserAliases(users []string) []string {
	aliases := make([]string, len(users))
	for i, user := range users {
		aliases[i] = user + "@"
	}
	return aliases
}

func exitUsersRevision(users []string) string {
	encoded, _ := json.Marshal(users)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
