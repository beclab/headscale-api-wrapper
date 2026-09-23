package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	resty "github.com/go-resty/resty/v2"
)

const defaultTokenVerifyURL = "http://lldap-service.os-platform:17170/auth/token/verify"

type tokenClaims struct {
	Username string `json:"username"`
}

var verifySessionToken = verifyOlaresSessionToken

// authenticatedUser returns the identity asserted by the verified Olares
// session. X-BFL-USER is diagnostic-only; it never selects the Headscale
// user or causes an otherwise valid request to be rejected.
func authenticatedUser(r *http.Request) (string, error) {
	token := strings.TrimSpace(r.Header.Get("X-Authorization"))
	token = strings.TrimPrefix(token, "Bearer ")
	if token == "" {
		return "", errors.New("missing X-Authorization header")
	}

	claims, err := verifySessionToken(token)
	if err != nil {
		return "", err
	}
	username := strings.TrimSpace(claims.Username)
	if username == "" {
		return "", errors.New("Olares session has no username")
	}

	if asserted := strings.TrimSpace(r.Header.Get("X-BFL-USER")); asserted != "" && asserted != username {
		log.Printf("warning: X-BFL-USER=%q does not match token username=%q", asserted, username)
	}
	return username, nil
}

func verifyOlaresSessionToken(token string) (tokenClaims, error) {
	verifyURL := strings.TrimSpace(os.Getenv("TOKEN_VERIFY_URL"))
	if verifyURL == "" {
		verifyURL = defaultTokenVerifyURL
	}
	resp, err := resty.New().SetTimeout(10*time.Second).R().
		SetHeader("Content-Type", "application/json").
		SetAuthToken(token).
		SetBody(map[string]string{"access_token": token}).
		Post(verifyURL)
	if err != nil {
		return tokenClaims{}, fmt.Errorf("verify Olares session: %w", err)
	}
	if resp.StatusCode() != http.StatusOK {
		return tokenClaims{}, fmt.Errorf("verify Olares session: status %d", resp.StatusCode())
	}
	var claims tokenClaims
	if err := json.Unmarshal(resp.Body(), &claims); err != nil {
		return tokenClaims{}, fmt.Errorf("decode Olares verification response: %w", err)
	}
	if strings.TrimSpace(claims.Username) == "" {
		return tokenClaims{}, errors.New("Olares verification response has no username")
	}
	return claims, nil
}
