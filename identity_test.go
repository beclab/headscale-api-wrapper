package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestPreAuthKeyRejectsUnavailableOlaresUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	originalVerifyToken := verifySessionToken
	originalVerifyAvailable := verifyOlaresUserAvailable
	t.Cleanup(func() {
		verifySessionToken = originalVerifyToken
		verifyOlaresUserAvailable = originalVerifyAvailable
	})
	verifySessionToken = func(context.Context, string) (tokenClaims, error) {
		return tokenClaims{Username: "alice"}, nil
	}
	verifyOlaresUserAvailable = func(_ context.Context, username string) (bool, error) {
		if username != "alice" {
			t.Fatalf("username = %q, want alice", username)
		}
		return false, nil
	}

	router := gin.New()
	router.GET("/headscale/preauthkey", getPreAuthKey)
	request := httptest.NewRequest(http.MethodGet, "/headscale/preauthkey", nil)
	request.Header.Set("X-Authorization", "Bearer old-token")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
	}
}

func TestAuthenticatedUserUsesVerifiedTokenIdentity(t *testing.T) {
	original := verifySessionToken
	verifySessionToken = func(ctx context.Context, token string) (tokenClaims, error) {
		return tokenClaims{Username: "alice"}, nil
	}
	defer func() { verifySessionToken = original }()

	req, _ := http.NewRequest(http.MethodGet, "/headscale/preauthkey", nil)
	req.Header.Set("X-Authorization", "token")
	req.Header.Set("X-BFL-USER", "alice")
	got, err := authenticatedUser(req)
	if err != nil {
		t.Fatal(err)
	}
	if got != "alice" {
		t.Fatalf("got user %q, want alice", got)
	}
}

func TestAuthenticatedUserIgnoresCallerSelectedUser(t *testing.T) {
	original := verifySessionToken
	verifySessionToken = func(ctx context.Context, token string) (tokenClaims, error) {
		return tokenClaims{Username: "alice"}, nil
	}
	defer func() { verifySessionToken = original }()

	req, _ := http.NewRequest(http.MethodGet, "/headscale/preauthkey", nil)
	req.Header.Set("X-Authorization", "token")
	req.Header.Set("X-BFL-USER", "bob")
	got, err := authenticatedUser(req)
	if err != nil {
		t.Fatal(err)
	}
	if got != "alice" {
		t.Fatalf("got user %q, want token user alice", got)
	}
}

func TestAuthenticatedUserRejectsInvalidSession(t *testing.T) {
	original := verifySessionToken
	verifySessionToken = func(ctx context.Context, token string) (tokenClaims, error) {
		return tokenClaims{}, errors.New("invalid session")
	}
	defer func() { verifySessionToken = original }()

	req, _ := http.NewRequest(http.MethodGet, "/headscale/preauthkey", nil)
	req.Header.Set("X-Authorization", "token")
	if _, err := authenticatedUser(req); err == nil {
		t.Fatal("expected invalid session to be rejected")
	}
}

func TestVerifyOlaresSessionTokenUsesVerifiedClaims(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"exp":123,"username":"alice","groups":["users"]}`))
	}))
	defer server.Close()
	t.Setenv("TOKEN_VERIFY_URL", server.URL)

	claims, err := verifyOlaresSessionToken(context.Background(), "token")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Username != "alice" {
		t.Fatalf("got username %q, want alice", claims.Username)
	}
}

func TestVerifyOlaresSessionTokenRejectsFailedVerification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Expired JWT", http.StatusBadRequest)
	}))
	defer server.Close()
	t.Setenv("TOKEN_VERIFY_URL", server.URL)

	if _, err := verifyOlaresSessionToken(context.Background(), "token"); err == nil {
		t.Fatal("expected failed verification to be rejected")
	}
}
