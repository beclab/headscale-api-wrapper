package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestTokenReviewRequestsDedicatedAudience(t *testing.T) {
	payload, err := json.Marshal(tokenReview{
		APIVersion: "authentication.k8s.io/v1",
		Kind:       "TokenReview",
		Spec: tokenReviewSpec{
			Token:     "token",
			Audiences: []string{bootstrapAudience},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var review tokenReview
	if err := json.Unmarshal(payload, &review); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(review.Spec.Audiences, []string{"headscale-bootstrap"}) {
		t.Fatalf("audiences = %#v", review.Spec.Audiences)
	}
}

func TestRequireAllowedServiceAccount(t *testing.T) {
	old := reviewServiceAccountToken
	reviewServiceAccountToken = func(_ context.Context, token, audience string) (string, error) {
		if audience != bootstrapAudience {
			t.Fatalf("audience = %q", audience)
		}
		if token != "valid" {
			t.Fatalf("token = %q", token)
		}
		return bootstrapServiceAccount, nil
	}
	t.Cleanup(func() { reviewServiceAccountToken = old })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(requireAllowedServiceAccount(bootstrapServiceAccount, bootstrapAudience))
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d: %s", resp.Code, http.StatusNoContent, resp.Body.String())
	}
}

func TestRequireAllowedServiceAccountRejectsOtherIdentity(t *testing.T) {
	old := reviewServiceAccountToken
	reviewServiceAccountToken = func(context.Context, string, string) (string, error) {
		return "system:serviceaccount:other:tailscale", nil
	}
	t.Cleanup(func() { reviewServiceAccountToken = old })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(requireAllowedServiceAccount(bootstrapServiceAccount, bootstrapAudience))
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusForbidden)
	}
}

func TestRequireAllowedServiceAccountRequiresBearerScheme(t *testing.T) {
	old := reviewServiceAccountToken
	reviewServiceAccountToken = func(context.Context, string, string) (string, error) {
		t.Fatal("TokenReview must not be called for a malformed Authorization header")
		return "", nil
	}
	t.Cleanup(func() { reviewServiceAccountToken = old })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(requireAllowedServiceAccount(bootstrapServiceAccount, bootstrapAudience))
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	for _, value := range []string{"valid", "Basic valid", "Bearer"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", value)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusUnauthorized {
			t.Fatalf("Authorization %q returned status %d, want %d", value, resp.Code, http.StatusUnauthorized)
		}
	}
}
