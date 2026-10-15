package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRequireOwner(t *testing.T) {
	gin.SetMode(gin.TestMode)
	original := verifyOlaresOwner
	t.Cleanup(func() { verifyOlaresOwner = original })

	for _, tt := range []struct {
		name       string
		owner      bool
		err        error
		wantStatus int
	}{
		{name: "owner", owner: true, wantStatus: http.StatusNoContent},
		{name: "non-owner", wantStatus: http.StatusForbidden},
		{name: "lookup failure", err: errors.New("lookup failed"), wantStatus: http.StatusBadGateway},
	} {
		t.Run(tt.name, func(t *testing.T) {
			verifyOlaresOwner = func(_ context.Context, username string) (bool, error) {
				if username != "alice" {
					t.Fatalf("username = %q, want alice", username)
				}
				return tt.owner, tt.err
			}

			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set(authenticatedUserContextKey, "alice")
				c.Next()
			})
			router.GET("/owner", requireOwner(), func(c *gin.Context) {
				c.Status(http.StatusNoContent)
			})

			request := httptest.NewRequest(http.MethodGet, "/owner", nil)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, tt.wantStatus, response.Body.String())
			}
		})
	}
}
