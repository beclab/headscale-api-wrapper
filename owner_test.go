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

func TestOlaresUserIsAvailableOwner(t *testing.T) {
	deletionTimestamp := "2026-10-19T00:00:00Z"
	for _, tt := range []struct {
		name              string
		role              string
		state             string
		deletionTimestamp *string
		want              bool
	}{
		{name: "available owner", role: "owner", state: "Created", want: true},
		{name: "non-owner", role: "admin", state: "Created"},
		{name: "owner not created", role: "owner", state: "Creating"},
		{name: "deleting owner", role: "owner", state: "Created", deletionTimestamp: &deletionTimestamp},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var user olaresUser
			user.Metadata.Annotations = map[string]string{ownerRoleAnnotation: tt.role}
			user.Metadata.DeletionTimestamp = tt.deletionTimestamp
			user.Status.State = tt.state
			if got := user.isAvailableOwner(); got != tt.want {
				t.Fatalf("isAvailableOwner() = %t, want %t", got, tt.want)
			}
		})
	}
}
