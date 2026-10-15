package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func timeoutTestContext(ctx context.Context) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	return c, w
}

func TestPolicyLockWaitCanTimeout(t *testing.T) {
	policyUpdateMu <- struct{}{}
	defer unlockPolicy()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	c, w := timeoutTestContext(ctx)
	if lockPolicy(c) {
		t.Fatal("acquired occupied lock")
	}
	if w.Code != http.StatusGatewayTimeout || len(policyUpdateMu) != 1 {
		t.Fatalf("status=%d tokens=%d", w.Code, len(policyUpdateMu))
	}
}

func TestCanceledRequestCannotAcquireFreePolicyLock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, _ := timeoutTestContext(ctx)
	if lockPolicy(c) || len(policyUpdateMu) != 0 {
		t.Fatal("canceled request acquired or leaked lock")
	}
}

func TestHeadscaleTimeoutReleasesPolicyLock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	oldURL := url
	url = server.URL
	t.Cleanup(func() { url = oldURL })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	c, _ := timeoutTestContext(ctx)
	getApplicationPorts(c)
	if len(policyUpdateMu) != 0 {
		t.Fatal("downstream timeout leaked policy lock")
	}
	c, _ = timeoutTestContext(context.Background())
	if !lockPolicy(c) {
		t.Fatal("next request could not acquire lock")
	}
	unlockPolicy()
}

func TestHeadscaleUserLookupHonorsCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	oldURL := url
	url = server.URL
	t.Cleanup(func() { url = oldURL })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := resolveUserIDString(ctx, "alice")
	if err == nil || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("lookup did not stop at deadline: %v", err)
	}
}
