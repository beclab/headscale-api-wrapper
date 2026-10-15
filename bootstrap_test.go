package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func mockBootstrapHeadscale(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(handler)
	previous := url
	url = server.URL
	t.Cleanup(func() { url = previous; server.Close() })
}

func TestBootstrapAuthKey(t *testing.T) {
	const secret = "hskey-auth-test-secret"
	called := 0
	mockBootstrapHeadscale(t, func(w http.ResponseWriter, r *http.Request) {
		called++
		if r.Method != "POST" || r.URL.Path != "/preauthkey" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var request createPreAuthKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if request.User != "" || request.Reusable || request.Ephemeral || !reflect.DeepEqual(request.AclTags, []string{"tag:olares"}) {
			t.Errorf("unexpected enrollment settings: %#v", request)
		}
		expires, err := time.Parse(time.RFC3339, request.Expiration)
		if err != nil || time.Until(expires) < 4*time.Minute || time.Until(expires) > bootstrapKeyLifetime {
			t.Errorf("expiration: %s %v", request.Expiration, err)
		}
		fmt.Fprintf(w, `{"preAuthKey":{"key":%q}}`, secret)
	})
	previous := reviewServiceAccountToken
	t.Cleanup(func() { reviewServiceAccountToken = previous })
	reviewServiceAccountToken = func(_ context.Context, token, audience string) (string, error) {
		if audience != bootstrapAudience {
			t.Errorf("wrong audience %q", audience)
		}
		switch token {
		case "allowed":
			return bootstrapServiceAccount, nil
		case "app-service":
			return "system:serviceaccount:os-framework:os-internal", nil
		default:
			return "", errors.New("invalid audience or token")
		}
	}
	router := gin.New()
	registerBootstrap(router)
	for _, tc := range []struct {
		token  string
		status int
	}{{"", 401}, {"wrong-audience", 401}, {"app-service", 403}, {"allowed", 200}} {
		req := httptest.NewRequest("POST", "/bootstrap/tailscale-authkey", strings.NewReader(`{"reusable":true,"aclTags":["tag:admin"],"user":"123"}`))
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != tc.status || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("token %s: status %d headers %v", tc.token, w.Code, w.Header())
		}
		if tc.status == 200 && (w.Body.String() != secret || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain")) {
			t.Fatal("expected plain text key")
		}
	}
	if called != 1 {
		t.Fatalf("Headscale called %d times", called)
	}
}

func TestBootstrapDoesNotLeakErrorBody(t *testing.T) {
	for _, body := range []string{`{"key":"hskey-auth-sensitive"}`, `<html>error</html>`, `{"preAuthKey":{"key":"hskey-auth-masked-***"}}`} {
		t.Run(body, func(t *testing.T) {
			mockBootstrapHeadscale(t, func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, body)
			})
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("POST", "/", nil)
			createBootstrapAuthKey(c)
			if w.Code != 502 || strings.Contains(w.Body.String(), "hskey-auth-") || strings.Contains(w.Body.String(), "<html>") {
				t.Fatalf("unsafe response: %d %s", w.Code, w.Body.String())
			}
		})
	}
	mockBootstrapHeadscale(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprint(w, "hskey-auth-sensitive")
	})
	if err := bootstrapRequest(context.Background(), "GET", "/preauthkey", nil, nil); err == nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("unsafe error: %v", err)
	}
}

func TestBootstrapRequestCancellation(t *testing.T) {
	mockBootstrapHeadscale(t, func(w http.ResponseWriter, r *http.Request) { t.Error("canceled request was sent") })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := bootstrapRequest(ctx, "GET", "/preauthkey", nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation: %v", err)
	}
}
