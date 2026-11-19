package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const ownerRoleAnnotation = "bytetrade.io/owner-role"

var verifyOlaresOwner = isOlaresOwner
var verifyOlaresUserAvailable = isOlaresUserAvailable

type olaresUser struct {
	Metadata struct {
		Name              string            `json:"name"`
		Annotations       map[string]string `json:"annotations"`
		DeletionTimestamp *string           `json:"deletionTimestamp"`
	} `json:"metadata"`
	Status struct {
		State string `json:"state"`
	} `json:"status"`
}

func (u olaresUser) availableForAuthorization() bool {
	return u.Status.State == "Created" && u.Metadata.DeletionTimestamp == nil
}

func (u olaresUser) isAvailableOwner() bool {
	return u.availableForAuthorization() && u.Metadata.Annotations[ownerRoleAnnotation] == "owner"
}

func requireOwner() gin.HandlerFunc {
	return requireOwnerFor("manage exit-node access")
}

func requireOwnerFor(action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.GetString(authenticatedUserContextKey)
		owner, err := verifyOlaresOwner(c.Request.Context(), username)
		if err != nil {
			logMutationFailure(c, "owner.authorize", err)
			c.AbortWithStatusJSON(http.StatusBadGateway, response{
				Code:    requestHeadscaleError,
				Message: err.Error(),
			})
			return
		}
		if !owner {
			logMutationFailure(c, action, errors.New("authenticated user is not the Olares owner"))
			c.AbortWithStatusJSON(http.StatusForbidden, response{
				Code:    requestHeadscaleError,
				Message: "only the Olares owner may " + action,
			})
			return
		}
		c.Next()
	}
}

func isOlaresOwner(ctx context.Context, username string) (bool, error) {
	if strings.TrimSpace(username) == "" {
		return false, errors.New("authenticated Olares username is empty")
	}
	var user olaresUser
	found, err := readOlaresResource(ctx, "/"+neturl.PathEscape(username), &user)
	return found && user.isAvailableOwner(), err
}

func isOlaresUserAvailable(ctx context.Context, username string) (bool, error) {
	if strings.TrimSpace(username) == "" {
		return false, errors.New("authenticated Olares username is empty")
	}
	var user olaresUser
	found, err := readOlaresResource(ctx, "/"+neturl.PathEscape(username), &user)
	return found && user.availableForAuthorization(), err
}

func readOlaresResource(ctx context.Context, suffix string, result any) (bool, error) {
	username := suffix
	username = strings.TrimSpace(username)
	if username == "" {
		return false, errors.New("authenticated Olares username is empty")
	}

	api, err := newOlaresUserAPI()
	if err != nil {
		return false, err
	}
	defer api.transport.CloseIdleConnections()
	resp, err := api.get(ctx, suffix, 10*time.Second)
	if err != nil {
		return false, fmt.Errorf("get Olares user %q: %w", username, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("get Olares user %q: status %d", username, resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return false, fmt.Errorf("decode Olares user %q: %w", username, err)
	}
	return true, nil
}

type olaresUserAPI struct {
	endpoint  string
	token     string
	transport *http.Transport
}

// newOlaresUserAPI reads the service account on every call because the
// projected token rotates.
func newOlaresUserAPI() (*olaresUserAPI, error) {
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	if host == "" || port == "" {
		return nil, errors.New("Kubernetes API service is unavailable")
	}

	caPEM, err := os.ReadFile(serviceAccountCAPath)
	if err != nil {
		return nil, fmt.Errorf("read Kubernetes service account CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("parse Kubernetes service account CA")
	}
	token, err := os.ReadFile(serviceAccountTokenPath)
	if err != nil {
		return nil, fmt.Errorf("read Kubernetes service account token: %w", err)
	}
	if len(strings.TrimSpace(string(token))) == 0 {
		return nil, errors.New("Kubernetes service account token is empty")
	}

	return &olaresUserAPI{
		endpoint: fmt.Sprintf("https://%s/apis/iam.kubesphere.io/v1alpha2/users", net.JoinHostPort(host, port)),
		token:    strings.TrimSpace(string(token)),
		transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		}},
	}, nil
}

func (a *olaresUserAPI) get(ctx context.Context, suffix string, timeout time.Duration) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+suffix, nil)
	if err != nil {
		return nil, fmt.Errorf("create Olares user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	return (&http.Client{Timeout: timeout, Transport: a.transport}).Do(req)
}
