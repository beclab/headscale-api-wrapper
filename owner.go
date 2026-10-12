package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

func requireOwner() gin.HandlerFunc {
	return requireOwnerFor("manage exit-node access")
}

func requireOwnerFor(action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.GetString(authenticatedUserContextKey)
		owner, err := verifyOlaresOwner(c.Request.Context(), username)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadGateway, response{
				Code:    requestHeadscaleError,
				Message: err.Error(),
			})
			return
		}
		if !owner {
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
	return found && user.Metadata.Annotations[ownerRoleAnnotation] == "owner", err
}

func readOlaresResource(ctx context.Context, suffix string, result any) (bool, error) {
	username := suffix
	username = strings.TrimSpace(username)
	if username == "" {
		return false, errors.New("authenticated Olares username is empty")
	}

	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	if host == "" || port == "" {
		return false, errors.New("Kubernetes API service is unavailable")
	}

	caPEM, err := os.ReadFile(serviceAccountCAPath)
	if err != nil {
		return false, fmt.Errorf("read Kubernetes service account CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return false, errors.New("parse Kubernetes service account CA")
	}
	token, err := os.ReadFile(serviceAccountTokenPath)
	if err != nil {
		return false, fmt.Errorf("read Kubernetes service account token: %w", err)
	}
	if len(strings.TrimSpace(string(token))) == 0 {
		return false, errors.New("Kubernetes service account token is empty")
	}

	endpoint := fmt.Sprintf(
		"https://%s/apis/iam.kubesphere.io/v1alpha2/users%s",
		net.JoinHostPort(host, port),
		suffix,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("create Olares user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		}},
	}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("get Olares user %q: %w", username, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return false, fmt.Errorf("get Olares user %q: status %d: %s", username, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return false, fmt.Errorf("decode Olares user %q: %w", username, err)
	}
	return true, nil
}
