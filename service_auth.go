package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	serviceAccountCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultServiceAuthNS    = "os-framework"
	defaultServiceAuthSA    = "os-internal"
	defaultServiceAudience  = "headscale-policy"
)

type tokenReview struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Spec       tokenReviewSpec   `json:"spec"`
	Status     tokenReviewStatus `json:"status,omitempty"`
}

type tokenReviewSpec struct {
	Token     string   `json:"token"`
	Audiences []string `json:"audiences"`
}

type tokenReviewStatus struct {
	Authenticated bool `json:"authenticated"`
	User          struct {
		Username string `json:"username"`
	} `json:"user"`
	Audiences []string `json:"audiences,omitempty"`
	Error     string   `json:"error,omitempty"`
}

var reviewServiceAccountToken = kubernetesTokenReview

func requireServiceAccount() gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := strings.Fields(c.GetHeader("Authorization"))
		if len(authorization) != 2 || !strings.EqualFold(authorization[0], "Bearer") || authorization[1] == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, response{Code: requestHeadscaleError, Message: "missing service account bearer token"})
			return
		}
		token := authorization[1]

		username, err := reviewServiceAccountToken(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, response{Code: requestHeadscaleError, Message: err.Error()})
			return
		}

		expectedNS := strings.TrimSpace(os.Getenv("POLICY_CLIENT_NAMESPACE"))
		if expectedNS == "" {
			expectedNS = defaultServiceAuthNS
		}
		expectedSA := strings.TrimSpace(os.Getenv("POLICY_CLIENT_SERVICE_ACCOUNT"))
		if expectedSA == "" {
			expectedSA = defaultServiceAuthSA
		}
		expectedUsername := fmt.Sprintf("system:serviceaccount:%s:%s", expectedNS, expectedSA)
		if username != expectedUsername {
			c.AbortWithStatusJSON(http.StatusForbidden, response{Code: requestHeadscaleError, Message: "service account is not allowed to manage Headscale policy"})
			return
		}

		c.Next()
	}
}

func kubernetesTokenReview(token string) (string, error) {
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	if host == "" || port == "" {
		return "", errors.New("Kubernetes API service is unavailable")
	}

	caPEM, err := os.ReadFile(serviceAccountCAPath)
	if err != nil {
		return "", fmt.Errorf("read Kubernetes service account CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return "", errors.New("parse Kubernetes service account CA")
	}

	audience := strings.TrimSpace(os.Getenv("POLICY_TOKEN_AUDIENCE"))
	if audience == "" {
		audience = defaultServiceAudience
	}
	payload, err := json.Marshal(tokenReview{
		APIVersion: "authentication.k8s.io/v1",
		Kind:       "TokenReview",
		Spec: tokenReviewSpec{
			Token:     token,
			Audiences: []string{audience},
		},
	})
	if err != nil {
		return "", fmt.Errorf("encode Kubernetes token review: %w", err)
	}
	reviewerToken, err := os.ReadFile(serviceAccountTokenPath)
	if err != nil {
		return "", fmt.Errorf("read wrapper service account token: %w", err)
	}
	if strings.TrimSpace(string(reviewerToken)) == "" {
		return "", errors.New("wrapper service account token is empty")
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		}},
	}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s:%s/apis/authentication.k8s.io/v1/tokenreviews", host, port), bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("create Kubernetes token review request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(reviewerToken)))

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("review Kubernetes service account token: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read Kubernetes token review response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("review Kubernetes service account token: status %d", resp.StatusCode)
	}

	var reviewed tokenReview
	if err := json.Unmarshal(body, &reviewed); err != nil {
		return "", fmt.Errorf("decode Kubernetes token review response: %w", err)
	}
	if !reviewed.Status.Authenticated {
		if reviewed.Status.Error != "" {
			return "", fmt.Errorf("service account token was not authenticated: %s", reviewed.Status.Error)
		}
		return "", errors.New("service account token was not authenticated")
	}
	if reviewed.Status.User.Username == "" {
		return "", errors.New("Kubernetes token review returned an empty username")
	}
	audienceAccepted := false
	for _, reviewedAudience := range reviewed.Status.Audiences {
		if reviewedAudience == audience {
			audienceAccepted = true
			break
		}
	}
	if !audienceAccepted {
		return "", fmt.Errorf("service account token is not valid for audience %q", audience)
	}
	return reviewed.Status.User.Username, nil
}
