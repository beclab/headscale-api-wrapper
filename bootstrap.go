package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	resty "github.com/go-resty/resty/v2"
)

const bootstrapServiceAccount = "system:serviceaccount:os-network:tailscale"
const bootstrapAudience = "headscale-bootstrap"
const bootstrapKeyLifetime = 5 * time.Minute

var bootstrapKeyPattern = regexp.MustCompile(`^hskey-auth-[a-zA-Z0-9_-]+$`)

type bootstrapPreAuthKey struct {
	Key string `json:"key"`
}

func registerBootstrap(router *gin.Engine) {
	bootstrap := router.Group("/bootstrap")
	bootstrap.Use(func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.Next()
	})
	bootstrap.Use(requireAllowedServiceAccount(bootstrapServiceAccount, bootstrapAudience))
	bootstrap.POST("/tailscale-authkey", createBootstrapAuthKey)
}

// Do not include Headscale response bodies in errors: they can contain keys.
func bootstrapRequest(ctx context.Context, method, path string, body, result any) error {
	resp, err := resty.New().SetTimeout(downstreamTimeout).R().SetContext(ctx).
		SetHeaders(headers).SetBody(body).Execute(method, url+path)
	if err != nil {
		return fmt.Errorf("Headscale bootstrap request failed: %w", err)
	}
	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("Headscale bootstrap request returned HTTP %d", resp.StatusCode())
	}
	if result != nil {
		if err := json.Unmarshal(resp.Body(), result); err != nil {
			return errors.New("invalid Headscale bootstrap response")
		}
	}
	return nil
}

func createBootstrapAuthKey(c *gin.Context) {
	var result struct {
		Key bootstrapPreAuthKey `json:"preAuthKey"`
	}
	request := createPreAuthKeyRequest{
		Reusable: false, Ephemeral: false,
		Expiration: time.Now().UTC().Add(bootstrapKeyLifetime).Format(time.RFC3339),
		AclTags:    []string{"tag:olares"},
	}
	err := bootstrapRequest(c.Request.Context(), http.MethodPost, "/preauthkey", request, &result)
	if err == nil && !bootstrapKeyPattern.MatchString(result.Key.Key) {
		err = errors.New("Headscale returned an invalid bootstrap key")
	}
	if err != nil {
		log.Printf("bootstrap authkey failed error=%v", err)
		c.JSON(http.StatusBadGateway, response{Code: requestHeadscaleError, Message: err.Error()})
		return
	}
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(result.Key.Key))
	log.Printf("bootstrap authkey issued serviceAccount=%q", bootstrapServiceAccount)
}
