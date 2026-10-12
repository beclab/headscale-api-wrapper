package main

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const downstreamTimeout = 10 * time.Second
const policyOperationTimeout = 30 * time.Second

// One token serializes the entire policy read-modify-write operation.
var policyUpdateMu = make(chan struct{}, 1)

func beginPolicyOperation(c *gin.Context) context.CancelFunc {
	ctx, cancel := context.WithTimeout(c.Request.Context(), policyOperationTimeout)
	c.Request = c.Request.WithContext(ctx)
	return cancel
}

func lockPolicy(c *gin.Context) bool {
	ctx := c.Request.Context()
	select {
	case policyUpdateMu <- struct{}{}:
		if ctx.Err() == nil {
			return true
		}
		unlockPolicy()
	case <-ctx.Done():
	}
	c.AbortWithStatusJSON(http.StatusGatewayTimeout, response{Code: requestHeadscaleError, Message: "policy operation canceled or timed out"})
	return false
}

func unlockPolicy() { <-policyUpdateMu }
