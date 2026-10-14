package main

import (
	"log"

	"github.com/gin-gonic/gin"
)

// logMutation records the outcome of a state-changing business operation.
// Keep details limited to identifiers and counts; never log credentials,
// preauth keys, request bodies, or the full policy.
func logMutation(c *gin.Context, operation string, changed bool, detail string) {
	user := c.GetString(authenticatedUserContextKey)
	if user == "" {
		user = "-"
	}
	if detail == "" {
		log.Printf("mutation operation=%s user=%q changed=%t", operation, user, changed)
		return
	}
	log.Printf("mutation operation=%s user=%q changed=%t %s", operation, user, changed, detail)
}

func logMutationFailure(c *gin.Context, operation string, err error) {
	user := c.GetString(authenticatedUserContextKey)
	if user == "" {
		user = "-"
	}
	log.Printf("mutation failed operation=%s user=%q error=%v", operation, user, err)
}
