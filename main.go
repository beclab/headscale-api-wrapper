package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	resty "github.com/go-resty/resty/v2"
	"github.com/spf13/pflag"
)

const (
	requestHeadscaleError int = 1001
	internalPolicyPort        = 8001
)

type response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

type createPreAuthKeyRequest struct {
	User       string   `json:"user,omitempty"`
	Reusable   bool     `json:"reusable,omitempty"`
	Ephemeral  bool     `json:"ephemeral,omitempty"`
	Expiration string   `json:"expiration,omitempty"`
	AclTags    []string `json:"aclTags,omitempty"`
}

type listUsersAPIResponse struct {
	Users []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"users"`
}

type listNodesAPIResponse struct {
	Nodes []json.RawMessage `json:"nodes"`
}

type nodeIdentity struct {
	ID   string `json:"id"`
	User struct {
		Name string `json:"name"`
	} `json:"user"`
}

var preauthkeyStr string = "/preauthkey"

const nodePath = "/node"

var apiKey string
var host string
var port int
var url string
var config string

var headers map[string]string
var proxyPrefix string = "/headscale"

const authenticatedUserContextKey = "authenticated-user"

func restyResponseError(operation string, resp *resty.Response) error {
	if resp == nil {
		log.Printf("%s failed: empty response", operation)
		return fmt.Errorf("%s failed: empty response", operation)
	}
	body := strings.TrimSpace(resp.String())
	if len(body) > 512 {
		body = body[:512]
	}
	log.Printf("%s failed status=%d body=%q", operation, resp.StatusCode(), body)
	return fmt.Errorf("%s failed: status %d", operation, resp.StatusCode())
}

func restyRequestError(operation string, err error) error {
	log.Printf("%s failed error=%v", operation, err)
	return fmt.Errorf("%s failed: %w", operation, err)
}

func init() {
	apiKey = os.Getenv("APIKEY")
	if !strings.HasPrefix(apiKey, "hskey-api-") {
		panic("APIKEY must be a hskey-api- key")
	}
	pflag.StringVar(&host, "host", "localhost", "headscale server hostname")
	pflag.IntVar(&port, "port", 8080, "headscale server port")
	pflag.StringVar(&config, "config", "/etc/headscale/config.yaml", "deprecated headscale config file")
	pflag.Parse()
	url = fmt.Sprintf("http://%s:%d/api/v1", host, port)
	// url = "https://headscale.hu9443.snowinning.com/api/v1"
	headers = map[string]string{
		"Authorization": "Bearer " + apiKey,
	}
}

func requireAuthenticatedUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		username, err := authenticatedUser(c.Request)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, response{
				Code:    requestHeadscaleError,
				Message: err.Error(),
			})
			return
		}

		c.Set(authenticatedUserContextKey, username)
		c.Next()
	}
}

func requireOwnedNode(c *gin.Context, nodeID string) bool {
	username := c.GetString(authenticatedUserContextKey)
	owned, err := userOwnsNode(c.Request.Context(), username, nodeID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response{
			Code:    requestHeadscaleError,
			Message: err.Error(),
		})
		return false
	}
	if !owned {
		c.JSON(http.StatusForbidden, response{
			Code:    requestHeadscaleError,
			Message: "node does not belong to the authenticated user",
		})
		return false
	}
	return true
}

func main() {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Lmicroseconds)
	// Invalid configuration is fatal, but unavailable dependencies are retried
	// in the background so user synchronization cannot block the HTTP APIs.
	// Use Background (not NotifyContext): catching SIGTERM here would stop only
	// the sync goroutines while gin keeps running and the process may not exit.
	if err := startHeadscaleUserSync(context.Background()); err != nil {
		log.Fatalf("configure Headscale user sync: %v", err)
	}

	{
		router := gin.Default()
		router.SetTrustedProxies(nil)

		router.GET(proxyPrefix+preauthkeyStr, getPreAuthKey)

		go func() {
			if err := router.Run(":9000"); err != nil {
				log.Fatalf("preauthkey server failed: %v", err)
			}
		}()
	}

	// gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.SetTrustedProxies(nil)

	registerBootstrap(router)

	rgProxy := router.Group(proxyPrefix)
	rgProxy.Use(requireAuthenticatedUser())
	rgProxy.GET("/policy/self-mesh", getSelfMesh)
	rgProxy.PUT("/policy/self-mesh", putSelfMesh)
	rgProxy.GET("/olares-users", requireOwnerFor("list Olares users"), getOlaresUsers)
	rgProxy.GET("/policy/lan-groups", requireOwnerFor("manage LAN groups"), getLanGroups)
	rgProxy.PUT("/policy/lan-groups/:name", requireOwnerFor("manage LAN groups"), putLanGroup)
	rgProxy.DELETE("/policy/lan-groups/:name", requireOwnerFor("manage LAN groups"), deleteLanGroup)
	rgProxy.GET("/policy/exit-users", requireOwner(), getExitUsers)
	rgProxy.PUT("/policy/exit-users/:username", requireOwner(), grantExitUser)
	rgProxy.DELETE("/policy/exit-users/:username", requireOwner(), revokeExitUser)
	rgProxy.GET("/policy/subnet-router/routes", requireOwnerFor("manage subnet routes"), getSubnetRoutes)
	rgProxy.PUT("/policy/subnet-router/routes", requireOwnerFor("manage subnet routes"), putSubnetRoutes)
	rgProxy.GET("/policy/subnet-router/access", requireOwnerFor("manage subnet access"), getSubnetAccess)
	rgProxy.PUT("/policy/subnet-router/access", requireOwnerFor("manage subnet access"), putSubnetAccess)
	rgProxy.GET(nodePath, func(c *gin.Context) {
		machines, err := getDevicesForUser(c.Request.Context(), c.GetString(authenticatedUserContextKey))
		if err != nil {
			c.JSON(http.StatusInternalServerError, response{
				Code:    requestHeadscaleError,
				Message: err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, response{
			Code:    0,
			Message: "",
			Data:    machines,
		})
	})

	rgProxy.DELETE(nodePath+"/:nodeID", func(c *gin.Context) {
		nodeID := strings.TrimSpace(c.Param("nodeID"))
		if nodeID == "" {
			c.JSON(http.StatusBadRequest, response{Code: requestHeadscaleError, Message: "node ID is required"})
			return
		}
		if !requireOwnedNode(c, nodeID) {
			return
		}

		machines, err := removeDevice(c.Request.Context(), nodeID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, response{
				Code:    requestHeadscaleError,
				Message: err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, response{Code: 0, Message: "", Data: machines})
		logMutation(c, "node.delete", true, fmt.Sprintf("nodeID=%q", nodeID))
	})

	rgProxy.PATCH(nodePath+"/:nodeID", func(c *gin.Context) {
		nodeID := strings.TrimSpace(c.Param("nodeID"))
		if nodeID == "" {
			c.JSON(http.StatusBadRequest, response{Code: requestHeadscaleError, Message: "node ID is required"})
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		if !bindJSON(c, &req, 4096) {
			return
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			c.JSON(http.StatusBadRequest, response{Code: requestHeadscaleError, Message: "name is required"})
			return
		}
		if !requireOwnedNode(c, nodeID) {
			return
		}

		machines, err := renameDevice(c.Request.Context(), nodeID, name)
		if err != nil {
			c.JSON(http.StatusInternalServerError, response{
				Code:    requestHeadscaleError,
				Message: err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, response{Code: 0, Message: "", Data: machines})
		logMutation(c, "node.rename", true, fmt.Sprintf("nodeID=%q", nodeID))
	})

	policyRouter := gin.Default()
	policyRouter.SetTrustedProxies(nil)
	policyRouter.GET("/internal/policy/application-ports", getApplicationPorts)
	policyRouter.PUT("/internal/policy/application-ports", putApplicationPorts)
	go func() {
		if err := policyRouter.Run(fmt.Sprintf(":%d", internalPolicyPort)); err != nil {
			log.Fatalf("application policy server failed: %v", err)
		}
	}()

	if err := router.Run(":8000"); err != nil {
		log.Fatalf("API server failed: %v", err)
	}
}

func getPreAuthKey(c *gin.Context) {
	username, err := authenticatedUser(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, response{Code: requestHeadscaleError, Message: err.Error()})
		return
	}
	available, err := verifyOlaresUserAvailable(c.Request.Context(), username)
	if err != nil {
		c.JSON(http.StatusBadGateway, response{Code: requestHeadscaleError, Message: err.Error()})
		return
	}
	if !available {
		c.JSON(http.StatusForbidden, response{Code: requestHeadscaleError, Message: "Olares user is not available"})
		return
	}

	uid, err := resolveUserIDString(c.Request.Context(), username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response{Code: requestHeadscaleError, Message: err.Error()})
		return
	}
	data := createPreAuthKeyRequest{
		User:       uid,
		Reusable:   true,
		Ephemeral:  false,
		Expiration: time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
	}
	resp, err := createPreAuthKey(c.Request.Context(), &data, preauthkeyStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response{Code: requestHeadscaleError, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, response{Code: 0, Message: "", Data: resp})
	logMutation(c, "preauthkey.create", true, fmt.Sprintf("username=%q", username))
}

func resolveUserIDString(ctx context.Context, username string) (string, error) {
	return resolveUserIDStringWithCreate(ctx, username, false)
}

func resolveUserIDStringWithCreate(ctx context.Context, username string, createIfMissing bool) (string, error) {
	var parsed listUsersAPIResponse
	resp, err := resty.New().SetTimeout(downstreamTimeout).R().SetContext(ctx).SetHeaders(headers).
		SetResult(&parsed).
		Get(url + "/user")
	if err != nil {
		return "", restyRequestError("list users", err)
	}
	if resp == nil || resp.StatusCode() != 200 {
		return "", restyResponseError("list users", resp)
	}
	for _, u := range parsed.Users {
		if u.Name == username {
			s := strings.TrimSpace(u.ID)
			if s == "" {
				return "", fmt.Errorf("empty user id for user %q", u.Name)
			}
			if _, err := strconv.ParseUint(s, 10, 64); err != nil {
				return "", fmt.Errorf("invalid user id %q for user %q: %w", u.ID, u.Name, err)
			}
			return s, nil
		}
	}
	if !createIfMissing {
		return "", fmt.Errorf("Headscale user %q does not exist", username)
	}

	resp, createErr := resty.New().SetTimeout(downstreamTimeout).R().SetContext(ctx).SetHeaders(headers).
		SetBody(map[string]string{"name": username}).
		Post(url + "/user")

	// Another concurrent request may have created the user first. Treat the
	// create operation as idempotent and use Headscale as the source of truth.
	uid, lookupErr := resolveUserIDStringWithCreate(ctx, username, false)
	if lookupErr == nil {
		return uid, nil
	}
	if createErr != nil {
		return "", restyRequestError("create user", createErr)
	}
	if resp == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusCreated) {
		return "", restyResponseError("create user", resp)
	}
	return "", lookupErr
}

func createPreAuthKey(ctx context.Context, data *createPreAuthKeyRequest, urlSuffix string) (interface{}, error) {
	var result interface{}
	resp, err := resty.New().SetTimeout(downstreamTimeout).R().SetContext(ctx).SetHeaders(headers).
		SetBody(data).
		SetResult(&result).
		Post(url + urlSuffix)
	if err != nil {
		return nil, restyRequestError("createPreAuthKey", err)
	}

	if resp == nil || resp.StatusCode() != 200 {
		return nil, restyResponseError("createPreAuthKey", resp)
	}

	return result, nil
}

func listDevices(ctx context.Context) (listNodesAPIResponse, error) {
	var result listNodesAPIResponse
	resp, err := resty.New().SetTimeout(downstreamTimeout).R().SetContext(ctx).SetHeaders(headers).
		SetResult(&result).
		Get(url + nodePath)
	if err != nil {
		return listNodesAPIResponse{}, restyRequestError("getDevices", err)
	}

	if resp == nil || resp.StatusCode() != 200 {
		return listNodesAPIResponse{}, restyResponseError("getDevices", resp)
	}

	return result, nil
}

func getDevicesForUser(ctx context.Context, username string) (listNodesAPIResponse, error) {
	result, err := listDevices(ctx)
	if err != nil {
		return listNodesAPIResponse{}, err
	}

	filtered := make([]json.RawMessage, 0, len(result.Nodes))
	for _, rawNode := range result.Nodes {
		var node nodeIdentity
		if err := json.Unmarshal(rawNode, &node); err != nil {
			return listNodesAPIResponse{}, fmt.Errorf("decode node identity failed: %w", err)
		}
		if node.User.Name == username {
			filtered = append(filtered, rawNode)
		}
	}

	result.Nodes = filtered
	return result, nil
}

func userOwnsNode(ctx context.Context, username, nodeID string) (bool, error) {
	result, err := listDevices(ctx)
	if err != nil {
		return false, err
	}

	for _, rawNode := range result.Nodes {
		var node nodeIdentity
		if err := json.Unmarshal(rawNode, &node); err != nil {
			return false, fmt.Errorf("decode node identity failed: %w", err)
		}
		if node.ID == nodeID {
			return node.User.Name == username, nil
		}
	}

	return false, nil
}

func removeDevice(ctx context.Context, nodeID string) (interface{}, error) {
	var result interface{}
	resp, err := resty.New().SetTimeout(downstreamTimeout).R().SetContext(ctx).SetHeaders(headers).
		SetResult(&result).
		Delete(url + "/node/" + neturl.PathEscape(nodeID))
	if err != nil {
		return nil, restyRequestError("removeDevice", err)
	}

	if resp == nil || resp.StatusCode() != 200 {
		return nil, restyResponseError("removeDevice", resp)
	}

	return result, nil
}

func renameDevice(ctx context.Context, nodeID, name string) (interface{}, error) {
	var result interface{}
	resp, err := resty.New().SetTimeout(downstreamTimeout).R().SetContext(ctx).SetHeaders(headers).
		SetResult(&result).
		Post(url + "/node/" + neturl.PathEscape(nodeID) + "/rename/" + neturl.PathEscape(name))
	if err != nil {
		return nil, restyRequestError("renameDevice", err)
	}

	if resp == nil || resp.StatusCode() != 200 {
		return nil, restyResponseError("renameDevice", resp)
	}

	return result, nil
}
