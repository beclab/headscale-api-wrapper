package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
)

type response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

type createPreAuthKeyRequest struct {
	User       string   `protobuf:"bytes,1,opt,name=user,proto3" json:"user,omitempty"`
	Reusable   bool     `protobuf:"varint,2,opt,name=reusable,proto3" json:"reusable,omitempty"`
	Ephemeral  bool     `protobuf:"varint,3,opt,name=ephemeral,proto3" json:"ephemeral,omitempty"`
	Expiration string   `protobuf:"bytes,4,opt,name=expiration,proto3" json:"expiration,omitempty"`
	AclTags    []string `protobuf:"bytes,5,rep,name=acl_tags,json=aclTags,proto3" json:"aclTags,omitempty"`
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
var getMachineStr string = "/node"
var removeMachineStr string = "/node/:machineId"
var renameMachineStr string = "/node/:machineId/rename/:newName"
var routeEnableStr string = "/node/approve_routes"

var apiKey string
var host string
var port int
var url string
var config string

var headers map[string]string
var proxyPrefix string = "/headscale"

const authenticatedUserContextKey = "authenticated-user"

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
	owned, err := userOwnsNode(username, nodeID)
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

	{
		router := gin.Default()
		router.SetTrustedProxies(nil)

		router.GET(proxyPrefix+preauthkeyStr, func(c *gin.Context) {

			username, err := authenticatedUser(c.Request)
			if err != nil {
				c.JSON(http.StatusUnauthorized, response{
					Code:    requestHeadscaleError,
					Message: err.Error(),
				})
				return
			}

			uid, err := resolveUserIDString(username)
			if err != nil {
				c.JSON(http.StatusInternalServerError, response{
					Code:    requestHeadscaleError,
					Message: err.Error(),
				})
				return
			}
			data := createPreAuthKeyRequest{
				User:       uid,
				Reusable:   true,
				Ephemeral:  false,
				Expiration: time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
			}
			fmt.Println(data)

			resp, err := createPreAuthKey(&data, preauthkeyStr)
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
				Data:    resp,
			})
		})

		go router.Run(":9000")
	}

	// gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.SetTrustedProxies(nil)

	rgProxy := router.Group(proxyPrefix)
	rgProxy.Use(requireAuthenticatedUser())
	rgProxy.POST(getMachineStr, func(c *gin.Context) {
		var req struct {
			ID string `json:"id,omitempty"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, response{
				Code:    requestHeadscaleError,
				Message: err.Error(),
			})
			return
		}

		if req.ID != "" {
			if !requireOwnedNode(c, req.ID) {
				return
			}
			machines, err := removeDevice(strings.Replace(removeMachineStr, ":machineId", req.ID, 1))
			if err != nil {
				c.JSON(http.StatusInternalServerError, response{
					Code:    requestHeadscaleError,
					Message: err.Error(),
				})
				return
			}
			c.JSON(http.StatusOK, response{Code: 0, Message: "", Data: machines})
			return
		}

		machines, err := getDevicesForUser(c.GetString(authenticatedUserContextKey))
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

	rgProxy.POST("/node/rename", func(c *gin.Context) {
		var req struct {
			ID   string `json:"id" binding:"required"`
			Name string `json:"name" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, response{Code: requestHeadscaleError, Message: err.Error()})
			return
		}
		if !requireOwnedNode(c, req.ID) {
			return
		}

		machines, err := renameDevice(strings.Replace(strings.Replace(renameMachineStr, ":machineId", req.ID, 1), ":newName", req.Name, 1))
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

	rgProxy.POST(routeEnableStr, func(c *gin.Context) {
		var req struct {
			ID     string   `json:"id" binding:"required"`
			Routes []string `json:"routes"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, response{
				Code:    requestHeadscaleError,
				Message: err.Error(),
			})
			return
		}
		if !requireOwnedNode(c, req.ID) {
			return
		}
		result, err := routeEnable(req.ID, req.Routes)
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
			Data:    result,
		})
	})

	router.Run(":8000")
}

func resolveUserIDString(username string) (string, error) {
	return resolveUserIDStringWithCreate(username, true)
}

func resolveUserIDStringWithCreate(username string, createIfMissing bool) (string, error) {
	var parsed listUsersAPIResponse
	resp, err := resty.New().R().SetHeaders(headers).
		SetResult(&parsed).
		Get(url + "/user")
	if err != nil {
		return "", fmt.Errorf("list users failed, err: %s, data: %s", err, resp.String())
	}
	if resp.StatusCode() != 200 {
		return "", fmt.Errorf("list users failed, data: %s", resp.String())
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
		return "", fmt.Errorf("user %q was created but could not be found", username)
	}

	resp, createErr := resty.New().R().SetHeaders(headers).
		SetBody(map[string]string{"name": username}).
		Post(url + "/user")

	// Another concurrent request may have created the user first. Treat the
	// create operation as idempotent and use Headscale as the source of truth.
	uid, lookupErr := resolveUserIDStringWithCreate(username, false)
	if lookupErr == nil {
		return uid, nil
	}
	if createErr != nil {
		return "", fmt.Errorf("create user failed, err: %s", createErr)
	}
	if resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusCreated {
		return "", fmt.Errorf("create user failed, data: %s", resp.String())
	}
	return "", lookupErr
}

func createPreAuthKey(data *createPreAuthKeyRequest, urlSuffix string) (interface{}, error) {
	var result interface{}
	resp, err := resty.New().R().SetHeaders(headers).
		SetBody(data).
		SetResult(&result).
		Post(url + urlSuffix)
	if err != nil {
		return nil, fmt.Errorf("createPreAuthKey failed, err: %s, data: %s", err, resp.String())
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("createPreAuthKey failed, data: %s", resp.String())
	}

	return result, nil
}

func listDevices() (listNodesAPIResponse, error) {
	var result listNodesAPIResponse
	resp, err := resty.New().R().SetHeaders(headers).
		SetResult(&result).
		Get(url + getMachineStr)
	if err != nil {
		return listNodesAPIResponse{}, fmt.Errorf("getDevices failed, err: %s, data: %s", err, resp.String())
	}

	if resp.StatusCode() != 200 {
		return listNodesAPIResponse{}, fmt.Errorf("getDevices failed, data: %s", resp.String())
	}

	return result, nil
}

func getDevicesForUser(username string) (listNodesAPIResponse, error) {
	result, err := listDevices()
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

func userOwnsNode(username, nodeID string) (bool, error) {
	result, err := listDevices()
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

func removeDevice(urlSuffix string) (interface{}, error) {
	var result interface{}
	resp, err := resty.New().R().SetHeaders(headers).
		SetResult(&result).
		Delete(url + urlSuffix)
	if err != nil {
		return nil, fmt.Errorf("removeDevice failed, err: %s, data: %s", err, resp.String())
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("removeDevice failed, data: %s", resp.String())
	}

	return result, nil
}

func renameDevice(urlSuffix string) (interface{}, error) {
	var result interface{}
	resp, err := resty.New().R().SetHeaders(headers).
		SetResult(&result).
		Post(url + urlSuffix)
	if err != nil {
		return nil, fmt.Errorf("renameDevice failed, err: %s, data: %s", err, resp.String())
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("renameDevice failed, data: %s", resp.String())
	}

	return result, nil
}

func routeEnable(nodeID string, routes []string) (interface{}, error) {
	var result interface{}
	body := map[string][]string{"routes": routes}
	if routes == nil {
		body["routes"] = []string{}
	}
	resp, err := resty.New().R().SetHeaders(headers).
		SetBody(body).
		SetResult(&result).
		Post(url + "/node/" + nodeID + "/approve_routes")
	if err != nil {
		return nil, fmt.Errorf("routeEnable failed, err: %s, data: %s", err, resp.String())
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("routeEnable failed, data: %s", resp.String())
	}

	return result, nil
}
