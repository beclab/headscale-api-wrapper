package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	resty "github.com/go-resty/resty/v2"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	//	"strconv"
	"bytes"
	"encoding/json"
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

type OnionRequest struct {
	Op       string      `json:"op"`
	DataType string      `json:"dataType"`
	Version  string      `json:"version"`
	Group    string      `json:"group"`
	Data     interface{} `json:"data"`
}

var user string = "default"
var preauthkeyStr string = "/preauthkey"
var controlUrlStr string = "/controlurl"
var machineRegisterStr string = "/machine/register"
var getMachineStr string = "/machine"
var removeMachineStr string = "/machine/:machineId"
var renameMachineStr string = "/machine/:machineId/rename/:newName"
var moveMachineStr string = "/machine/:machineId/user"
var machineRoutesStr string = "/machine/:machineId/routes"
var machinetagsStr string = "/machine/:machineId/tags"
var routeDisableStr string = "/routes/:routeId/disable"
var routeEnableStr string = "/routes/:routeId/enable"

var apiKey string
var host string
var port int
var url string
var config string

type Response struct {
	ControlURL string `json:"controlurl"`
}

var headers map[string]string
var proxyPrefix string = "/headscale"
var innerPrefix string = "/inner"

func init() {
	apiKey = os.Getenv("APIKEY")
	if apiKey == "" {
		panic("need env APIKEY")
	}
	pflag.StringVar(&host, "host", "localhost", "headscale server hostname")
	pflag.IntVar(&port, "port", 8080, "headscale server port")
	pflag.StringVar(&config, "config", "/etc/headscale/config.yaml", "headscale config file")
	pflag.Parse()
	url = fmt.Sprintf("http://%s:%d/api/v1", host, port)
	// url = "https://headscale.hu9443.snowinning.com/api/v1"
	headers = map[string]string{
		"Authorization": "Bearer " + apiKey,
	}
}

func ProxyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Println("ProxyMiddleware")
		log.Println(c.Request.URL.Path)
		if c.Request.Method == "GET" && c.Request.URL.Path == proxyPrefix+preauthkeyStr {
			return
		}
		var oreq OnionRequest
		err := c.ShouldBindJSON(&oreq)
		if err != nil {
			c.Error(err)
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		log.Printf("%+v", oreq)
		if oreq.Data == nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		c.Set("data", oreq.Data)

		c.Next()
	}
}

func main() {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Lmicroseconds)

	{
		router := gin.Default()
		router.SetTrustedProxies(nil)

		router.GET(proxyPrefix+preauthkeyStr, func(c *gin.Context) {

			data := createPreAuthKeyRequest{
				User:       user,
				Reusable:   true,
				Ephemeral:  false,
				Expiration: time.Now().UTC().AddDate(10, 0, 0).Format(time.RFC3339),
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
	// rgProxy.Use(ProxyMiddleware())

	rgProxy.GET(preauthkeyStr, func(c *gin.Context) {
		c.Request.URL.Path = innerPrefix + preauthkeyStr
		router.HandleContext(c)
	})

	rgProxy.POST("/:name", func(c *gin.Context) {
		log.Println("one")
		name := c.Param("name")

		type zzz struct {
			Id string `json:"id,omitempty"`
		}
		var z zzz
		if err := c.ShouldBindJSON(&z); err != nil {
			log.Println("Error parsing JSON:", err)
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		if name == "machine" && z.Id != "" {
			c.Request.Method = "DELETE"
			c.Request.URL.Path = innerPrefix + "/" + name + "/" + z.Id
		} else {
			c.Request.Method = "GET"
			c.Request.URL.Path = innerPrefix + "/" + name
		}
		router.HandleContext(c)
		c.Request.Method = "POST"
	})

	rgProxy.POST("/:name/:action", func(c *gin.Context) {
		log.Println("two")
		name := c.Param("name")
		action := c.Param("action")

		type zzz struct {
			Key  string   `json:"key,omitempty"`
			Id   string   `json:"id,omitempty"`
			Tags []string `json:"tags,omitempty"`
			User string   `json:"user,omitempty"`
			Name string   `json:"name,omitempty"`
		}
		var z zzz
		if err := c.ShouldBindJSON(&z); err != nil {
			log.Println("Error parsing JSON:", err)
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		if action == "register" {
			c.Request.URL.Path = innerPrefix + "/" + name + "/" + action
			q := c.Request.URL.Query()
			q.Add("key", z.Key)
			c.Request.URL.RawQuery = q.Encode()
		} else if action == "user" {
			c.Request.URL.Path = innerPrefix + "/" + name + "/" + z.Id + "/" + action
			q := c.Request.URL.Query()
			q.Add("user", z.User)
			c.Request.URL.RawQuery = q.Encode()
		} else if action == "rename" {
			c.Request.URL.Path = innerPrefix + "/" + name + "/" + z.Id + "/" + action + "/" + z.Name
		} else if action == "delete" {
			c.Request.URL.Path = innerPrefix + "/" + name + "/" + z.Id
			c.Request.Method = "DELETE"
		} else if action == "routes" {
			c.Request.URL.Path = innerPrefix + "/" + name + "/" + z.Id + "/" + action
		} else {
			c.Request.URL.Path = innerPrefix + "/" + name + "/" + z.Id + "/" + action
		}

		log.Println(c.Request.URL.Path)

		if action == "routes" {
			c.Request.Method = "GET"
		} else if action == "tags" {
			if z.Tags != nil {
				v, _ := json.Marshal(map[string][]string{"tags": z.Tags})
				c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(v))
			} else {
				c.Request.Body = ioutil.NopCloser(bytes.NewBufferString(""))
			}
		} else {
			c.Request.Body = ioutil.NopCloser(bytes.NewBufferString(""))
		}

		router.HandleContext(c)
		c.Request.Method = "POST"
		log.Println("------------------------------>")
	})

	rg := router.Group(innerPrefix)

	rg.POST(machineRegisterStr, func(c *gin.Context) {
		key := c.Query("key")
		resp, err := newDevice(key, machineRegisterStr)
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

	rg.GET(controlUrlStr, func(c *gin.Context) {
		controlUrl, err := getControlURL()
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
			Data:    gin.H{"controlUrl": controlUrl},
		})
	})

	rg.GET(getMachineStr, func(c *gin.Context) {
		machines, err := getDevices(getMachineStr)
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

	rg.DELETE(removeMachineStr, func(c *gin.Context) {
		machineId := c.Param("machineId")
		machines, err := removeDevice(strings.Replace(removeMachineStr, ":machineId", machineId, 1))
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

	rg.POST(renameMachineStr, func(c *gin.Context) {
		machineId := c.Param("machineId")
		newName := c.Param("newName")
		machines, err := renameDevice(strings.Replace(strings.Replace(renameMachineStr, ":machineId", machineId, 1), ":newName", newName, 1))
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

	rg.POST(moveMachineStr, func(c *gin.Context) {
		machineId := c.Param("machineId")
		user := c.Query("user")
		machines, err := moveDevice(strings.Replace(moveMachineStr, ":machineId", machineId, 1), user)
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

	rg.GET(machineRoutesStr, func(c *gin.Context) {
		machineId := c.Param("machineId")
		routes, err := getMachineRoutes(strings.Replace(machineRoutesStr, ":machineId", machineId, 1))
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
			Data:    routes,
		})
	})

	rg.POST(machinetagsStr, func(c *gin.Context) {
		machineId := c.Param("machineId")
		data, err := c.GetRawData()
		if err != nil {
			c.JSON(http.StatusInternalServerError, response{
				Code:    requestHeadscaleError,
				Message: err.Error(),
			})
			return
		}
		routes, err := updateTags(strings.Replace(machinetagsStr, ":machineId", machineId, 1), data)
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
			Data:    routes,
		})
	})

	rg.POST(routeEnableStr, func(c *gin.Context) {
		routeId := c.Param("routeId")
		result, err := routeEnable(strings.Replace(routeEnableStr, ":routeId", routeId, 1))
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

	rg.POST(routeDisableStr, func(c *gin.Context) {
		routeId := c.Param("routeId")
		result, err := routeDisable(strings.Replace(routeDisableStr, ":routeId", routeId, 1))
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

func newDevice(key, urlSuffix string) (interface{}, error) {
	var result interface{}
	resp, err := resty.New().R().SetHeaders(headers).
		SetQueryParam("user", user).
		SetQueryParam("key", key).
		SetResult(&result).
		Post(url + urlSuffix)
	log.Printf("%+v", resp)
	if err != nil {
		return nil, fmt.Errorf("newDevice failed, err: %s, data: %s", err, resp.String())
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("newDevice failed, data: %s", resp.String())
	}

	return result, nil
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

func getControlURL() (string, error) {

	source, err := ioutil.ReadFile(config)
	if err != nil {
		fmt.Println("failed reading config file: %v", err)
		return "", err
	}

	data := make(map[interface{}]interface{})
	err = yaml.Unmarshal(source, &data)
	if err != nil {
		fmt.Println("unmarshal error: %v", err)
		return "", err
	}

	fmt.Printf("server_url: %+v\n", data["server_url"])

	return data["server_url"].(string), nil
}

func getDevices(urlSuffix string) (interface{}, error) {
	var result interface{}
	resp, err := resty.New().R().SetHeaders(headers).
		SetResult(&result).
		Get(url + urlSuffix)
	if err != nil {
		return nil, fmt.Errorf("getDevices failed, err: %s, data: %s", err, resp.String())
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("getDevices failed, data: %s", resp.String())
	}

	return result, nil
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

func moveDevice(urlSuffix, user string) (interface{}, error) {
	fmt.Println(urlSuffix)
	fmt.Println(user)
	var result interface{}
	resp, err := resty.New().R().SetHeaders(headers).
		SetQueryParam("user", user).
		SetResult(&result).
		Post(url + urlSuffix)
	if err != nil {
		return nil, fmt.Errorf("moveDevice failed, err: %s, data: %s", err, resp.String())
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("moveDevice failed, data: %s", resp.String())
	}

	return result, nil
}

func getMachineRoutes(urlSuffix string) (interface{}, error) {
	var result interface{}
	resp, err := resty.New().R().SetHeaders(headers).
		SetResult(&result).
		Get(url + urlSuffix)
	if err != nil {
		return nil, fmt.Errorf("getMachineRoutes failed, err: %s, data: %s", err, resp.String())
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("getMachineRoutes failed, data: %s", resp.String())
	}

	return result, nil
}

func updateTags(urlSuffix string, data []byte) (interface{}, error) {
	var result interface{}
	resp, err := resty.New().R().SetHeaders(headers).
		SetBody(data).
		SetResult(&result).
		Post(url + urlSuffix)
	if err != nil {
		return nil, fmt.Errorf("updateTags failed, err: %s, data: %s", err, resp.String())
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("updateTags failed, data: %s", resp.String())
	}

	return result, nil
}

func routeEnable(urlSuffix string) (interface{}, error) {
	var result interface{}
	resp, err := resty.New().R().SetHeaders(headers).
		SetResult(&result).
		Post(url + urlSuffix)
	if err != nil {
		return nil, fmt.Errorf("routeEnable failed, err: %s, data: %s", err, resp.String())
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("routeEnable failed, data: %s", resp.String())
	}

	return result, nil
}

func routeDisable(urlSuffix string) (interface{}, error) {
	var result interface{}
	resp, err := resty.New().R().SetHeaders(headers).
		SetResult(&result).
		Post(url + urlSuffix)
	if err != nil {
		return nil, fmt.Errorf("routeDisable failed, err: %s, data: %s", err, resp.String())
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("routeDisable failed, data: %s", resp.String())
	}

	return result, nil
}
