# Headscale API Wrapper 对接说明

本文只描述业务调用方需要使用的接口。按“认证 → 请求 → 响应 → 约束”实现即可。

## 目录

- [1. 调用前先确认](#1-调用前先确认)
  - [1.1 地址与认证](#11-地址与认证)
  - [1.2 统一响应与错误](#12-统一响应与错误)
- [2. app-service 专用接口](#2-app-service-专用接口)
  - [2.1 地址](#21-地址)
  - [2.2 读取应用端口规则](#22-读取应用端口规则)
  - [2.3 替换应用端口规则](#23-替换应用端口规则)
  - [2.4 请求约束](#24-请求约束)
- [3. 用户注册 key（Vault / LarePass）](#3-用户注册-keyvault--larepass)
- [4. 设备接口（当前用户自己的设备）](#4-设备接口当前用户自己的设备)
- [5. 同用户设备互访](#5-同用户设备互访)
- [6. Exit node 授权（owner）](#6-exit-node-授权owner)
- [7. 子网路由与内网访问（owner）](#7-子网路由与内网访问owner)
  - [7.1 发布网段](#71-发布网段)
  - [7.2 内网访问 ACL](#72-内网访问-acl)
- [8. Olares 用户与 LAN 组（owner）](#8-olares-用户与-lan-组owner)
  - [查询可授权用户](#查询可授权用户)
  - [LAN 组](#lan-组)

## 1. 调用前先确认

### 1.1 地址与认证

`/headscale/*` 业务接口：

- 直连地址：`http://headscale-server-svc.os-network:8000`
- 经 Olares provider 调用：使用当前用户对应的 provider 入口
- 用户身份：`X-Authorization: Bearer <Olares AccessToken>`
- 经 provider 调用时还要带：`Authorization: Bearer <provider ServiceAccount token>`

两个 token 用途不同：`Authorization` 通过 provider 权限检查，`X-Authorization` 由 wrapper 校验当前用户身份。请求体为 JSON 时带 `Content-Type: application/json`。

第 6～8 节接口只允许 Olares owner 调用；设备接口和 self-mesh 由当前用户操作。

### 1.2 统一响应与错误

成功响应：

```json
{"code":0,"message":"","data":{}}
```

常见 HTTP 状态：

- `200`：成功；同时要求 `code == 0`
- `400`：请求体、用户名、网段或端口格式错误
- `401`：缺少或无效的用户 AccessToken
- `403`：当前用户无权操作
- `409`：托管策略结构不支持当前修改，或要删除的组仍被策略引用（主要出现在 policy/subnet/LAN group 接口）
- `500`：wrapper 内部处理失败；设备、preauthkey 和 application-ports 的部分上游错误也会返回此状态
- `502`：owner 校验、Headscale、Kubernetes 或其他上游调用失败（不同接口的映射略有差异）
- `504`：带策略操作超时控制的请求超过 30 秒
- 未注册路径可能返回纯文本 `404`

策略写入超时后不要直接重复提交；先 GET 当前状态，再决定是否重试。

## 2. app-service 专用接口

这些接口只供 app-service 等后台服务调用，不供用户或前端直接调用。

### 2.1 地址

```text
http://headscale-server-svc.os-network:8001
```

### 2.2 读取应用端口规则

```http
GET /internal/policy/application-ports
```

响应：

```json
{
  "code": 0,
  "message": "",
  "data": {
    "applicationPorts": [
      {"user":"alice","tcp":["5000"],"udp":["5353"]}
    ]
  }
}
```

### 2.3 替换应用端口规则

```http
PUT /internal/policy/application-ports
Content-Type: application/json
```

请求体：

```json
{
  "applicationPorts": [
    {"user":"alice","tcp":["5000","6000-6010"],"udp":["5353"]},
    {"user":"bob","tcp":[],"udp":["5353"]}
  ]
}
```

成功响应：

```json
{
  "code": 0,
  "message": "",
  "data": {}
}
```

### 2.4 请求约束

- `applicationPorts` 必须是数组；省略或 `null` 返回 `400`
- `user` 是策略用户名，不带 `@`
- `tcp`、`udp` 使用单端口或闭区间，范围 `1–65535`
- 不允许 `"*"`
- PUT 是动态应用端口规则的全量替换；未提交用户的动态端口授权会被移除
- 空数组会清空全部动态应用端口规则


## 3. 用户注册 key（Vault / LarePass）

### 获取当前用户的 preauthkey

```http
GET http://headscale-authkey-svc.os-network:9000/headscale/preauthkey
X-Authorization: Bearer <Olares AccessToken>
```

无请求体、无用户名参数。服务端根据 AccessToken 确定当前用户。

响应中的 `data` 透传 Headscale 结果，注册时使用 `data.preAuthKey.key`：

```json
{
  "code": 0,
  "message": "",
  "data": {
    "preAuthKey": {
      "key": "hskey-auth-...",
      "reusable": true,
      "expiration": "2026-10-15T10:00:00Z",
      "user": {"name": "alice"}
    }
  }
}
```

每次请求都会生成新的 key；有效期以响应中的 `expiration` 为准。

## 4. 设备接口（当前用户自己的设备）

### 查询设备

```http
GET /headscale/node
```

```json
{"code":0,"message":"","data":{"nodes":[]}}
```

只返回当前 AccessToken 用户的设备。

### 删除设备

```http
DELETE /headscale/node/:nodeID
```

- `nodeID` 为 Headscale 设备 ID
- 只能删除当前用户的设备
- 成功时 `data` 为 Headscale 删除结果

### 修改设备名称

```http
PATCH /headscale/node/:nodeID
Content-Type: application/json

{"name":"macbook-pro"}
```

`name` 必填且不能为空；请求体只接受 `name` 字段。

## 5. 同用户设备互访

### 查询或修改当前用户开关

```http
GET /headscale/policy/self-mesh
PUT /headscale/policy/self-mesh
```

PUT 请求：

```json
{"enabled":true}
```

响应：

```json
{"code":0,"message":"","data":{"enabled":true,"changed":true}}
```

约束：

- 不传用户名，只操作当前 AccessToken 用户
- `enabled` 必须是 boolean
- `false` 表示关闭
- 重复保存同一值时 `changed` 可能省略

## 6. Exit node 授权（owner）

```http
GET    /headscale/policy/exit-users
PUT    /headscale/policy/exit-users/:username
DELETE /headscale/policy/exit-users/:username
```

PUT、DELETE 无请求体，`:username` 使用 Olares 用户名，不带 `@`。

GET 示例：

```json
{"code":0,"message":"","data":{"users":["alice","bob"]}}
```

PUT/DELETE 示例：

```json
{"code":0,"message":"","data":{"users":["alice"],"changed":true}}
```

- PUT 授权一个用户，DELETE 撤销一个用户
- 重复授权或删除不存在的授权是成功的无变化操作，`changed` 可能省略
- 授权 exit node 不等于授权 subnet router

## 7. 子网路由与内网访问（owner）

发布路由和访问权限是两个独立配置：发布路由只决定客户端是否能得到到该网段的路由；访问权限决定哪些用户/组、哪些协议和端口可以通过 ACL 访问。两者都满足时，流量才可用。

### 7.1 发布网段

```http
GET /headscale/policy/subnet-router/routes
PUT /headscale/policy/subnet-router/routes
```

PUT 请求：

```json
{"routes":["192.168.31.0/24"]}
```

PUT 响应：

```json
{"code":0,"message":"","data":{}}
```

约束：

- `routes` 必须是数组；PUT 是全量替换，不是追加
- `routes: []` 清空业务发布网段
- 只接受 IPv4 CIDR；本次提交的网段之间不能重叠
- 不能覆盖 Olares 集群 Pod/Service 网段

### 7.2 内网访问 ACL

```http
GET /headscale/policy/subnet-router/access
PUT /headscale/policy/subnet-router/access
```

PUT 请求示例：

```json
{
  "access": [
    {
      "users": ["alice", "bob"],
      "target": "192.168.31.0/24",
      "protocol": "udp",
      "ports": ["53"]
    },
    {
      "groups": ["nas-users"],
      "target": "192.168.31.10/32",
      "protocol": "tcp",
      "ports": ["445", "5000-5010"]
    }
  ]
}
```

字段规则：

- `users` 和 `groups` 至少填写一个；两者是“或”关系
- 用户名不带 `@`
- `groups` 填 LAN 组名，例如 `nas-users`
- `target` 是 IPv4 地址或 CIDR
- `protocol` 只能是 `tcp` 或 `udp`，大小写不敏感
- `ports` 是非空数组，支持单端口、闭区间和单独的 `"*"`
- 端口范围为 `1–65535`；`"*"` 必须是该规则唯一的端口项
- 每次最多 256 条规则，每条最多 256 个端口项，请求体最多 1 MiB
- routes 和 access 独立保存；实际访问必须同时存在可达路由和匹配的 ACL

响应：

```json
{"code":0,"message":"","data":{}}
```

- GET 返回当前全部访问规则
- PUT 全量替换全部访问规则；未提交的旧规则会被删除
- `{"access":[]}` 清空全部访问权限
- 没有单条规则 ID，也没有单条 DELETE；删除一条规则时，GET 后移除目标项，再 PUT 全量列表

## 8. Olares 用户与 LAN 组（owner）

### 查询可授权用户

```http
GET /headscale/olares-users
```

```json
{"code":0,"message":"","data":{"users":[{"username":"alice"}]}}
```

只返回状态为 `Created` 且未删除的 Olares 用户；是否已经注册 VPN 不影响返回。授权参数使用 `username`。

### LAN 组

```http
GET    /headscale/policy/lan-groups
PUT    /headscale/policy/lan-groups/:name
DELETE /headscale/policy/lan-groups/:name
```

创建或替换成员：

```http
PUT /headscale/policy/lan-groups/nas-users
Content-Type: application/json

{"users":["alice","bob"]}
```

响应：

```json
{"code":0,"message":"","data":{"name":"nas-users","users":["alice","bob"],"changed":true}}
```

约束：

- 组名只能是 1–40 个小写字母、数字或连字符，且以字母开头
- PUT 替换该组全部成员；`{"users":[]}` 清空成员但保留组
- 成员必须是可用的 Olares 用户
- DELETE 不需要请求体；组被访问规则引用时返回 `409`
- 删除被引用的组前，先从所有 subnet access 规则中移除组引用；不需要先清空成员
