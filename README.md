# ZenProxy

ZenProxy 是一个代理池管理与转发服务，由两部分组成：

- **ZenProxy Server**（Rust + Axum）：服务端，管理代理池、用户认证、请求转发、代理验证与质检
- **sing-box-zenproxy**（Go，修改版 sing-box）：本地客户端，通过 Clash API 提供代理存储、订阅管理、批量绑定等功能，支持并发多 IP 出口

## 架构概览

### 服务端模式

```
用户请求 → ZenProxy Server (Axum) → sing-box (动态 Bindings) → 代理服务器 → 目标网站
```

### 本地客户端模式

```
你的程序 → 127.0.0.1:20001 ──→ 代理A (IP-A)
         → 127.0.0.1:20002 ──→ 代理B (IP-B)
         → 127.0.0.1:20003 ──→ 代理C (IP-C)
         ...
         → 127.0.0.1:20100 ──→ 代理N (IP-N)

代理来源：
  ├── 从 ZenProxy Server 批量 fetch
  ├── 从订阅 URL 导入
  └── 手动添加 URI / outbound JSON
```

每个本地端口是独立的 HTTP+SOCKS5 代理，路由到不同出口 IP。端口池范围 20001-30000，最多同时绑定 10000 个代理。适用于批量注册、数据采集等需要并发多 IP 的场景。

---

## 一、ZenProxy Server（Rust 服务端）

### 支持的代理协议

- VMess
- VLESS
- Trojan
- Shadowsocks
- Hysteria2
- SOCKS5 / SOCKS4
- HTTP / HTTPS

### 支持的订阅格式

| 类型 | 说明 |
|------|------|
| `auto` | 自动检测（默认），依次尝试 Clash YAML → Base64 V2Ray → 原始 V2Ray URI |
| `clash` | Clash YAML 格式（`proxies:` 字段） |
| `v2ray` | V2Ray URI 格式，每行一个 `vmess://`、`vless://`、`trojan://`、`socks5://`、`http://` 等 |
| `base64` | Base64 编码的 V2Ray URI 列表 |
| `socks5` | 纯文本 SOCKS5 代理列表，每行 `host:port` 或 `user:pass@host:port` |
| `socks4` | 纯文本 SOCKS4 代理列表，格式同上 |
| `http` | 纯文本 HTTP 代理列表，格式同上 |
| `https` | 纯文本 HTTPS 代理列表，格式同上（启用 TLS） |

### 配置文件

ZenProxy 从 `config.toml` 读取配置（与可执行文件同目录），示例：

```toml
[server]
host = "0.0.0.0"
port = 3000
admin_password = "your-admin-password"    # 管理后台密码
min_trust_level = 1                       # OAuth 用户最低信任等级（Linux.do trust_level）

[oauth]
client_id = ""                            # Linux.do OAuth client ID
client_secret = ""                        # Linux.do OAuth client secret
redirect_uri = "https://your-domain.com/api/auth/callback"

[singbox]
binary_path = "/usr/local/bin/sing-box"   # sing-box 二进制路径（同目录优先）
config_path = "data/singbox-config.json"  # sing-box 运行配置路径（自动生成）
base_port = 10001                         # 代理端口起始值（分配范围: base_port+1 ~ base_port+max_proxies）
max_proxies = 300                         # 最大同时绑定代理数（默认 300）
api_port = 9090                           # sing-box Clash API 端口（默认 9090）
api_secret = ""                           # sing-box API 密钥（可选）

[database]
path = "data/zenproxy.db"                 # SQLite 数据库路径

[validation]
url = "https://www.bing.com"              # 验证目标 URL
timeout_secs = 10                         # 单个代理验证超时（秒）
concurrency = 50                          # 并发验证数
interval_mins = 30                        # 定时验证间隔（分钟）
error_threshold = 10                      # 连续失败超过此值删除代理

[quality]
interval_mins = 120                       # 质检间隔（分钟），实际不使用此字段
concurrency = 10                          # 并发质检数

[subscription]
auto_refresh_interval_mins = 0            # 定时自动刷新间隔（分钟），0 = 禁用，例如 360 = 每 6 小时
```

### 认证方式

| 方式 | 适用场景 | 格式 |
|------|----------|------|
| OAuth 会话 | Web 页面 | Cookie: `zenproxy_session=...`（7 天有效） |
| API Key | 程序调用 | Query: `?api_key=xxx` 或 Header: `Authorization: Bearer xxx` |
| 管理密码 | 管理后台 | Header: `Authorization: Bearer {admin_password}` |

OAuth 使用 [Linux.do](https://linux.do) 作为身份提供商。用户登录后获得 API Key，可在个人页面查看和重新生成。

> **注意：** `/api/relay` 端点**仅支持 `api_key` query 参数认证**。请求中的 `Authorization`、`Cookie` 等 header 会原样转发给目标服务器。

### 服务端 API

#### 页面

| 路径 | 说明 |
|------|------|
| `GET /` | 用户页面 |
| `GET /admin` | 管理后台 |
| `GET /docs` | API 文档 |

#### 认证

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| `GET /api/auth/login` | 跳转 OAuth 登录 | 无 |
| `GET /api/auth/callback` | OAuth 回调 | 无 |
| `GET /api/auth/me` | 获取当前用户信息 | 会话 |
| `POST /api/auth/logout` | 登出 | 会话 |
| `POST /api/auth/regenerate-key` | 重新生成 API Key | 会话 |

#### 代理获取（/api/fetch）

```
GET /api/fetch?api_key=xxx&count=5&country=US&chatgpt=true
```

**参数：**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `api_key` | string | - | API Key（也可用 Header） |
| `count` | int | 1 | 返回代理数量 |
| `proxy_id` | string | - | 指定代理 ID |
| `chatgpt` | bool | false | 仅返回支持 ChatGPT 的代理 |
| `google` | bool | false | 仅返回支持 Google 的代理 |
| `residential` | bool | false | 仅返回住宅 IP 代理 |
| `risk_max` | float | - | 最大风险评分（0~1） |
| `country` | string | - | 国家代码过滤（如 US、JP） |
| `type` | string | - | 代理类型过滤（vmess、vless、trojan 等） |

**响应示例：**

```json
{
  "proxies": [
    {
      "id": "uuid",
      "name": "代理名称",
      "type": "vmess",
      "server": "1.2.3.4",
      "port": 443,
      "local_port": 10002,
      "status": "valid",
      "quality": {
        "ip_address": "5.6.7.8",
        "country": "US",
        "ip_type": "ISP",
        "is_residential": true,
        "chatgpt": true,
        "google": true,
        "risk_score": 0.1,
        "risk_level": "Low"
      }
    }
  ],
  "count": 1
}
```

#### 客户端专用获取（/api/client/fetch）

供本地客户端使用，返回代理信息 **含完整 outbound 配置**，可直接用于 sing-box 创建绑定。

```
GET /api/client/fetch?api_key=xxx&count=100&country=US&type=vmess
```

参数同 `/api/fetch`，默认 `count=10`。

**响应示例：**

```json
{
  "proxies": [
    {
      "id": "uuid",
      "name": "proxy-name",
      "type": "vmess",
      "server": "1.2.3.4",
      "port": 443,
      "outbound": {
        "type": "vmess",
        "server": "1.2.3.4",
        "server_port": 443,
        "uuid": "...",
        "alter_id": 0,
        "security": "auto"
      },
      "quality": {
        "country": "US",
        "chatgpt": true,
        "google": true,
        "is_residential": false,
        "risk_score": 0.1,
        "risk_level": "Low"
      }
    }
  ],
  "count": 1
}
```

#### 请求转发（/api/relay）

通过代理池转发任意 HTTP 请求到目标 URL。

```
POST /api/relay?api_key=xxx&url=https://api.example.com/data&method=POST&country=US
```

> **认证要求：** relay 端点**仅接受 `api_key` query 参数**认证。请求中的 `Authorization`、`Cookie` 等 header 会原样转发给目标。

**参数：**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `url` | string | **必填** | 目标 URL |
| `method` | string | GET | HTTP 方法（GET/POST/PUT/DELETE/PATCH/HEAD） |
| `api_key` | string | **必填** | ZenProxy API Key（仅支持 query 参数） |
| `proxy_id` | string | - | 指定代理（支持无端口代理，按需创建绑定） |
| `chatgpt` | bool | false | ChatGPT 可用过滤 |
| `google` | bool | false | Google 可用过滤 |
| `residential` | bool | false | 住宅 IP 过滤 |
| `risk_max` | float | - | 最大风险评分 |
| `country` | string | - | 国家过滤 |
| `type` | string | - | 代理类型过滤 |

**额外响应头：**

| Header | 说明 |
|--------|------|
| `X-Proxy-Id` | 使用的代理 ID |
| `X-Proxy-Name` | 代理名称（URL 编码） |
| `X-Proxy-Server` | 代理服务器地址 |
| `X-Proxy-IP` | 代理出口 IP |
| `X-Proxy-Country` | 代理所在国家 |
| `X-Proxy-Attempt` | 重试次数（仅随机选择时） |

**使用示例：**

```bash
# 通过美国住宅代理访问 API
curl "https://your-domain.com/api/relay?api_key=xxx&url=https://httpbin.org/ip&country=US&residential=true"

# 通过指定代理发送 POST 请求
curl -X POST "https://your-domain.com/api/relay?api_key=xxx&url=https://api.example.com/data&method=POST&proxy_id=uuid" \
  -H "Authorization: Bearer target_api_token" \
  -H "Content-Type: application/json" \
  -d '{"key": "value"}'
```

#### 代理列表（/api/proxies）

```
GET /api/proxies?api_key=xxx
```

返回所有代理及统计信息，包含质检数据。

#### 管理接口

所有管理接口需要 `Authorization: Bearer {admin_password}`。

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET /api/admin/stats` | 系统统计 |
| `GET /api/admin/proxies` | 代理列表 |
| `DELETE /api/admin/proxies/:id` | 删除代理 |
| `POST /api/admin/proxies/cleanup` | 清理高错误代理 |
| `POST /api/admin/validate` | 手动触发验证 |
| `POST /api/admin/quality-check` | 手动触发质检 |
| `GET /api/admin/users` | 用户列表 |
| `DELETE /api/admin/users/:id` | 删除用户 |
| `POST /api/admin/users/:id/ban` | 封禁用户 |
| `POST /api/admin/users/:id/unban` | 解封用户 |
| `GET /api/subscriptions` | 列出所有订阅 |
| `POST /api/subscriptions` | 添加订阅 |
| `DELETE /api/subscriptions/:id` | 删除订阅及其代理 |
| `POST /api/subscriptions/:id/refresh` | 刷新订阅 |

### 验证与质检

#### 代理验证（Validation）

验证通过配置的 URL 检测代理是否可用，标记为 Valid / Invalid。

**触发时机：**
- 导入/刷新订阅后**立即触发**
- 定时任务：每 `validation.interval_mins` 分钟运行一次
- 定时订阅刷新后自动触发（需开启 `auto_refresh_interval_mins`）

**流程：**
1. 检查 Valid 代理中 `error_count > 0` 的（用户使用时失败过），重置为 Untested 重新验证
2. `sync_proxy_bindings(Validation)` — 优先为 Untested 代理分配端口
3. 并发验证所有有端口的 Untested 代理
4. 成功 → Valid（error_count 清零），失败 → Invalid
5. 如果 Untested 数量 > `max_proxies`，多轮循环直到全部验证完
6. 无法获取绑定的代理（配置错误）直接标记为 Invalid
7. 验证完成后执行 `sync_proxy_bindings(Normal)` 恢复正常端口分配

**Relay 失败反馈：** 用户通过 `/api/relay` 使用代理失败时，该代理的 `error_count` 会自动增加。下次定时验证时，这些有错误的代理会被重新验证，不通过则标记为 Invalid 移除。

#### 订阅自动刷新

在 `config.toml` 中设置 `[subscription] auto_refresh_interval_mins`（非 0 值）即可启用定时自动刷新。

**刷新策略（平滑替换）：**
- 拉取/解析失败时，旧代理**完全不受影响**
- 解析出 0 个代理时，中止刷新，保留旧数据
- 对 (server, port, proxy_type) 相同的代理，**保留**其验证状态、端口绑定和质检数据
- 仅新增的代理标记为 Untested 等待验证
- 仅已消失的旧代理才会被删除
- 全部刷新完成后统一触发一次验证

#### 质量检测（Quality Check）

通过 ip-api.com 和 ipinfo.io 获取代理的 IP 信息、地理位置、风险评估。

**检测内容：**
| 项目 | 来源 | 说明 |
|------|------|------|
| IP 地址 | ip-api.com / ipinfo.io | 代理出口 IP |
| 国家 | ip-api.com / ipinfo.io | 国家代码 |
| IP 类型 | ipinfo.io | ISP / Datacenter 等 |
| 是否住宅 | ipinfo.io | company.type == "isp" |
| ChatGPT 可访问 | chatgpt.com | 检测是否被封锁 |
| Google 可访问 | google.com/generate_204 | 检测连通性 |
| 风险评分 | ip-api.com | proxy + hosting 综合评分 |

### 服务端部署

#### 编译

```bash
# sing-box（修改版）
cd sing-box-zenproxy
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o sing-box -tags with_clash_api ./cmd/sing-box

# ZenProxy Server
cargo zigbuild --release --target x86_64-unknown-linux-gnu
```

#### 目录结构

```
/opt/zenproxy/
├── zenproxy          # Rust 主程序
├── sing-box          # 修改版 sing-box（同目录优先加载）
├── config.toml       # 配置文件
└── data/
    ├── zenproxy.db           # SQLite 数据库
    └── singbox-config.json   # 自动生成的 sing-box 配置
```

#### 启动

```bash
cd /opt/zenproxy
./zenproxy
```

---

## 二、sing-box-zenproxy（本地客户端）

sing-box-zenproxy 是修改版 sing-box，在官方 Clash API 基础上新增了代理存储、订阅管理、远程 Fetch、批量绑定等功能，用于将 ZenProxy 的代理池能力搬到用户本地使用。

### 新增功能概览

| 功能 | 说明 |
|------|------|
| **代理存储** | 本地 JSON 文件持久化代理列表，重启不丢失 |
| **订阅管理** | 支持 V2Ray URI / Clash YAML / Base64 订阅格式 |
| **远程 Fetch** | 从 ZenProxy Server 批量获取代理 |
| **端口池** | 自动分配本地端口（20001-30000），无需手动指定 |
| **批量绑定** | 一键为所有代理创建本地 HTTP/SOCKS5 代理端口 |
| **协议解析器** | 内置 vmess/vless/trojan/ss/hy2 URI 和 Clash YAML 解析 |

### 架构

```
sing-box-zenproxy Clash API (默认 127.0.0.1:9090)
├── /store              代理存储 CRUD
├── /subscriptions      订阅管理
├── /fetch              从服务器 fetch 代理
├── /bindings           动态绑定管理（含批量）
│   ├── POST /batch     批量创建绑定
│   └── DELETE /all     删除所有绑定
└── data/store.json     持久化文件
```

### 新增源码结构

```
experimental/clashapi/
├── store.go           # 代理存储（ProxyStore），文件持久化
├── proxy_manage.go    # GET/POST/DELETE /store 端点 + PortPool
├── subscription.go    # 订阅管理端点
├── remote_fetch.go    # 从 ZenProxy Server fetch 代理
├── bindings.go        # 增强版绑定管理（proxy_id、batch、delete all）
├── server.go          # 路由注册（新增 /store、/fetch、/subscriptions）
└── parser/
    ├── parser.go      # 解析入口 + 自动检测
    ├── v2ray.go       # vmess/vless/trojan/ss/hy2 URI 解析
    ├── clash.go       # Clash YAML 解析
    └── base64.go      # Base64 解码
```

### 客户端 API

所有 API 通过 Clash API 地址访问（默认 `http://127.0.0.1:9090`），认证方式为 Bearer Token（sing-box 配置中的 `secret`）。

#### 代理存储（/store）

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET /store` | 列出所有存储的代理 |
| `POST /store` | 添加代理 |
| `DELETE /store/{id}` | 删除指定代理 |
| `DELETE /store` | 清空所有代理 |

**添加代理（URI 方式）：**

```bash
curl -X POST http://127.0.0.1:9090/store \
  -H "Authorization: Bearer your-secret" \
  -d '{"uri": "vmess://eyJhZGQiOi..."}'
```

**添加代理（outbound JSON 方式）：**

```bash
curl -X POST http://127.0.0.1:9090/store \
  -H "Authorization: Bearer your-secret" \
  -d '{
    "outbound": {
      "type": "vmess",
      "server": "1.2.3.4",
      "server_port": 443,
      "uuid": "xxx",
      "alter_id": 0,
      "security": "auto"
    }
  }'
```

**响应：**

```json
{
  "id": "generated-uuid",
  "name": "1.2.3.4:443",
  "type": "vmess",
  "server": "1.2.3.4",
  "port": 443,
  "outbound": { "type": "vmess", "..." },
  "source": "manual",
  "added_at": "2026-03-01T12:00:00Z"
}
```

#### 订阅管理（/subscriptions）

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET /subscriptions` | 列出所有订阅 |
| `POST /subscriptions` | 添加订阅 |
| `DELETE /subscriptions/{id}` | 删除订阅及其代理 |
| `POST /subscriptions/{id}/refresh` | 刷新订阅（重新获取并替换代理） |

**从 URL 添加订阅：**

```bash
curl -X POST http://127.0.0.1:9090/subscriptions \
  -H "Authorization: Bearer your-secret" \
  -d '{
    "name": "my-sub",
    "url": "https://example.com/sub",
    "type": "auto"
  }'
```

**直接提供内容：**

```bash
curl -X POST http://127.0.0.1:9090/subscriptions \
  -H "Authorization: Bearer your-secret" \
  -d '{
    "name": "manual-sub",
    "type": "v2ray",
    "content": "vmess://...\nvless://..."
  }'
```

**响应：**

```json
{
  "subscription": {
    "id": "sub-uuid",
    "name": "my-sub",
    "type": "auto",
    "url": "https://example.com/sub",
    "proxy_count": 50,
    "created_at": "...",
    "updated_at": "..."
  },
  "added": 50
}
```

#### 远程 Fetch（/fetch）

从 ZenProxy Server 批量获取代理（含 outbound 配置），存入本地。

```bash
curl -X POST http://127.0.0.1:9090/fetch \
  -H "Authorization: Bearer your-secret" \
  -d '{
    "server": "https://proxy.zenapi.top",
    "api_key": "your-zenproxy-api-key",
    "count": 100,
    "country": "US",
    "type": "vmess",
    "auto_bind": false
  }'
```

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `server` | string | **必填** | ZenProxy Server 地址 |
| `api_key` | string | **必填** | ZenProxy 用户 API Key |
| `count` | int | 10 | 获取代理数量 |
| `country` | string | - | 国家过滤 |
| `chatgpt` | bool | false | ChatGPT 可用过滤 |
| `type` | string | - | 代理类型过滤 |
| `auto_bind` | bool | false | 获取后自动创建绑定 |

**响应：**

```json
{
  "added": 100,
  "message": "Fetched 100 proxies from server",
  "bound": 100
}
```

#### 绑定管理（/bindings）

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET /bindings` | 列出所有活跃绑定 |
| `POST /bindings` | 创建单个绑定 |
| `POST /bindings/batch` | 批量创建绑定 |
| `DELETE /bindings/{tag}` | 删除单个绑定 |
| `DELETE /bindings/all` | 删除所有绑定 |

**从 store 创建绑定（自动分配端口）：**

```bash
curl -X POST http://127.0.0.1:9090/bindings \
  -H "Authorization: Bearer your-secret" \
  -d '{"proxy_id": "stored-proxy-uuid"}'
```

**手动指定 outbound 和端口：**

```bash
curl -X POST http://127.0.0.1:9090/bindings \
  -H "Authorization: Bearer your-secret" \
  -d '{
    "tag": "my-proxy",
    "listen_port": 8888,
    "outbound": {"type": "vmess", "..."}
  }'
```

**批量创建绑定：**

```bash
# 绑定所有存储的代理
curl -X POST http://127.0.0.1:9090/bindings/batch \
  -H "Authorization: Bearer your-secret" \
  -d '{"all": true}'

# 绑定前 100 个 vmess 代理
curl -X POST http://127.0.0.1:9090/bindings/batch \
  -H "Authorization: Bearer your-secret" \
  -d '{
    "count": 100,
    "filter": {"type": "vmess"}
  }'

# 绑定指定代理
curl -X POST http://127.0.0.1:9090/bindings/batch \
  -H "Authorization: Bearer your-secret" \
  -d '{"proxy_ids": ["id1", "id2", "id3"]}'
```

**批量绑定响应：**

```json
{
  "created": 100,
  "failed": 2,
  "bindings": [
    {"proxy_id": "id1", "local_port": 20001},
    {"proxy_id": "id2", "local_port": 20002},
    ...
  ]
}
```

**批量过滤参数：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `proxy_ids` | string[] | 指定代理 ID 列表 |
| `all` | bool | 绑定所有代理 |
| `count` | int | 绑定前 N 个代理 |
| `filter.type` | string | 按代理类型过滤（vmess/vless/trojan 等） |
| `filter.source` | string | 按来源过滤（server/manual/subscription） |

**删除所有绑定：**

```bash
curl -X DELETE http://127.0.0.1:9090/bindings/all \
  -H "Authorization: Bearer your-secret"
```

### 典型使用流程

#### 场景：批量注册需要 100 个不同 IP

```bash
# 1. 从 ZenProxy Server 获取 100 个代理
curl -X POST http://127.0.0.1:9090/fetch \
  -H "Authorization: Bearer secret" \
  -d '{"server": "https://proxy.zenapi.top", "api_key": "your-key", "count": 100}'

# 2. 批量创建绑定 → 每个代理分配一个本地端口
curl -X POST http://127.0.0.1:9090/bindings/batch \
  -H "Authorization: Bearer secret" \
  -d '{"all": true}'

# 3. 查看绑定列表，获取端口映射
curl http://127.0.0.1:9090/bindings -H "Authorization: Bearer secret"

# 4. 并发使用不同端口 → 不同出口 IP
curl -x http://127.0.0.1:20001 https://httpbin.org/ip  # → IP-A
curl -x http://127.0.0.1:20002 https://httpbin.org/ip  # → IP-B
curl -x http://127.0.0.1:20003 https://httpbin.org/ip  # → IP-C
...
```

#### 场景：使用订阅 URL

```bash
# 1. 添加订阅
curl -X POST http://127.0.0.1:9090/subscriptions \
  -H "Authorization: Bearer secret" \
  -d '{"name": "airport", "url": "https://airport.example.com/sub"}'

# 2. 批量绑定订阅中的代理
curl -X POST http://127.0.0.1:9090/bindings/batch \
  -H "Authorization: Bearer secret" \
  -d '{"all": true, "filter": {"source": "subscription"}}'

# 3. 后续刷新订阅（更新代理列表）
curl -X POST http://127.0.0.1:9090/subscriptions/{sub-id}/refresh \
  -H "Authorization: Bearer secret"
```

#### 场景：一步到位（fetch + 自动绑定）

```bash
curl -X POST http://127.0.0.1:9090/fetch \
  -H "Authorization: Bearer secret" \
  -d '{
    "server": "https://proxy.zenapi.top",
    "api_key": "your-key",
    "count": 200,
    "country": "US",
    "auto_bind": true
  }'
# 响应: {"added": 200, "bound": 200, "message": "..."}
# 此时 127.0.0.1:20001~20200 已经全部可用
```

### 客户端编译

```bash
cd sing-box-zenproxy
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o sing-box -tags with_clash_api ./cmd/sing-box
```

### 客户端配置

sing-box 最小配置（`config.json`）：

```json
{
  "log": {"level": "info"},
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": "your-secret"
    }
  },
  "outbounds": [
    {"type": "direct", "tag": "direct"}
  ]
}
```

启动后 Clash API 监听 `127.0.0.1:9090`，所有代理通过 API 动态管理。

### 客户端目录结构

```
./
├── sing-box           # 修改版 sing-box 二进制
├── config.json        # sing-box 配置
└── data/
    └── store.json     # 代理存储（自动生成，持久化）
```

### 数据持久化

代理和订阅数据存储在 `data/store.json`，重启 sing-box 后自动加载。绑定（inbound/outbound 端口映射）不持久化，重启后需要重新调用 `/bindings/batch` 创建。

---

## 三、修改版 sing-box 说明

ZenProxy 使用的 sing-box 在官方版本基础上新增了 **动态绑定管理**，支持运行时通过 REST API 增删代理绑定，无需重启进程。

### 原有 Bindings API

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET /bindings` | 列出所有绑定 |
| `POST /bindings` | 创建绑定 |
| `DELETE /bindings/{tag}` | 删除绑定 |

### 新增能力（本次改造）

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST /bindings` | 增加 `proxy_id` 字段，从 store 获取 outbound 并自动分配端口 |
| `POST /bindings/batch` | 批量创建绑定 |
| `DELETE /bindings/all` | 删除所有绑定 |
| `GET /store` | 列出存储的代理 |
| `POST /store` | 添加代理（URI 或 outbound JSON） |
| `DELETE /store/{id}` | 删除代理 |
| `DELETE /store` | 清空所有代理 |
| `GET /subscriptions` | 列出订阅 |
| `POST /subscriptions` | 添加订阅 |
| `DELETE /subscriptions/{id}` | 删除订阅 |
| `POST /subscriptions/{id}/refresh` | 刷新订阅 |
| `POST /fetch` | 从 ZenProxy Server 获取代理 |

## 日志

### 服务端

```bash
RUST_LOG=zenproxy=info,tower_http=info ./zenproxy
RUST_LOG=zenproxy=debug ./zenproxy  # 调试模式
```

### 客户端

在 `config.json` 中设置 `log.level`：`debug` / `info` / `warn` / `error`。
