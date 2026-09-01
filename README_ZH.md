<p align="center">
  <img src="assets/portway-logo.png" width="180" alt="Portway logo">
</p>

<h1 align="center">Portway</h1>

<p align="center">
  一款面向长期可靠网络访问的轻量级双向隧道系统。
</p>

Portway 在 `portway` 与 `portwayd` 之间建立认证隧道，并支持两个流量方向：

- **Proxy 模式（服务端到客户端）：** 通过 `portwayd` 的 TCP/UDP 端口或
  HTTP/HTTPS 域名入口，暴露 `portway` 可访问的服务。
- **Forward 模式（客户端到服务端）：** 在 `portway` 上创建本地 TCP/UDP
  Listener，访问 `portwayd` 所在网络中明确授权的 IP 和端口。

两种模式是相互独立的功能，既可分别运行，也可复用同一条认证客户端-服务端连接。

## 项目总体功能架构

```text
Portway
├── Proxy：将客户端侧服务通过 portwayd 发布出去
│   ├── 普通代理：一个公共入口对应一个客户端服务
│   │   ├── TCP / UDP 公共端口
│   │   └── HTTP / HTTPS 域名
│   └── 镜像代理：一组公共 TCP/UDP 端口将输入复制给多个客户端
│       └── 只有指定 Primary 回复，其他客户端的回复被丢弃
└── Forward：将服务端侧获准服务转发到 portway 本地端口
    └── TCP / UDP 本地 Listener
```

**Proxy** 用于发布客户端网络中的服务。公共 Listener 由 `portwayd` 持有，访问者
流量通过隧道送到 `portway`。普通代理适合 SSH、Web 应用、DNS、游戏服务等需要
稳定公网入口的服务。

**镜像 Proxy** 是受控的 TCP/UDP 代理变体，适合流量观测、并行处理、协议迁移、
审计以及影子服务验证。所有在线成员收到相同的访问者输入，但只有指定 Primary
能够回复，因此镜像客户端不会干扰访问者响应。详见
[TCP 与 UDP Proxy 镜像](assets/docs/proxy-mirroring/README_ZH.md)。

**Forward** 用于使用服务端网络中的服务。本地 TCP/UDP Listener 由 `portway`
持有，连接或数据报会发送到 `portwayd` 可达且明确获准的目标。典型场景包括私有
数据库、管理接口、内部 DNS，以及其他不应暴露到公网的服务。

| 需求 | 功能 | 入口位置 | 目标位置 | 协议 |
| --- | --- | --- | --- | --- |
| 发布单个客户端服务 | 普通 Proxy | `portwayd` | 客户端网络 | TCP、UDP、HTTP、HTTPS |
| 将公共输入复制给多个客户端 | 镜像 Proxy | `portwayd` | 多个客户端网络 | TCP、UDP |
| 从本地访问服务端侧服务 | Forward | `portway` | 服务端网络 | TCP、UDP |

流量图和完整模式边界请参阅
[Proxy 与 Forward 工作模式](assets/docs/modes/README_ZH.md)。

## 功能亮点

**双向流量能力**

- 通过服务端公共 Listener 代理客户端侧 TCP 和 UDP 服务。
- 将受 Governed 或 Managed 管理的公共 TCP/UDP Proxy 入口镜像给多个客户端，
  同时阻止影子客户端影响访问者响应。
- 按域名代理 HTTP 或 HTTPS，支持服务端 TLS 终止、流式传输、Upgrade、连接复用
  和证书原子热更新。
- 将客户端侧 TCP/UDP Listener 转发到服务端网络，并由服务端 Allowlist 按 CIDR、
  协议和端口限制所有目标。
- 在同一个认证客户端会话中同时运行 Proxy 和 Forward 条目。

**传输与安全**

- 可选 TCP 或 QUIC 作为底层客户端-服务端传输。
- 对控制连接和数据连接执行认证与加密，不提供明文回退。
- 严格校验 YAML 和协议数据，限制队列与会话资源，并以故障关闭方式发布配置。
- 通过独立监视的 IPv4/IPv6 deny-list 阻断来源 IP。

**运维与治理**

- 原子注册完整的 Proxy 和 Forward 集合，并在有界窗口内恢复中断会话。
- 提供小巧的客户端和服务端二进制文件，命令行接口风格一致。
- 支持可信客户端群组共享配置、受策略约束的客户端配置和服务端完全托管配置。
- 原子热加载服务端配置，包括 Token 吊销、策略选择性吊销、Managed 配置下发、
  Forward 策略和 HTTPS 证书；无效更新继续保留上一份有效状态。

## 快速开始

以下示例使用 Shared 认证模式。请将
`REPLACE_WITH_SAME_RANDOM_TOKEN_OVER_32_CHARS` 替换为密码学安全生成的 Token，
并在两个配置文件中使用相同值。Token 必须包含大于 32 个 UTF-8 字符。两种场景
均应先启动 `portwayd`，再启动 `portway`。

### 场景一：通过服务端暴露客户端侧服务

当服务只能由 `portway` 访问，而用户需要通过公网或集中部署的 `portwayd` 主机
连接时，使用 Proxy 模式。以下示例将客户端 SSH 服务发布为
`SERVER_IP:22022`。

创建 `server.yaml`：

```yaml
transport:
  type: tcp
  listen_address: 0.0.0.0:7000

authentication:
  shared_token: REPLACE_WITH_SAME_RANDOM_TOKEN_OVER_32_CHARS
```

创建 `client.yaml`：

```yaml
transport:
  type: tcp
  server_address: SERVER_IP:7000

authentication:
  token: REPLACE_WITH_SAME_RANDOM_TOKEN_OVER_32_CHARS

proxies:
  - name: ssh
    type: tcp
    local:
      ip: 127.0.0.1
      port: 22
    public:
      port: 22022
```

使用配置文件路径启动两个进程：

```bash
portwayd run server.yaml
portway run client.yaml
```

用户现在可以通过服务端访问客户端侧 SSH 服务：

```text
SERVER_IP:22022
```

流量路径如下：

```text
访问者 -> portwayd:22022 -> 认证隧道 -> portway -> 127.0.0.1:22
```

### 场景二：从客户端访问服务端侧网络

当服务可由 `portwayd` 访问，而 `portway` 旁的用户或应用需要一个本地入口时，
使用 Forward 模式。以下示例仅在客户端回环地址 `127.0.0.1:15432` 暴露服务端侧
数据库 `10.20.1.15:5432`。

创建 `server.yaml`。Forward 默认关闭，因此需要启用它，并明确允许目标网段、
协议和端口：

```yaml
transport:
  type: tcp
  listen_address: 0.0.0.0:7000

authentication:
  shared_token: REPLACE_WITH_SAME_RANDOM_TOKEN_OVER_32_CHARS

forwards:
  enabled: true
  rules:
    - ip_range: 10.20.1.0/24
      tcp:
        port_ranges:
          - start: 5432
            end: 5432
```

创建 `client.yaml`：

```yaml
transport:
  type: tcp
  server_address: SERVER_IP:7000

authentication:
  token: REPLACE_WITH_SAME_RANDOM_TOKEN_OVER_32_CHARS

forwards:
  - name: database
    type: tcp
    listen:
      ip: 127.0.0.1
      port: 15432
    target:
      ip: 10.20.1.15
      port: 5432
```

启动两个进程：

```bash
portwayd run server.yaml
portway run client.yaml
```

客户端主机上的应用现在可以通过以下地址连接服务端侧数据库：

```text
127.0.0.1:15432
```

流量方向与 Proxy 模式相反：

```text
本地应用 -> portway:15432 -> 认证隧道 -> portwayd -> 10.20.1.15:5432
```

Forward 目标只接受 IP 地址。每个目标必须完整匹配一条服务端规则，不会组合不同
规则中的范围。除非确实需要其他主机访问，否则应将客户端 Listener 绑定到回环
地址。Forward 支持 TCP 和 UDP；基于域名的 HTTP/HTTPS 路由属于 Proxy 模式。

## HTTP 与 HTTPS 代理

在服务端按需启用 HTTP、HTTPS 或两个公网 Listener；
`proxies.https.listen_address` 为空时禁用 HTTPS：

```yaml
proxies:
  http:
    listen_address: 127.0.0.1:8080
  https:
    listen_address: 127.0.0.1:8443
    certificates:
      - domains:
          - app.example.com
        cert_file: /path/to/https-server.crt
        key_file: /path/to/https-server.key
```

在客户端注册一个域名：

```yaml
proxies:
  - name: web
    type: http
    local:
      ip: 127.0.0.1
      port: 8080
    public:
      schemes:
        - https
        - http
      domain: app.example.com
```

`type` 表示 `portwayd` 与 `portway` 之间的代理语义，`public.schemes` 显式选择
公网 HTTP/HTTPS Listener；任一所选 Listener 未启用都会拒绝整批注册。
省略或留空 `public.schemes` 时默认仅使用 HTTP 入口。
公共 `Host` 会被匹配到已认证的客户端注册信息。`portwayd` 终止公网 HTTPS，
随后通过认证隧道固定回源 HTTP，因此本地应用只接收普通 HTTP 请求。Visitor
提供的 `Forwarded`、`X-Forwarded-For`、`X-Forwarded-Host` 和
`X-Forwarded-Proto` 会被删除，`portwayd` 写入可信的
`X-Forwarded-For`、`X-Forwarded-Host` 和 `X-Forwarded-Proto`。HTTP 与 HTTPS
共用代理限制。HTTPS 要求规范化后的 SNI 与 HTTP `Host` 完全一致。协议超时和
请求体限制默认关闭，可在服务端 `http` 配置中启用。HTTPS 根据 SNI 从可原子热更新的证书集合中选择证书；
无效更新会继续使用上一代集合。HTTPS 支持 HTTP/1.1、HTTP/2，最低使用 TLS 1.2。
当前不支持 HTTPS 回源、SNI 透传、ACME 和 HTTP/3。

## UDP 代理

在客户端注册一个公共 UDP 端口和本地 UDP 服务：

```yaml
proxies:
  - name: dns
    type: udp
    local:
      ip: 127.0.0.1
      port: 53
    public:
      port: 5353
```

Portway 保留数据报边界，并为每个公网访问者关联提供独立的认证数据链路。
无论选择 TCP 还是 QUIC 作为客户端-服务端传输，UDP 均可正常工作。
服务端的关联、队列、速率、内存和空闲限制均设有安全默认值和可配置的硬上限。

## QUIC 传输

Portway 可以在 `portway` 和 `portwayd` 之间使用 QUIC 替代 TCP。
QUIC 除了需要 Portway Token 认证外，还需要服务端证书和 TLS 验证。

对于私有部署，可生成内部 CA 和服务端证书。证书 SAN 必须匹配客户端配置的
`transport.quic.server_name`：

```bash
# 客户端使用 IP 校验服务端。
portwayd gen cert --ip 10.0.0.10

# 客户端使用域名校验服务端；server_address 仍可填写 IP。
portwayd gen cert --server-name gateway.example.com

# 同时允许两种身份。
portwayd gen cert \
  --server-name gateway.example.com \
  --ip 10.0.0.10
```

同时省略 `--server-name` 和 `--ip` 时，证书默认包含 `localhost` 和
`127.0.0.1`，只适合本机使用。如果 `server_name` 配置为 IP，该 IP 必须通过
`--ip` 写入证书；DNS SAN 不能用于校验 IP 身份。

在 `portwayd` 配置生成的服务端证书和私钥：

```yaml
transport:
  type: quic
  listen_address: 0.0.0.0:7000
  quic:
    cert_file: ./certs/server.crt
    key_file: ./certs/server.key
```

在 `portway` 配置匹配的身份和生成的根 CA 证书：

```yaml
transport:
  type: quic
  server_address: 10.0.0.10:7000
  quic:
    server_name: 10.0.0.10
    ca_file: ./certs/root-ca.crt
```

使用域名证书时，`server_address` 仍可填写 `10.0.0.10:7000`，但
`server_name` 必须填写 `gateway.example.com`。Portway 使用 `server_address`
建立连接，使用 `server_name` 校验证书。

运行 `portwayd help gen cert` 查看所有证书选项。必须妥善保护 `root-ca.key` 和
`server.key`；只向客户端分发 `root-ca.crt`，客户端不需要任何私钥。

## 命令

```text
portway run [FILE]
portway gen config [full]
portway version

portwayd run [FILE]
portwayd gen config [full]
portwayd gen cert [options]
portwayd version
```

`gen config` 会在当前目录创建最小可运行的 `client.yaml` 或 `server.yaml`；客户端
配置生成会把新的规范 256-bit Token 写入仅属主可读写的文件。追加 `full` 可生成
带完整注释的全量模板。命令不会覆盖已有文件。直接运行任一二进制文件（不带参数）
会列出包括嵌套生成命令在内的全部可用命令。

可选位置参数 `FILE` 用于指定配置路径。省略时，`portway run` 从当前工作目录加载
`client.yaml`，`portwayd run` 从当前工作目录加载 `server.yaml`。命令不提供
`--config` 选项。

## 使用 Homebrew 安装

官方 [Acexy Homebrew Tap](https://github.com/acexy/homebrew-tap) 为 macOS 和
Linux 分别提供客户端与服务端 Formula。

安装客户端：

```bash
brew install acexy/tap/portway
```

安装服务端：

```bash
brew install acexy/tap/portwayd
```

需要时可以在同一主机安装两个组件：

```bash
brew install acexy/tap/portway acexy/tap/portwayd
```

Formula 不会创建或覆盖配置文件。运行安装后的命令前，需要自行准备对应的
`client.yaml` 或 `server.yaml`。

## 技术文档

- [Proxy 与 Forward 工作模式](assets/docs/modes/README_ZH.md)
- [TCP 与 UDP Proxy 镜像](assets/docs/proxy-mirroring/README_ZH.md)
- [技术概览](assets/docs/technical/README_ZH.md)
- [运维接口](assets/docs/operations/README_ZH.md)
- [多模式认证与配置控制](assets/docs/authentication/README_ZH.md)
- [服务端配置热加载](assets/docs/reload/README_ZH.md)
- [安全性](assets/docs/security/README_ZH.md)
- [未来计划](assets/docs/future/README_ZH.md)
- 完整中文注释配置示例：
  [客户端](config/zh/client.yaml) 和 [服务端](config/zh/server.yaml)

技术文档描述稳定的行为和安全性属性，而非作为完整的线协议规范。

## 许可证

Copyright 2026 Acexy.

Portway 基于 [Apache License 2.0](LICENSE) 许可。有关归属信息，请参阅 [NOTICE](NOTICE)。
