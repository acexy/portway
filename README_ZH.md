<p align="center">
  <img src="assets/portway-logo.png" width="180" alt="Portway logo">
</p>

<h1 align="center">Portway</h1>

<p align="center">
一款轻量、安全、稳定的网络连接系统，通过 Proxy、Forward 与 VNet 三种模式，实现服务发布、受限访问与跨网络私网互联。
</p>

Portway 在 `portway` 与 `portwayd` 之间建立认证、加密的连接，为私有网络提供三种
彼此独立、可按需组合的能力：

- **Proxy 模式：** 从 `portwayd` 的公共入口访问客户端侧服务。
- **Forward 模式：** 从 `portway` 的本地入口访问服务端侧受限服务。
- **VNet 模式：** 跨不同网络将服务端与 Managed 客户端组成可互访的私有网络集群。

Proxy 和 Forward 面向明确的服务与端口；VNet 则提供类似中心式 VPN 的私网互联体验：
不同网络中的受管节点以稳定地址彼此访问。客户端间流量先经服务端中继，在探测成功后
自动让新 Flow 升级为 QUIC Datagram 直连；客户端与服务端之间始终保持中继。当前 VNet
承载已授权的 IPv4 TCP/UDP 流量，目标节点的端口策略仍是访问边界。三种模式可独立运行，
Proxy 与 Forward 可共享同一认证会话，VNet 则使用服务端下发的 Managed 节点身份与地址分配。

## 三种连接模式

```text
Portway
├── Proxy：将客户端侧服务通过 portwayd 发布出去
│   ├── 普通代理：一个公共入口对应一个客户端服务
│   │   ├── TCP / UDP 公共端口
│   │   └── HTTP / HTTPS 域名
│   └── 镜像代理：一组公共 TCP/UDP 端口将输入复制给多个客户端
│       └── 只有指定 Primary 回复，其他客户端的回复被丢弃
├── Forward：将服务端侧获准服务转发到 portway 本地端口
│   └── TCP / UDP 本地 Listener
└── VNet：通过稳定的私有 IPv4 地址连接 Managed 节点
    └── TCP / UDP 使用 1-8 条隔离 Packet Channel（默认 4）
```

### Proxy：把客户端服务发布到服务端入口

**Proxy** 用于发布客户端网络中的服务。公共 Listener 由 `portwayd` 持有，访问者
流量通过隧道送到 `portway`。普通代理适合 SSH、Web 应用、DNS、游戏服务等需要
稳定公共或中心入口的服务。

**镜像 Proxy** 是受控的 TCP/UDP 代理变体，适合流量观测、并行处理、协议迁移、
审计以及影子服务验证。所有在线成员收到相同的访问者输入，但只有指定 Primary
能够回复，因此镜像客户端不会干扰访问者响应。详见
[TCP 与 UDP Proxy 镜像](assets/docs/proxy-mirroring/README_ZH.md)。加入活跃流量的
成员只接收后续数据：TCP 会从任意字节偏移开始，UDP 从下一份数据报开始。
本地服务不可用不影响客户端登录，服务恢复后自动继续转发，不重放不可用期间丢失的流量。

### Forward：把服务端网络的服务带到客户端本地

**Forward** 用于使用服务端网络中的服务。本地 TCP/UDP Listener 由 `portway`
持有，连接或数据报会发送到 `portwayd` 可达且明确获准的目标。典型场景包括私有
数据库、管理接口、内部 DNS，以及其他不应暴露到公网的服务。

### VNet：跨网络组建可互访的私有网络集群

**VNet** 是仅适用于 Managed 身份的 Linux、macOS 和 Windows amd64 模式，适合将分布在不同内网、云主机
或边缘网络的节点组建为类似 VPN 的私有网络集群。服务端默认占用
`172.20.0.1`，并为配置的客户端分配稳定地址；客户端间可达时自动使用 QUIC P2P，
不可达时继续由服务端集中中继。
Portway 只创建具有所有权记录的逻辑网络 `portway0`，并执行每个目标节点的 TCP/UDP
端口允许列表。服务端控制的 `network_mode` 默认使用原生 TUN 交付；`loopback` 使用
用户态 TCP/IP 栈访问绑定在 `127.0.0.1` 相同端口的 TCP/UDP 服务。Linux 服务端使用
`portwayd vnetwork status|install|repair|uninstall`；
Linux 客户端地址由服务端下发，因此只暴露安全的 `portway vnetwork uninstall` 命令。
macOS 的 `run` 进程自动使用同一二进制的短生命周期提权模式，不提供手工管理命令。
Windows amd64 发布包会单独内置官方签名的 `wintun.dll`。启用 VNet 的 `portway` 或
`portwayd` 必须以管理员身份启动；临时 Adapter 仅在实际启用 VNet 时创建，并随持有
进程关闭而移除。Proxy、Forward 或未启用 VNet 的运行不会加载 Wintun，也不要求管理员权限。
详见 [VNet 配置与运维](assets/docs/vnetwork/README_ZH.md)。

| 需求 | 功能 | 入口位置 | 目标位置 | 协议 |
| --- | --- | --- | --- | --- |
| 发布单个客户端服务 | 普通 Proxy | `portwayd` | 客户端网络 | TCP、UDP、HTTP、HTTPS |
| 将公共输入复制给多个客户端 | 镜像 Proxy | `portwayd` | 多个客户端网络 | TCP、UDP |
| 从本地访问服务端侧服务 | Forward | `portway` | 服务端网络 | TCP、UDP |
| 连接 Managed 虚拟节点 | VNet | 任意已配置节点 | 服务端或客户端节点 | TCP、UDP |

下表帮助选择模式；详细流量图和边界请参阅
[三种连接模式](assets/docs/modes/README_ZH.md)。

## 功能亮点

**三种受控连接能力**

- 通过服务端公共 Listener 代理客户端侧 TCP 和 UDP 服务。
- 将受 Governed 或 Managed 管理的公共 TCP/UDP Proxy 入口镜像给多个客户端，
  同时阻止影子客户端影响访问者响应。
- 按域名代理 HTTP 或 HTTPS，支持服务端 TLS 终止、流式传输、Upgrade、连接复用
  和证书原子热更新。
- 将客户端侧 TCP/UDP Listener 转发到服务端网络，并由服务端 Allowlist 按 CIDR、
  协议和端口限制所有目标。
- 在同一个认证客户端会话中同时运行 Proxy 和 Forward 条目。
- 通过服务端集中路由和节点级 TCP/UDP 入站端口策略连接 Managed VNet 节点。

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

前两个示例使用 Shared 认证模式。请将
`REPLACE_WITH_SAME_RANDOM_TOKEN_OVER_32_CHARS` 替换为密码学安全生成的 Token，
并在两个配置文件中使用相同值。Token 必须包含大于 32 个 UTF-8 字符。应先启动
`portwayd`，再启动 `portway`。第三个示例使用由服务端定义身份与配置的 Managed 模式。

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

### 场景三：让受管节点通过私有地址互相访问

当不希望为每项服务分别创建 Proxy 或 Forward 入口，而需要让分布在不同网络、由同一服务端
管理的节点以稳定私有地址互访时，使用 VNet。它让私网中的访问体验接近 VPN：应用直接访问
目标节点私有地址和端口。例如，为服务端分配 `172.20.0.1`，为边缘节点分配 `172.20.0.2`，
并只允许其他 VNet 节点访问该节点的 TCP `8080` 端口。

先在 `managed_clients_path` 指定的目录中创建一个 Managed 客户端记录，例如
`managed/edge-a.yaml`：

```yaml
authentication:
  client_id: edge-a
  token: REPLACE_WITH_A_UNIQUE_RANDOM_TOKEN_OVER_32_CHARS
configuration:
  revision: 1
  proxies: []
  forwards: []
```

在 `server.yaml` 启用该节点的地址与端口策略：

```yaml
authentication:
  managed_clients_path: ./managed

virtual_network:
  enabled: true
  cidr: 172.20.0.0/16
  server_ip: 172.20.0.1
  server_ports:
    tcp:
      port_ranges:
        - start: 22
          end: 22
  nodes:
    - client_id: edge-a
      ip: 172.20.0.2
      ports:
        tcp:
          port_ranges:
            - start: 8080
              end: 8080
```

在节点上配置最小的 `client.yaml`，其中 Token 必须与该 Managed 记录一致：

```yaml
transport:
  type: tcp
  server_address: SERVER_IP:7000
authentication:
  client_id: edge-a
  token: REPLACE_WITH_A_UNIQUE_RANDOM_TOKEN_OVER_32_CHARS
```

启动后，服务端可访问 `172.20.0.2:8080`，该节点可访问已授权的
`172.20.0.1:22`；客户端间流量在探测成功后自动使用 QUIC 直连，否则继续经 `portwayd`
中继；涉及服务端的流量不会升级到 P2P。VNet 需要 Linux 或
macOS 的 TUN 权限，首次启用可能请求操作系统授权。Windows amd64 上需要以管理员身份
运行启用 VNet 的进程，发布包已内置 Wintun。完整配置、`tun`/`loopback` 交付方式、
端口策略和安装维护命令请参阅 [VNet 配置与运维](assets/docs/vnetwork/README_ZH.md)。

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
共用代理限制。HTTPS 要求规范化后的 SNI 与 HTTP `Host` 完全一致。HTTP/HTTPS 合计最多 4096 条公网连接，TLS 握手最多 10 秒；请求头默认 10 秒，
公网 Keep-Alive 空闲默认 60 秒。请求体及上游业务限制默认关闭，可在 `proxies.http` 中配置。HTTPS 根据 SNI 从可原子热更新的证书集合中选择证书；
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

**开始使用**

- [三种连接模式：Proxy、Forward 与 VNet](assets/docs/modes/README_ZH.md)
- 完整中文注释配置示例：
  [客户端](config/zh/client.yaml) 和 [服务端](config/zh/server.yaml)
- [多模式认证与配置控制](assets/docs/authentication/README_ZH.md)
- [安全性](assets/docs/security/README_ZH.md)

**按需功能**

- [VNet 配置与运维](assets/docs/vnetwork/README_ZH.md)
- [TCP 与 UDP Proxy 镜像](assets/docs/proxy-mirroring/README_ZH.md)

**架构与运维**

- [技术概览](assets/docs/technical/README_ZH.md)
- [运维接口](assets/docs/operations/README_ZH.md)
- [服务端配置热加载](assets/docs/reload/README_ZH.md)
- [未来计划](assets/docs/future/README_ZH.md)

技术文档描述稳定的行为和安全性属性，而非作为完整的线协议规范。

## 许可证

Copyright 2026 Acexy.

Portway 基于 [Apache License 2.0](LICENSE) 许可。有关归属信息，请参阅 [NOTICE](NOTICE)。
