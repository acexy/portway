# 安装与快速开始

本文档说明 Portway 的安装、命令、配置文件约定，以及 Proxy、Forward、VNet 和 QUIC
Transport 的基本配置。完整字段与默认值请参阅带注释的
[客户端配置](../../../config/zh/client.yaml)和[服务端配置](../../../config/zh/server.yaml)。

## 安装

macOS 和 Linux 可以通过 [Acexy Homebrew Tap](https://github.com/acexy/homebrew-tap) 安装：

```bash
brew install acexy/tap/portway
brew install acexy/tap/portwayd
```

客户端与服务端可以安装在同一主机。Formula 不会创建或覆盖配置文件。
也可以从 GitHub Releases 下载对应平台的发布包。Windows amd64 发布包已包含 VNet
所需的官方签名 `wintun.dll`。

## 命令与配置文件

常用命令如下：

```text
portway run [config]
portway gen config [full]
portway version

portwayd run [config]
portwayd gen config [full]
portwayd gen cert [options]
portwayd version
```

`gen config` 在当前目录生成最小的 `client.yaml` 或 `server.yaml`；追加 `full` 会生成
完整注释模板。命令不会覆盖已有文件。省略 `run` 的配置路径时，客户端读取当前目录的
`client.yaml`，服务端读取 `server.yaml`。

以下示例使用 Shared Token。请使用双方相同、密码学安全且超过 32 个 UTF-8 字符的
随机 Token，不要提交真实凭据。

## Proxy：发布客户端侧服务

服务端配置：

```yaml
transport:
  type: tcp
  listen_address: 0.0.0.0:7000

authentication:
  shared_token: REPLACE_WITH_SAME_RANDOM_TOKEN_OVER_32_CHARS
```

客户端配置将本机 SSH 发布到服务端 TCP `22022` 端口：

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

先运行 `portwayd run server.yaml`，再运行 `portway run client.yaml`。访问者随后可连接
`SERVER_IP:22022`。UDP 使用相同结构，将 `type` 改为 `udp`；Portway 会保留数据报边界。

HTTP/HTTPS Proxy 使用 `public.domain` 和 `public.schemes` 选择服务端入口。
HTTPS 在 `portwayd` 终止 TLS，并通过认证隧道以 HTTP 回源。Listener、证书、超时和
容量配置见完整服务端模板；行为边界见[技术概览](../technical/README_ZH.md)。

需要受控的一对多递送时，镜像 Proxy 可以把相同的公共 TCP/UDP 输入复制给多个
Governed 或 Managed 客户端，同时只允许指定的 Primary 回复。它适合观测、审计、
并行处理和影子验证，但不是负载均衡器。配置方法见
[TCP 与 UDP Proxy 镜像](../proxy-mirroring/README_ZH.md)。

## Forward：访问服务端侧网络

Forward 默认关闭。服务端必须明确启用，并限制允许访问的目标网段、协议和端口：

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

客户端在回环地址创建本地入口：

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

启动双方后，本地应用连接 `127.0.0.1:15432` 即可访问目标数据库。除非确实需要其他
主机访问，应将本地入口绑定到回环地址。目标只接受明确的 IP，每次连接都会按服务端
当前规则授权。完整边界见[Forward：访问服务端侧网络](../forward/README_ZH.md)。

## VNet：类似 VPN 的私网互联

VNet 为服务端和 Managed 客户端分配稳定的私有 IPv4 地址，提供类似 VPN 的节点互访
体验。它不是无边界网络：访问仍由每个目标节点的 TCP/UDP 入站端口策略控制。

先在 `managed_clients_path` 中创建 Managed 客户端记录，再在服务端配置地址和策略：

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

Managed 客户端只需提供与服务端记录匹配的身份、Token 和 Transport 地址；VNet 参数由
服务端下发。客户端间流量先使用 Relay，探测成功后新 Flow 自动使用 QUIC Datagram
直连，不可直连时继续中继。涉及服务端的流量始终中继。

VNet 支持 Linux、macOS 和 Windows amd64，并需要相应的 TUN/Wintun 权限。P2P 还需要
允许 `P+1/UDP`，其中 `P` 是 Transport 端口。完整 Managed 记录、`tun`/`loopback`
模式和平台运维命令见 [VNet 配置与运维](../vnetwork/README_ZH.md)。

## 使用 QUIC Transport

TCP 和 QUIC Transport 不改变 Proxy、Forward 或 VNet 的业务语义。QUIC 除了 Portway
Token 认证，还要求客户端验证服务端 TLS 证书。

私有部署可以生成内部 CA 和服务端证书：

```bash
portwayd gen cert --server-name gateway.example.com --ip 10.0.0.10
```

服务端配置证书和私钥：

```yaml
transport:
  type: quic
  listen_address: 0.0.0.0:7000
  quic:
    cert_file: ./certs/server.crt
    key_file: ./certs/server.key
```

客户端配置证书身份和根 CA：

```yaml
transport:
  type: quic
  server_address: 10.0.0.10:7000
  quic:
    server_name: gateway.example.com
    ca_file: ./certs/root-ca.crt
```

`server_name` 必须匹配证书 SAN。妥善保护 `root-ca.key` 和 `server.key`，只向客户端
分发 `root-ca.crt`。更多安全要求见[安全性](../security/README_ZH.md)。

## 下一步

- 选择配置控制方式：[多模式认证与配置控制](../authentication/README_ZH.md)
- 发布客户端侧服务：[Proxy](../proxy/README_ZH.md)
- 访问服务端侧网络：[Forward](../forward/README_ZH.md)
- 连接受管节点：[VNet](../vnetwork/README_ZH.md)
- 安全复制公共 TCP/UDP 输入：[TCP 与 UDP Proxy 镜像](../proxy-mirroring/README_ZH.md)
- 配置监控与探针：[运维接口](../operations/README_ZH.md)
- 了解热加载范围：[服务端配置热加载](../reload/README_ZH.md)
