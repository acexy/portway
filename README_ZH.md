<p align="center">
  <img src="assets/portway-logo.png" width="180" alt="Portway logo">
</p>

<h1 align="center">Portway</h1>

<p align="center">
轻量、安全的跨网络连接工具：发布私有服务、访问远端内网，或连接分散的受管节点。
</p>

Portway 在 `portway` 客户端与 `portwayd` 服务端之间建立认证、加密的连接。
它适合没有固定公网地址、位于 NAT 后方或不希望直接开放端口的服务。

```text
私有网络 / 边缘节点  <-- 认证加密连接 -->  公网或中心节点
       portway                              portwayd
```

## 可以用它做什么

### 发布私有服务

把家庭网络、开发机或边缘节点上的 SSH、Web、DNS、游戏服务等，通过一台可访问的
`portwayd` 主机提供给用户。

```text
访问者 -> portwayd 公共端口或域名 -> portway -> 私有服务
```

这就是 **Proxy** 模式，支持 TCP、UDP、HTTP 和 HTTPS。TCP/UDP Proxy 还可以将同一份
输入镜像给多个客户端，用于观测、审计和影子验证。

### 安全访问远端内网

在本地打开一个端口，访问只有 `portwayd` 所在网络才能到达的数据库、管理接口、
内部 DNS 或其他服务，而不必把它们暴露到公网。

```text
本地应用 -> portway 本地端口 -> portwayd -> 获准的内网服务
```

这就是 **Forward** 模式，支持 TCP 和 UDP。服务端通过 IP、协议和端口规则限制
客户端能够访问的目标。

### 获得类似 VPN 的私网互联体验

为不同网络中的服务器、工作站或边缘节点分配稳定的私有 IPv4 地址，让应用像使用
VPN 一样，直接通过私有地址访问其他受管节点。

```text
受管节点 A -> 私有地址 -> portwayd Relay / 自动 QUIC P2P -> 受管节点 B
```

这就是 **VNet** 模式。它提供类似中心式 VPN 的私网互联体验：客户端之间会自动尝试
QUIC Datagram 直连，不可直连时继续通过服务端中继；与传统的无边界二层或三层 VPN
不同，每个目标节点仍通过 TCP/UDP 端口策略控制入站访问。

| 你的需求 | 选择 | 入口在哪里 | 目标在哪里 |
| --- | --- | --- | --- |
| 对外提供客户端侧服务 | Proxy | `portwayd` | 客户端网络 |
| 在本地使用服务端侧内网服务 | Forward | `portway` | 服务端网络 |
| 获得类似 VPN 的受控私网互联 | VNet | 节点私有地址 | 服务端或受管客户端 |

## 为什么选择 Portway

- **职责清晰：** Proxy、Forward 和 VNet 可以独立使用，也可以按需组合。
- **安全默认：** 所有连接都需要 Token 认证并加密，不提供明文降级。
- **协议完整：** 保留 TCP 字节流与半关闭、UDP 数据报边界和 HTTP 请求语义。
- **连接灵活：** 客户端与服务端之间可选择 TCP 或 QUIC Transport。
- **策略可控：** 支持 Shared、Governed、Managed 三种配置控制方式，以及来源 IP
  拒绝列表和服务端热加载。
- **运行稳定：** 资源、队列和恢复窗口均有边界，配置以完整集合原子发布。

## 5 分钟体验

下面把客户端主机的 SSH 服务发布到 `SERVER_IP:22022`。

在服务端创建 `server.yaml`：

```yaml
transport:
  type: tcp
  listen_address: 0.0.0.0:7000

authentication:
  shared_token: REPLACE_WITH_SAME_RANDOM_TOKEN_OVER_32_CHARS
```

在客户端创建 `client.yaml`：

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

请将示例 Token 替换为双方相同的密码学安全随机值。先启动服务端，再启动客户端：

```bash
portwayd run server.yaml
portway run client.yaml
```

现在可以通过 `SERVER_IP:22022` 访问客户端的 SSH 服务。

Forward、VNet、HTTP/HTTPS、UDP 和 QUIC 的配置方式见
[安装与快速开始](assets/docs/getting-started/README_ZH.md)。完整注释模板见
[客户端配置](config/zh/client.yaml)和[服务端配置](config/zh/server.yaml)。

## 安装

macOS 和 Linux 可以通过 [Acexy Homebrew Tap](https://github.com/acexy/homebrew-tap)
分别安装客户端和服务端：

```bash
brew install acexy/tap/portway
brew install acexy/tap/portwayd
```

也可以从 GitHub Releases 下载对应平台的发布包。Windows amd64 发布包已包含 VNet
所需的官方签名 Wintun 组件。

## 文档

**开始使用**

- [安装、命令与快速开始](assets/docs/getting-started/README_ZH.md)
- [三种连接模式：Proxy、Forward 与 VNet](assets/docs/modes/README_ZH.md)
- [完整客户端配置](config/zh/client.yaml)与[完整服务端配置](config/zh/server.yaml)

**功能与安全**

- [多模式认证与配置控制](assets/docs/authentication/README_ZH.md)
- [VNet 配置与运维](assets/docs/vnetwork/README_ZH.md)
- [TCP 与 UDP Proxy 镜像](assets/docs/proxy-mirroring/README_ZH.md)
- [安全性](assets/docs/security/README_ZH.md)

**架构与运维**

- [技术概览](assets/docs/technical/README_ZH.md)
- [运维接口](assets/docs/operations/README_ZH.md)
- [服务端配置热加载](assets/docs/reload/README_ZH.md)
- [未来计划](assets/docs/future/README_ZH.md)

## 许可证

Copyright 2026 Acexy.

Portway 基于 [Apache License 2.0](LICENSE) 许可。有关归属信息，请参阅 [NOTICE](NOTICE)。
