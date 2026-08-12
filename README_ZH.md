<p align="center">
  <img src="assets/portway-logo.png" width="180" alt="Portway logo">
</p>

<h1 align="center">Portway</h1>

<p align="center">
  一款轻量级、面向长期可靠稳定运行的反向隧道系统，支持 TCP、UDP、HTTP 和 HTTPS 服务。
</p>

Portway 通过公共服务端将私有网络中的服务暴露到公网。它将控制平面与隧道流量分离，
支持 TCP 和 QUIC 作为底层客户端-服务端传输协议，并围绕显式资源归属、有界资源管理和安全默认配置进行设计。

## 亮点

- TCP、UDP 和基于域名的 HTTP/HTTPS 反向代理
- 可选 TCP 或 QUIC 作为客户端-服务端传输协议
- 认证加密的客户端-服务端连接
- 原子化代理注册与有界会话恢复
- HTTP/HTTPS 流式传输和 Upgrade 支持，具备连接复用能力
- 服务端 HTTPS TLS 终止与证书原子热更新
- 基于独立规则文件监视的 IPv4/IPv6 来源 IP 阻断策略
- 严格的 YAML 配置和故障关闭（fail-closed）校验
- 小巧的客户端和服务端二进制文件，命令行接口风格一致
- **灵活的客户端配置治理：**
  - 面向可信客户端群组的共享配置
  - 受策略约束的客户端配置
  - 完全由服务端管理的客户端配置
- **故障关闭的服务端主配置热加载：**
  - 完整配置代际的原子校验与发布
  - 选择性凭证吊销和 Managed 配置在线切换
  - 校验失败时自动保留上一份有效快照

## 快速开始

以下示例将客户端的本地 SSH 服务暴露在 Portway 服务端的 TCP 端口 `22022` 上。

创建 `server.yaml`：

```yaml
transport:
  type: tcp
  listen_address: 127.0.0.1:7000

authentication:
  shared_token: REPLACE_WITH_AT_LEAST_32_RANDOM_BYTES
```

创建 `client.yaml`：

```yaml
transport:
  type: tcp
  server_address: 127.0.0.1:7000

authentication:
  token: REPLACE_WITH_AT_LEAST_32_RANDOM_BYTES

proxies:
  - name: ssh
    type: tcp
    local_ip: 127.0.0.1
    local_port: 22
    remote_port: 22022
```

在两端使用相同的加密随机 Token，然后启动服务端和客户端：

```bash
portwayd run --config server.yaml
portway run --config client.yaml
```

本地 SSH 服务现在可以通过以下地址访问：

```text
127.0.0.1:22022
```

## HTTP 与 HTTPS 代理

在服务端按需启用 HTTP、HTTPS 或两个公网 Listener；
`https_listen_address` 为空时禁用 HTTPS：

```yaml
tunnel:
  http_listen_address: 127.0.0.1:8080
  https_listen_address: 127.0.0.1:8443

https:
  certificates:
    - domains: [app.example.com]
      cert_file: /path/to/https-server.crt
      key_file: /path/to/https-server.key
```

在客户端注册一个域名：

```yaml
proxies:
  - name: web
    type: http
    public_schemes:
      - https
      - http
    domain: app.example.com
    local_ip: 127.0.0.1
    local_port: 8080
```

`type` 表示 `portwayd` 与 `portway` 之间的代理语义，`public_schemes` 显式选择
公网 HTTP/HTTPS Listener；任一所选 Listener 未启用都会拒绝整批注册。
省略或留空 `public_schemes` 时默认仅使用 HTTP 入口。
公共 `Host` 会被匹配到已认证的客户端注册信息。`portwayd` 终止公网 HTTPS，
随后通过认证隧道固定回源 HTTP，因此本地应用只接收普通 HTTP 请求。Visitor
提供的 `Forwarded` 和 `X-Forwarded-*` 会被删除，`portwayd` 写入可信的
`X-Forwarded-For`、`X-Forwarded-Host` 和 `X-Forwarded-Proto`。HTTP 与 HTTPS
共用代理限制。HTTPS 根据 SNI 从可原子热更新的证书集合中选择证书；
无效更新会继续使用上一代集合。HTTPS 支持 HTTP/1.1、HTTP/2，最低使用 TLS 1.2。
当前不支持 HTTPS 回源、SNI 透传、ACME 和 HTTP/3。

## UDP 代理

在客户端注册一个公共 UDP 端口和本地 UDP 服务：

```yaml
proxies:
  - name: dns
    type: udp
    local_ip: 127.0.0.1
    local_port: 53
    remote_port: 5353
```

Portway 保留数据报边界，并为每个公网访问者关联提供独立的认证数据链路。
无论选择 TCP 还是 QUIC 作为客户端-服务端传输，UDP 均可正常工作。
服务端的关联、队列、速率、内存和空闲限制均设有安全默认值和可配置的硬上限。

## QUIC 传输

Portway 可以在 `portway` 和 `portwayd` 之间使用 QUIC 替代 TCP。
QUIC 除了需要 Portway Token 认证外，还需要服务端证书和 TLS 验证。

对于私有部署，生成内部 CA 和服务端证书：

```bash
portwayd gen cert \
  --server-name gateway.example.com \
  --ip 10.0.0.10
```

运行 `portwayd help gen cert` 查看所有证书选项。请将生成的根 CA 私钥离线保管，
仅向客户端分发根 CA 证书。

## 命令

```text
portway run [--config FILE]
portway gen config [full]
portway version

portwayd run [--config FILE]
portwayd gen config [full]
portwayd gen cert [options]
portwayd version
```

`gen config` 会在当前目录创建最小可运行的 `client.yaml` 或 `server.yaml`；
追加 `full` 可生成带完整注释的全量模板。命令不会覆盖已有文件。直接运行任一
二进制文件（不带参数）会列出包括嵌套生成命令在内的全部可用命令。

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

## 公开文档

- [技术概览](assets/docs/technical/README_ZH.md)
- [运维接口](assets/docs/operations/README_ZH.md)
- [多模式认证与配置控制](assets/docs/authentication/README_ZH.md)
- [服务端配置热加载](assets/docs/reload/README_ZH.md)
- [安全性](assets/docs/security/README_ZH.md)
- [未来计划](assets/docs/future/README_ZH.md)
- 完整中文注释配置示例：
  [客户端](config/zh/client.yaml) 和 [服务端](config/zh/server.yaml)

公开文档有意描述稳定的行为和安全性属性，而非作为完整的线协议规范。

## 当前范围

Portway 专注于轻量级、由运维人员管理的反向隧道。目前不提供 Web 仪表板、
P2P NAT 穿透、TUN/TAP 网络、动态插件或分布式多租户控制平面。

## 许可证

Copyright 2026 Acexy.

Portway 基于 [Apache License 2.0](LICENSE) 许可。有关归属信息，请参阅 [NOTICE](NOTICE)。
