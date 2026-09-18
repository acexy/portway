# Proxy：发布客户端侧服务

Proxy 将 `portway` 客户端可访问的服务，通过 `portwayd` 上稳定的公共或中心入口
提供出去。服务本身可以继续位于家庭局域网、开发机、私有云或边缘站点，无需直接
接受来自公网的入站连接。

Proxy 支持 TCP、UDP 公共端口，以及基于域名路由的 HTTP 和 HTTPS。TCP/UDP Proxy
还提供受控的一对多镜像变体。

## 适用场景

以下情况适合使用 Proxy：

- SSH、Web 应用、DNS、遥测或其他服务位于 NAT 后方；
- 服务没有稳定公网地址，但需要稳定的服务端入口；
- 希望在 `portwayd` 集中终止公网 TLS；
- 多个获授权消费者需要观测完全相同的 TCP/UDP 输入。

如果需要在客户端创建本地入口，访问服务端可达的目标，应使用
[Forward](../forward/README_ZH.md)。如果受管节点需要通过稳定私有地址互访，而不是
逐个发布服务，应使用 [VNet](../vnetwork/README_ZH.md)。

## 网络流程

```text
                       认证的 TCP 或 QUIC Transport
公网访问者           +--------------------------------------+
    |                |                                      |
    v                v                                      v
portwayd 公共 Listener -> 已授权 Proxy -> Data Link -> portway
                                                            |
                                                            v
                                                   客户端侧服务
```

1. 客户端完成认证并注册完整 Proxy 集合，或从 Managed 服务端记录接收配置。
2. `portwayd` 校验所有权和冲突，然后原子发布 Listener 或域名路由。
3. 访问者连接服务端端口，或向配置域名发送 HTTP 请求。
4. 服务端向所属客户端请求一条认证 Data Link。
5. 客户端连接配置的本地 IP 和端口并中继流量。

TCP 保留字节流和半关闭语义；UDP 保留数据报边界，并通过有界 Association 隔离
访问者；HTTP 保留请求、流式响应和 Upgrade 行为。公网 HTTPS 在 `portwayd` 终止
TLS，客户端侧源站接收 HTTP。

## 普通 Proxy 配置

最小 Shared 认证服务端只需要 Transport Listener，以及与客户端相同的高熵 Token：

```yaml
transport:
  type: tcp
  listen_address: 0.0.0.0:7000

authentication:
  shared_token: REPLACE_WITH_SAME_RANDOM_TOKEN_OVER_32_CHARS
```

客户端发布本地 SSH 和 UDP DNS：

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

  - name: dns
    type: udp
    local:
      ip: 127.0.0.1
      port: 53
    public:
      port: 5353
```

访问者可以通过 `SERVER_IP:22022/TCP` 和 `SERVER_IP:5353/UDP` 访问对应服务。
本地目标也可以是客户端可达的其他规范 IP 地址，但不接受主机名。

## HTTP 与 HTTPS

在服务端启用公共 Listener。HTTPS 还需要 SNI 证书映射；该证书与 QUIC Transport
证书彼此独立。

```yaml
proxies:
  http:
    listen_address: 0.0.0.0:80
  https:
    listen_address: 0.0.0.0:443
    certificates:
      - domains:
          - app.example.com
        cert_file: /path/to/app.example.com.crt
        key_file: /path/to/app.example.com.key
```

客户端注册域名：

```yaml
proxies:
  - name: web
    type: http
    local:
      ip: 127.0.0.1
      port: 8080
    public:
      schemes:
        - http
        - https
      domain: app.example.com
```

DNS 必须将域名指向 `portwayd`。使用 HTTPS 时，SNI 与 HTTP `Host` 必须匹配。
本地服务使用 HTTP；Portway 当前不提供 HTTPS 回源、TLS 透传、ACME 或 HTTP/3。

## 镜像 Proxy

镜像 Proxy 将相同的 TCP 字节或 UDP 数据报复制给多个 Governed 或 Managed 客户端。
只有 `primary_client_id` 可以回复，其他响应会被持续读取并丢弃。

```text
                              +-> Primary 客户端 -> 主服务 -----+
访问者 -> portwayd TCP/UDP ---+                                 +-> 访问者
                              +-> 镜像客户端  -> 影子服务 -----X
                              +-> 镜像客户端  -> 观察服务 -----X
```

它适合流量观测、审计、协议分析、并行处理和使用真实输入验证替代服务。它不是负载
均衡器：不会分配访问者、聚合响应，也不会选举替代 Primary。

镜像组由服务端管理，并要求 Governed 或 Managed 身份：

```yaml
proxies:
  mirror:
    governed:
      - name: telemetry
        type: tcp
        public:
          port_ranges:
            - start: 2233
              end: 2233
        primary_client_id: governed-primary
        client_ids:
          - governed-primary
          - governed-observer
```

每个成员仍需具有匹配权限，并配置相同公共端口的 Proxy。成员加入活跃 TCP Flow 时
可能从任意字节偏移开始，此前输入绝不回放。完整成员关系、恢复和热更新行为见
[TCP 与 UDP Proxy 镜像](../proxy-mirroring/README_ZH.md)。

## 安全与运行注意事项

- 除非由上游防火墙或反向代理限制，否则公共 Proxy 端口和域名面向互联网；应按需
  保护应用本身。
- 将 `proxies.bind_ip` 绑定到预期接口；来源 IP 拒绝列表是应用控制，不能替代防火墙。
- Shared 客户端直接声明配置；Governed 客户端受服务端权限约束；Managed 配置完全
  由服务端管理。
- TCP 与 QUIC Transport 保持相同 Proxy 语义；QUIC 除 Token 认证外还要求有效的
  服务端 TLS 身份。
- 公共端口和域名必须唯一；冲突时整批注册原子拒绝，不会部分生效。
- 镜像带宽和 Data Link 消耗随在线成员数量增加，应相应规划带宽、连接限制和队列。

所有限制与默认值见带注释的[客户端](../../../config/zh/client.yaml)和
[服务端](../../../config/zh/server.yaml)模板。
