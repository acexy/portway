# Portway 运维接口

Portwayd 可以通过独立 HTTP Listener 提供进程探针和低基数运行指标。该 Listener
默认关闭，不承载公网代理流量或客户端—服务端隧道流量。

## 启用 Listener

在 `server.yaml` 中配置独立地址：

```yaml
operations:
  listen_address: 127.0.0.1:9090
```

修改该地址需要重启 `portwayd`。它不能与 Transport、公网 HTTP 或公网 HTTPS
Listener 使用相同地址。

运维接口不提供应用层认证。应将 Listener 绑定到回环地址或受保护的管理网络，
不得直接暴露到公网。

## 健康检查

`GET /healthz` 用于确认进程及其运维 HTTP Server 仍能响应。正常时返回：

```text
HTTP/1.1 200 OK

ok
```

该端点适合作为进程存活探针，但不保证隧道 Listener 或代理 Listener 已完成初始化。

## 就绪检查

`GET /readyz` 表示 Transport、Proxy Registry 和全部已配置 Listener 是否完成初始化。

- 已就绪：返回 `200 OK` 和 `ready`；
- 尚未初始化或正在退出：返回 `503 Service Unavailable` 和 `not ready`。

该端点适合作为就绪探针或负载均衡器健康检查。

## 指标

`GET /metrics` 返回兼容 Prometheus 文本格式的当前快照。现有指标均为 Gauge：

| 指标 | 含义 |
|---|---|
| `portway_ready` | 所有已配置 Listener 是否完成初始化 |
| `portway_configuration_generation` | 当前已发布的服务端配置 Generation |
| `portway_sessions_initializing` | 正在初始化的控制 Session 数量 |
| `portway_sessions_active` | 活跃控制 Session 数量 |
| `portway_sessions_suspended` | 可恢复的暂停 Session 数量 |
| `portway_links_pending` | 等待绑定的 Data Link 数量 |
| `portway_links_active` | 已绑定的活跃 Data Link 数量 |
| `portway_tcp_proxies` | 已注册 TCP Proxy 数量 |
| `portway_udp_proxies` | 已注册 UDP Proxy 数量 |
| `portway_http_proxies` | 已注册 HTTP 域名 Proxy 数量 |
| `portway_http_active_requests` | 活跃 HTTP/HTTPS 请求数量 |
| `portway_http_active_upgrades` | 活跃 HTTP Upgrade 连接数量 |
| `portway_udp_associations` | UDP Association 总数，包括 Pending Association |
| `portway_udp_pending_associations` | 等待 Data Link 的 UDP Association 数量 |
| `portway_udp_queued_bytes` | 当前在内存中排队的 UDP Payload 字节数 |

指标不会使用 ClientID、SessionID、ProxyName、LinkID、域名或来源 IP 作为标签，
从而保持基数有界，并避免通过监控接口暴露部署身份。

第一版只报告当前资源水位，暂不提供请求、失败或流量累计 Counter。

## 探针示例

```bash
curl --fail http://127.0.0.1:9090/healthz
curl --fail http://127.0.0.1:9090/readyz
curl http://127.0.0.1:9090/metrics
```

Kubernetes 探针示例：

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 9090
readinessProbe:
  httpGet:
    path: /readyz
    port: 9090
```

仍需通过网络策略或等效的主机防火墙限制对运维 Listener 的访问。
