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

`GET /metrics` 返回兼容 Prometheus 文本格式的当前快照。除以 `_total` 结尾的 Counter 外，其余指标均为 Gauge：

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
| `portway_forward_links_pending` | 等待绑定的 Forward Data Link |
| `portway_forward_links_active` | 已绑定的 Forward Data Link |
| `portway_forward_bindings` | 已注册 Forward Binding |
| `portway_forward_bindings_active` | Active Forward Binding |
| `portway_forward_bindings_inactive` | 非 Active Forward Binding，不等同故障数 |
| `portway_tcp_forwards` | 已注册 TCP Forward |
| `portway_udp_forwards` | 已注册 UDP Forward |
| `portway_forward_udp_associations` | 服务端 Forward UDP Association，含 Pending |
| `portway_forward_udp_pending_associations` | 服务端 Forward Pending UDP Association |
| `portway_forward_udp_queued_bytes` | 服务端 Forward UDP 排队 Payload 字节 |
| `portway_tcp_mirror_groups` | TCP Mirror 组 |
| `portway_udp_mirror_groups` | UDP Mirror 组 |
| `portway_tcp_mirror_members` | TCP Mirror 已注册成员 |
| `portway_udp_mirror_members` | UDP Mirror 已注册成员 |
| `portway_vnet_enabled` | VNet 配置是否启用 |
| `portway_vnet_device_open` | 服务端运行时是否持有 VNet Device |
| `portway_vnet_device_preparing` | 服务端是否正在准备 VNet Device |
| `portway_vnet_nodes` | 已配置 VNet 节点数 |
| `portway_vnet_sessions` | 已附着的 VNet 控制 Session 数 |
| `portway_vnet_configuration_generation` | VNet 配置 Generation |
| `portway_vnet_pools_pending` | Pending Channel Pool 数 |
| `portway_vnet_pools_active` | 已发布的 Active Channel Pool 数 |
| `portway_vnet_channels_active` | Active Pool 中 Channel 数 |
| `portway_vnet_flows` | 服务端 Router Flow 记录数 |
| `portway_vnet_peer_pairs` | 服务端协调的 Peer Pair 数 |
| `portway_vnet_direct_pairs` | 服务端已激活的 Direct Pair 数 |
| `portway_vnet_queued_packets` | 服务端发送队列包数 |
| `portway_vnet_userspace_flows` | 服务端用户态 Flow 记录数 |
| `portway_vnet_tcp_connections` | 服务端用户态 TCP Connection 数 |
| `portway_vnet_udp_associations` | 服务端用户态 UDP Association 数 |
| `portway_vnet_capacity_rejected_total` | Router 容量拒绝累计数 |
| `portway_vnet_rate_rejected_total` | Router 速率拒绝累计数 |
| `portway_vnet_policy_rejected_total` | Router 策略拒绝累计数 |
| `portway_vnet_queue_rejected_total` | 发送队列准入拒绝累计数 |
| `portway_vnet_queue_expired_total` | 排队包过期累计数 |
| `portway_vnet_queue_revoked_total` | 排队包授权撤销累计数 |
| `portway_vnet_queue_write_failed_total` | 排队包写入失败累计数 |

指标不会使用 ClientID、SessionID、ProxyName、LinkID、域名或来源 IP 作为标签，
从而保持基数有界，并避免通过监控接口暴露部署身份。

Counter 在同一服务端 VNet Runtime 生命周期内累计，配置更新、Session 重连、Pool
重建和 VNet 禁用不会主动清零；新 Runtime 或进程重启可以重置。未创建的组件返回零。

这些指标仅描述服务端观察到的资源与事件：Forward Active 不保证客户端 Listener 或
目标服务可达；VNet Device 存在不保证系统路由或端到端通信健康；Attached Session
不等于 Active 节点；Direct Pair 表示协调状态，不保证当前直连路径健康。P2P 直连流量
不经过服务端，本接口不报告完整 VNet 流量。正常 Relay 回退不是整体故障。

各组件快照分别采集，跨组件读数不保证全局事务一致性。Forward UDP 与 Proxy UDP
分别记账。局部功能不可用不会使全局 `/readyz` 失败。接口不会主动探测目标、修复
系统网络或返回身份、地址、策略明细；保护 Listener 的既有要求保持不变。

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

## 客户端重连

客户端遇到临时连接或服务端故障时会持续重试，直到进程停止。永久认证、协议
和配置错误会终止客户端。每次控制 Session 建立共用 20 秒期限，其中 Transport
拨号最多 5 秒；取消操作可以进一步缩短期限。

心跳每 5 秒发送一次，20 秒没有有效响应触发重连。服务端保留暂停 Session
60 秒。客户端最多尝试恢复身份 90 秒，之后重新注册。失败的恢复初始化不会
延长服务端保留窗口。

恢复重试间隔为 0.5、1、2 秒，最高 3 秒；普通注册为 1、2、4、8、15 秒，最高
30 秒，均加入 ±25% 抖动。首次建立连接后启用快速恢复；之后短暂连接保留退避，
只有连接健康运行至少 60 秒并持续收到有效心跳响应才重置退避。这些时间参数
当前为固定值。
