# TCP 与 UDP Proxy 镜像

Proxy 镜像是 Proxy 模式的一种受控变体。`portwayd` 上的一个逻辑公共 TCP 或 UDP
端口组承接访问者流量，并把相同输入复制给多个已配置的 `portway` 客户端。

它不是负载均衡器，不会把不同访问者分配给不同成员；它也与 Forward 模式无关：
公共 Listener 仍位于 `portwayd`，目标仍是各客户端可访问的服务。

## 使用场景

典型场景包括：

- 将同一份遥测或事件流交给多个处理器；
- 在不允许观察端影响回复的前提下观测生产流量；
- 切换前使用真实输入验证替代服务；
- 并行执行协议分析、审计或入侵检测；
- 对比多个实现，同时保留唯一的权威回复端。

如果每个后端都必须独立服务访问者、需要聚合多个响应，或者需要在后端之间分配
访问者，则不应使用镜像 Proxy。这些需求应由应用层分发、消息系统或负载均衡器
处理。

## 流量与回复模型

```text
                              +-> Primary 客户端 -> 主服务 -----+
访问者 -> portwayd TCP/UDP ---+                                 +-> 访问者
                              +-> 镜像客户端  -> 影子服务 -----X
                              +-> 镜像客户端  -> 观察服务 -----X
```

对于每个新建 TCP 连接或 UDP Visitor Association：

1. `portwayd` 获取当时在线且已配置的成员快照。
2. 访问者输入独立复制给快照中的每个成员。
3. 只有 `primary_client_id` 拥有回复权。
4. 非 Primary 的回复会被持续读取并丢弃，避免其发送缓冲区阻塞正常处理。
5. Primary 离线时，其他在线成员仍会收到输入，但不会向访问者回复，也不会自动
   选举替代 Primary。

TCP 在每条成员链路上保留字节流和半关闭语义，单个缓慢或故障成员不会阻塞其他
成员。UDP 保留数据报边界，并为每个 Visitor Association 和成员创建独立链路。

回复权在 TCP 连接或 UDP Association 创建时固定。因此，Primary 变更作用于新流量
单元，不会在活跃连接或 Association 内混合不同回复源。

## 配置边界

镜像 Proxy 只适用于 Governed 和 Managed 认证模式，并且只支持 TCP、UDP 公共
端口。Shared 客户端、HTTP/HTTPS 域名代理以及 Forward 条目不能加入镜像组。

每个镜像组必须具备：

- 唯一的 `name`；
- 一个或多个已排序且不重叠的公共 `port_ranges`，展开后的具体端口不能与同协议
  其他镜像组重叠；
- 值为 `tcp` 或 `udp` 的 `type`；
- 同时存在于 `client_ids` 中的唯一 `primary_client_id`；
- 明确且数量受限的授权客户端 ID 列表。

Governed 成员必须已经获准注册组端口；每个 Managed 成员必须具有唯一匹配的
服务端托管 Proxy 条目。Portway 会在发布配置前拒绝不完整组、未列出的客户端、
端口冲突和模式不匹配。

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
            - start: 2240
              end: 2249
        primary_client_id: governed-primary
        client_ids:
          - governed-primary
          - governed-observer
    managed:
      - name: discovery
        type: udp
        public:
          port_ranges:
            - start: 5353
              end: 5353
        primary_client_id: managed-primary
        client_ids:
          - managed-primary
          - managed-observer
```

对应的客户端权限和 Managed Proxy 定义仍位于正常的认证记录中。完整服务端配置
上下文请参阅带注释的 [`config/zh/server.yaml`](../../../config/zh/server.yaml)。

## 热更新与运维

镜像组、成员和 Primary 选择均支持故障关闭式服务端配置热加载。非法候选不会
替换上一份有效状态。同端口更新会复用公共 Endpoint；被移除成员不再接收新流量，
新建 TCP 连接或 UDP Association 使用更新后的成员和 Primary 快照。

运维接口分别报告 TCP、UDP 镜像组和活跃成员数量。既有 Proxy 容量、Link、队列、
会话以及 UDP Association 限制继续生效，因此增加镜像成员会按在线接收者数量相应
增加数据链路和带宽消耗。
