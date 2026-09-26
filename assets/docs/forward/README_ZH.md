# Forward：访问服务端侧网络

Forward 在 `portway` 上创建本地 TCP 或 UDP Listener，并通过认证隧道把流量送到
`portwayd` 可达、且经过明确授权的 IP 和端口。目标服务保持私有，不需要公共
Listener，也不直接接受来自客户端网络的连接。

## 适用场景

Forward 适合：

- 通过本地回环端口访问私有数据库；
- 访问服务端网络中的管理或监控接口；
- 使用内部 DNS、目录或基础设施服务；
- 只授予一个协议和端口的窄范围访问，而不加入更广泛的私网。

如果访问者从服务端公共端口或域名进入，而服务位于客户端侧，应使用
[Proxy](../proxy/README_ZH.md)。如果 Managed 节点需要通过稳定私有地址互访，应使用
[VNet](../vnetwork/README_ZH.md)。

## 网络流程

```text
本地应用
   |
   v
portway 本地 TCP/UDP Listener
   |
   | 通过 TCP 或 QUIC Transport 建立认证 Data Link
   v
portwayd 策略校验
   |
   v
获准的服务端侧 IP:端口
```

1. 客户端声明完整 Forward 集合，或通过 Managed 记录接收配置。
2. 服务端按全局 Forward Allowlist 以及客户端更窄的权限检查每个目标。
3. 只有批准后，`portway` 才创建本地 Listener。
4. 每条连接或 UDP Association 使用一条认证 Data Link。
5. `portwayd` 再次按当前策略检查，然后连接目标或向其发送数据报。

TCP 保留全双工字节流和半关闭；UDP 保留数据报边界并隔离来源 Association。
Forward 可以使用 TCP 或 QUIC 作为客户端—服务端 Transport，而不改变这些应用语义。

客户端限制 TCP 连接总数为 512、每个 Forward 名称为 256，包含正在建立的连接。
正在建立的连接总数最多 128、每个名称最多 64；超出的连接立即关闭。
TCP 和 UDP 共同遵守最多 128 个待完成 Link Offer 请求的限制。

对于 UDP，服务端按全局、客户端和 Forward 名称限制 Association 数量、待建立数量
及创建速率。重载限额时保留已有计数和速率窗口。来源 IP 和队列字节限制由客户端
执行，因为原始本地来源地址仅在客户端可见。

## 配置

Forward 默认关闭。服务端必须显式启用并定义全局 Allowlist。下面只允许访问
`10.20.1.0/24` 中的 PostgreSQL：

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

客户端只在回环地址提供数据库入口：

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

应用连接 `127.0.0.1:15432`，`portwayd` 则连接 `10.20.1.15:5432`。UDP 使用相同
结构，把 `type` 改为 `udp`，并配置匹配的服务端 UDP 规则。

目标必须是规范 IP 地址，不能使用主机名，使策略判断不依赖可变的 DNS 解析结果。
目标必须完整匹配同一条规则；Portway 不会把一条规则的 CIDR 与另一条规则的端口
范围组合使用。

## 授权模式

- **Shared：** 客户端选择 Forward 声明，但所有目标必须位于服务端全局 Allowlist 内。
- **Governed：** 先应用全局 Allowlist，再由该客户端的服务端记录进一步收紧目标
  CIDR、协议、端口和限制。
- **Managed：** 服务端拥有完整 Forward 集合，客户端不能用本地声明替换。

关闭 Forward 时客户端保持在线，但本地 Forward Listener 会被移除；重新启用后，
仍获授权的声明自动恢复。服务端策略成功热更新后会关闭受影响的活跃 Link 和 Listener；
非法候选则保留上一份有效策略。

## 安全与运行注意事项

- 除非确实要允许其他主机使用本地入口，否则应将 `listen.ip` 绑定到 `127.0.0.1`；
  绑定 `0.0.0.0` 可能让客户端成为网络网关。
- 全局 Allowlist 应尽量收窄；只需一个服务端口时，不要授权整个私有网段的所有端口。
- 目标由 `portwayd` 主机访问，因此其路由、基于 IP 的可达性、主机防火墙和返回路径
  都必须允许连接。
- Forward 不是通用 SOCKS 或 HTTP 代理，不接受本地应用动态指定目标。
- 客户端 YAML 只在进程启动时读取。Shared 或 Governed Forward 声明变更需要重启
  客户端；服务端策略支持故障关闭式热更新。
- 本地 Listener 创建失败时，Shared 和 Governed 客户端会关闭本批入口、尽力报告
  失败并退出，不会以部分配置继续运行。
- Forward 本身不需要 TUN 设备或管理员权限。

权限记录见[多模式认证与配置控制](../authentication/README_ZH.md)，所有字段和限制见
带注释的[客户端](../../../config/zh/client.yaml)和[服务端](../../../config/zh/server.yaml)模板。
