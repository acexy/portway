# 三种连接模式：Proxy、Forward 与 VNet

Portway 提供三种面向不同网络边界的连接模式。Proxy 将 `portway` 可访问的服务
发布出去；Forward 让用户从本地访问 `portwayd` 所在网络中经过授权的服务；VNet
则将跨不同网络的服务端与显式配置的 Managed 节点组成一个受端口策略约束、可彼此访问的
私有 IPv4 网络集群。

## 模式与流量方向

### Proxy：发布客户端侧服务

```text
公网访问者
    |
    v
portwayd 公共 Listener
    |
    | 认证隧道
    v
portway 客户端
    |
    v
客户端侧本地服务
```

Listener 由 `portwayd` 持有。TCP/UDP Proxy 使用服务端公共端口，HTTP/HTTPS
Proxy 使用域名。普通 Proxy 将入口映射到一个客户端服务；受 Governed 或 Managed
管理的 TCP/UDP [镜像 Proxy](../proxy-mirroring/README_ZH.md) 会把相同访问者输入复制
给多个已配置客户端，同时只允许一个 Primary 回复。客户端通过嵌套的 `local` 节点
声明本地目标。

```yaml
proxies:
  - name: ssh
    type: tcp
    local:
      ip: 127.0.0.1
      port: 22
    public:
      port: 22022
```

当客户端网络中的应用需要通过 Portway 服务端对外提供访问时，应使用 Proxy。

### Forward：从本地访问服务端侧服务

```text
本地访问者
    |
    v
portway 客户端 Listener
    |
    | 认证隧道
    v
portwayd
    |
    v
经过授权的服务端侧目标
```

Listener 由 `portway` 持有。Forward 支持 TCP 和 UDP，并分别保留字节流和数据报
语义。`listen` 定义客户端入口；`target`
定义服务端所在网络中可达的目标。

```yaml
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

Forward 适合访问管理接口、数据库、DNS 等需要保留在服务端私有网络中，但又要
通过客户端本地端口安全使用的服务。

## Forward 安全边界

`server.yaml` 未配置 `forwards`，或配置 `enabled: false` 时，Forward 均为关闭
状态。关闭时客户端声明保持休眠，客户端进程和 Proxy 正常运行且不创建 Forward
监听；重新开启后自动恢复仍获授权的监听。显式配置该节点时必须提供 IP/CIDR 与
TCP/UDP 端口规则；启用后，这些规则
构成服务端全局 Allowlist：

```yaml
forwards:
  enabled: true
  rules:
    - ip_range: 10.20.0.0/16
      tcp:
        port_ranges:
          - start: 5432
            end: 5432
```

Shared、Governed、Managed 客户端都不能绕过全局边界。Governed 和 Managed
记录可以继续收紧权限。目标必须使用明确 IP 而非主机名，每条新 Link 都会按当前
策略重新授权。

服务端全部 Forward 配置和权限均支持故障关闭式热加载：非法候选保留上一代快照；
策略成功变更后自动断开受影响连接。客户端不会热加载本地 YAML，因此 Shared 或
Governed 模式的 Listener 变化需要重启客户端。

Shared 或 Governed 客户端可以同时配置 Proxy 与 Forward。两者都可使用 TCP 或 QUIC 作为
底层传输，并在隧道中保持应用协议语义。

Forward 本地入口在服务端批准后创建，客户端控制会话结束时关闭，恢复后重新创建。
本地启动失败时，Shared/Governed 客户端关闭本批入口、尽力通知服务端并退出。
普通 TCP Proxy 和 Forward 正常半关闭不设固定响应排空期限；异常 I/O 或会话取消
关闭两个方向。镜像 TCP 仍使用独立的排空策略。

### VNet：通过稳定私有地址连接受管节点

```text
服务端或 VNet 客户端
          |
          | 私有 IPv4 TCP / UDP
          v
 portwayd 中继或 QUIC P2P
          |
          v
另一个已授权的 VNet 节点
```

VNet 没有“公共入口”或客户端本地转发 Listener。服务端为自身和每个 Managed 客户端
分配稳定私有 IPv4 地址，并根据目标节点的 TCP/UDP 端口允许列表决定是否递送流量；
客户端间流量先经 `portwayd` 中继，自动探测成功后仅将新 Flow 升级为 QUIC P2P；
涉及服务端的流量始终保持中继。它使不同网络中的固定节点获得类似 VPN 的私网互访
体验，适合管理、服务发现和内部服务访问；当前不承载任意 IP 协议、广播或通用互联网出口。

VNet 只在服务端 `virtual_network` 节点配置，且只允许 Managed 客户端加入。它需要
Linux 或 macOS 的 TUN 网络资源；`network_mode: tun` 将流量交给虚拟 IP 上的服务，
`loopback` 将已授权流量送往同端口的 `127.0.0.1` 服务。配置、运维命令和安全边界见
[VNet 配置与运维](../vnetwork/README_ZH.md)。

## 如何选择

| 需求 | 模式 | 入口或地址所有者 | 目标位置 |
| --- | --- | --- | --- |
| 将客户端私有服务提供给访问者 | Proxy | `portwayd` 公共 Listener | 客户端网络 |
| 在客户端本地使用服务端侧服务 | Forward | `portway` 本地 Listener | 服务端网络 |
| 让集中管理的节点彼此私网访问 | VNet | 服务端下发的私有 IPv4 地址 | 服务端或 Managed 客户端 |
