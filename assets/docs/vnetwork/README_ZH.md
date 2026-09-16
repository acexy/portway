# VNet

VNet 使用稳定的私有 IPv4 地址连接跨不同网络的 `portwayd` 服务端与显式配置的 Managed
客户端，支持 Linux、macOS 和 Windows amd64 上的 IPv4 TCP、UDP。它让固定节点获得类似 VPN 的私网集群
与互访体验：应用直接使用目标节点的私有地址和端口。客户端间流量先经服务端中继，探测成功后
自动让新 Flow 使用 QUIC Datagram 直连；涉及服务端的流量始终保持中继。
VNet 状态与 Proxy、Forward 相互独立。

这里的“互访”受目标节点的端口策略约束，而非无边界网络访问：每个节点只接收其 `ports`
明确允许的 TCP/UDP 端口流量。VNet 当前不提供任意 IP 协议、广播或互联网出口。

## 自动 QUIC P2P

启用 VNet 后自动使用 P2P，不提供独立配置开关。两个客户端之间的首个 Flow 在
`portwayd` 协调有界连通性探测期间继续使用 Relay。系统优先尝试 LAN Host Candidate，
再尝试 Internet ServerReflexive Candidate。双方完成 QUIC 路径认证后，只有新 Flow
改用 QUIC Datagram 直连，已经使用 Relay 的 Flow 不迁移。探测或直连失败只会保持或
回退 Relay，不会关闭 VNet、Proxy 或 Forward。涉及服务端的流量永远不尝试 P2P。

无论客户端与服务端之间配置 TCP 还是 QUIC Transport，P2P 始终使用独立 QUIC Datagram
Connection。Peer 流量仍受目标节点 TCP/UDP Allowlist 和认证虚拟地址约束。服务端负责
协调身份、策略、激活和撤销；Direct Flow 激活后，业务包不再经过服务端。

`portwayd` 和每个参与的 `portway` 都会独占绑定 UDP 端口 `P+1`，其中 `P` 是已配置的
Transport 端口。防火墙需要同时允许 Transport 端口和 `P+1/UDP`。本地端口绑定冲突会
终止进程；NAT、CGNAT 或防火墙穿透失败只会保持 Relay。

```text
Relay
  └─ Probing
       ├─ LAN QUIC Direct
       ├─ Internet QUIC Direct
       └─ Relay fallback
```

## 配置

VNet 只在服务端配置。每个节点的 `ports` 是其他节点访问该节点时的 TCP/UDP 入站
允许列表：

```yaml
virtual_network:
  enabled: true
  network_mode: tun
  cidr: 172.20.0.0/16
  server_ip: 172.20.0.1
  packet_channels: 4
  server_ports:
    tcp:
      port_ranges:
        - start: 22
          end: 22
    udp:
      port_ranges: []
  nodes:
    - client_id: managed-a
      ip: 172.20.0.2
      ports:
        tcp:
          port_ranges:
            - start: 8080
              end: 8080
        udp:
          port_ranges: []
```

这里引用的 ClientID 必须存在于 `managed_clients_path`。TCP 和 QUIC Transport 均使用
`packet_channels`，默认值为 4，允许范围是 1 到 8。

`network_mode` 默认为 `tun`，应用必须监听本机虚拟 IP 或能够覆盖它的通配地址。
设为 `loopback` 后，Portway 用户态栈终止已授权的入站 TCP/UDP，并连接相同端口的
`127.0.0.1`。此设置只由服务端控制，客户端跟随 Assignment，
修改后必须重启服务端。

首次激活需要权限时，Portway 调用操作系统的 `sudo` 机制，不读取或保存密码。Linux
使用持久化 TUN `portway0` 并支持下列管理命令。macOS 的 `run` 自动启动同一二进制的
短生命周期提权模式，接收其创建的 `utunN` FD 后继续以普通权限运行。macOS 不支持
手工 `vnetwork` 命令；持有进程关闭 FD 后，接口和路由由系统自动清理。

Windows amd64 发布包内置官方签名的 `wintun.dll`，无需单独安装。启用 VNet 的
`portway` 或 `portwayd` 必须以管理员身份启动。Portway 仅在实际激活 VNet 时加载
Wintun 并创建临时 `portway0` Adapter，持有进程关闭后移除 Adapter。Windows 不支持
手工 `vnetwork` 命令。Windows arm64 及其他 Windows 架构不受支持。

Linux 服务端管理命令如下：

```text
portwayd vnetwork status
portwayd vnetwork install [server.yaml]
portwayd vnetwork repair [server.yaml]
portwayd vnetwork uninstall
```

Linux 客户端只能在认证后获得网络参数，因此没有 install、repair 命令，只提供
`portway vnetwork uninstall`。卸载会拒绝外部资源、配置漂移或正被进程锁定的资源。
macOS 调用这些命令时会明确报告 VNet 由 `run` 自动管理。Windows 也会报告由 `run`
自动管理，并要求 `run` 进程本身已提升权限。
