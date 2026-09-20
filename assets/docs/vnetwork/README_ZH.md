# VNet

VNet 使用稳定的私有 IPv4 地址连接跨不同网络的 `portwayd` 服务端与显式配置的 Managed
客户端，支持 Linux、macOS 和 Windows amd64 上的 IPv4 TCP、UDP。它让固定节点获得类似 VPN 的私网集群
与互访体验：应用直接使用目标节点的私有地址和端口。客户端间流量先经服务端中继，探测成功后
自动让新 Flow 使用 QUIC Datagram 直连；涉及服务端的流量始终保持中继。
VNet 状态与 Proxy、Forward 相互独立。

这里的“互访”受目标节点的端口策略约束，而非无边界网络访问：每个节点只接收其 `ports`
明确允许的 TCP/UDP 端口流量。VNet 当前不提供任意 IP 协议、广播或互联网出口。

## 适用场景

VNet 适合由单一运维方管理的一组固定服务器、工作站和边缘节点，让它们通过稳定私有
地址通信。典型场景包括跨网络管理、服务发现、内部服务间访问，以及网络条件允许时的
客户端直连。

VNet 不是面向任意用户或互联网出口的通用远程访问 VPN。只有显式配置的 Managed
客户端可以加入，并且每个目标仍执行自身 TCP/UDP 入站端口策略。需要稳定公共服务
入口时使用 [Proxy](../proxy/README_ZH.md)；需要窄范围地从本地访问服务端侧目标时使用
[Forward](../forward/README_ZH.md)。

## 网络架构与数据流程

```text
节点 A 上的应用
      |
      v
portway0 / utunN / Wintun，或 loopback 用户态网络栈
      |
      v
源地址校验 + 目标端口策略
      |
      +---- Relay Packet Channel ----> portwayd ----+
      |                                             |
      +---- 已认证 QUIC Datagram P2P ---------------+
                                                    v
                                          节点 B 的 VNet Endpoint
                                                    |
                                                    v
                                               本地应用
```

服务端向每个 Managed 客户端下发地址、MTU、Packet Channel 数量和策略。`tun` 模式下，
完整 IPv4 TCP/UDP 包从平台设备进入；`loopback` 模式下，Portway 在用户态 TCP/IP 栈中
终止获授权流量。服务端在 Relay 路由前校验源地址所有权与目标策略。客户端对并行探测，
只有双方认证 Direct Path 后，新 Flow 才选择 P2P；回退时绝不重放交付状态不确定的数据包。

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

### Transport 建议

VNet 可以使用 TCP 或 QUIC 作为认证的客户端—服务端 Transport。UDP 可用时建议使用
QUIC：其独立 Stream 更适合 VNet 的并行 Packet Channel，并可避免丢包时 TCP 连接级
队头阻塞；QUIC 还提供 TLS 1.3 服务端身份校验。UDP Transport 不可用或持续被阻断时
再使用 TCP。

Transport 选择不控制客户端间 P2P：VNet 直连流量始终使用独立 QUIC Datagram
Connection。因此，即使主 Transport 使用 TCP，P2P 仍需要 `P+1/UDP`。

```yaml
# server.yaml
transport:
  type: quic
  listen_address: 0.0.0.0:7000
  quic:
    cert_file: ./certs/server.crt
    key_file: ./certs/server.key
```

```yaml
# client.yaml
transport:
  type: quic
  server_address: SERVER_IP:7000
  quic:
    server_name: gateway.example.com
    ca_file: ./certs/root-ca.crt
```

`server_name` 必须匹配服务端证书中的 DNS 或 IP SAN。私有 CA 部署可以运行
`portwayd gen cert`，并应妥善保护两份私钥。

### VNet 策略

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

## 平台权限与生命周期

首次激活需要权限时，Portway 调用操作系统的 `sudo` 机制，不读取或保存密码。Linux
使用持久化 TUN `portway0` 并支持下列管理命令。macOS 的 `run` 自动启动同一二进制的
短生命周期提权模式，接收其创建的 `utunN` FD 后继续以普通权限运行。macOS 不支持
手工 `vnetwork` 命令；持有进程关闭 FD 后，接口和路由由系统自动清理。

Windows amd64 发布包内置官方签名的 `wintun.dll`，无需单独安装。可能需要 Windows
VNet 权限的命令会通过 UAC 申请管理员授权；用户确认后，命令在重新启动的提升权限进程中
继续执行。客户端只能在认证后得知是否启用 VNet，因此 `portway run` 在启动前申请授权；
`portwayd run` 仅在 `virtual_network.enabled` 为 true 时申请。Portway 仅在实际激活
VNet 时加载 Wintun 并创建临时 `portway0` Adapter，持有进程关闭后移除 Adapter。
Windows 不支持 install 或 repair，但提供只读的 `vnetwork status` 和 `vnetwork uninstall`，
用于检查或安全移除正常进程生命周期之外残留的自有 Adapter。Windows arm64 及其他
Windows 架构不受支持。

Linux 服务端管理命令如下：

```text
portwayd vnetwork status
portwayd vnetwork install [server.yaml]
portwayd vnetwork repair [server.yaml]
portwayd vnetwork uninstall
```

每个命令都会向原调用终端报告结果：`status` 输出网络字段，`install` 和 `repair` 成功时
分别输出 `Installed` 和 `Repaired`，`uninstall` 输出稳定的删除结果。Windows UAC 操作会
把结果回传到原终端，输出重定向时行为保持不变。

Linux 客户端只能在认证后获得网络参数，因此没有 install、repair 命令，只提供
`portway vnetwork uninstall`。卸载按名称删除唯一的 `portway0` 网络，但会拒绝删除正被
Portway 进程锁定的网络。Windows amd64 的客户端和服务端都提供 `vnetwork status` 和
`vnetwork uninstall`；status 只读且不申请 UAC，uninstall 在需要时申请 UAC 授权，并拒绝
删除仍被 Portway 进程持有的网络。
Windows 运行期地址变更会原地迁移现有 Adapter；启动前会替换残留的同名 Adapter。macOS
的 VNet 由 `run` 自动管理，因此命令帮助中不显示 `vnetwork`。

## 安全与运行注意事项

- 在主机、云和上游防火墙中放行 Transport 端口及 `P+1/UDP`。穿透失败时 Relay
  保持可用；本地 P2P 端口无法绑定则 VNet 启动失败。
- Linux 和 macOS 的 `tun` 模式需要特权网络配置。macOS 使用短生命周期 `sudo`
  Helper；没有有效 sudo 授权缓存时可能要求交互输入密码，脱离终端的进程无法在启动后
  再发起密码询问。
- Windows amd64 上为启用 VNet 的进程申请 UAC；其他 Windows 架构不受支持。
- CIDR 不应与局域网、云路由、容器网络或其他 VPN 重叠。Portway 会拒绝检测到的冲突，
  而不会替换外部路由。
- `tun` 模式下，应用应绑定虚拟地址或适当的通配地址。只有确实需要将同端口流量送到
  `127.0.0.1` 时才使用 `loopback`。
- 入站端口范围应尽量收窄。VNet 是主机防火墙和应用凭据的补充，而不是替代品。
- UDP 网络质量允许时优先使用 QUIC Transport，同时注意 P2P 与主 Transport 使用不同
  Socket 和证书边界。

完整部署指导见带注释的[服务端配置](../../../config/zh/server.yaml)、
[Managed 客户端记录](../../../config/zh/managed/managed-client.yaml)和
[安全性](../security/README_ZH.md)。

## 可靠性与容量

VNet 提供单服务端部署内的 Channel 和直连路径恢复，不提供服务端状态复制或无缝
故障接管。服务端重启后，应用需要允许重新连接。TCP Flow 授权在连续五分钟无包活动
后到期；空闲长连接应使用短于该期限的应用心跳或 TCP keepalive。未知 TCP ACK 不能
重建已过期授权。Loopback TCP 到期会关闭两端代理连接并释放名额。UDP Flow 授权在
双向空闲一分钟后到期。

每个节点对双向共用 1024 条 Flow 上限，新 Flow 每秒补充 128 个令牌、允许 256 次
突发；已有 Flow 和回复不消耗新建速率令牌。这些限制叠加现有节点及全局预算；容量
或速率拒绝只丢弃新流量，不重建 Packet Channel。它们是资源保护，不是吞吐保证。

Peer 协调使用各控制 Session 独立的有界队列。如果安全通知从入队起五秒内无法
送达，或队列满，受影响的控制连接会关闭，以撤销旧直连授权。其他 Session 继续
运行，该节点的应用可能需要重连。失败 Peer Pair 在退避结束后释放配额。周期性的
`vnet_statistics` 日志报告 Flow 占用、容量及速率拒绝、Peer 状态和 loopback 连接
占用、直连故障回退、客户端 Pool 故障、写超时及最近一次 Pool 重建耗时，不包含业务
包内容或凭证。

普通控制会话重连会保留 P2P UDP Socket 及其 QUIC Transport，继续占用原本地端口。
旧直连连接会关闭，随后使用新的会话凭证、Peer 状态和注册信息重新探测。虚拟 IP 或
MTU 变化同样复用 Socket。关闭 VNet、删除节点、撤销 P2P 能力或退出客户端时才释放
该绑定；绑定端口改变或 Socket 本身故障时需要重新绑定。保留 Socket 不代表保留旧
控制会话的访问授权。

普通控制 Session 重连也会在 Linux、macOS 和 Windows 上保留未变化且由进程持有的
VNet Device 与系统网络。客户端关闭旧 Packet Channel 和 Session 权限，收到新
Assignment 后把新 Channel 绑定到现有 Device。只有关闭 VNet、删除节点、不兼容的网络
参数变化、Device 故障或客户端进程退出时才重建设备。因此 macOS 不会仅因普通重连而
为重建同一临时网络再次请求管理员授权。
