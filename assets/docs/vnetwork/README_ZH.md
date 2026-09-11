# VNet

VNet 使用稳定的私有 IPv4 地址连接 `portwayd` 服务端与显式配置的 Governed 客户端，
支持 Linux 和 macOS 上的 IPv4 TCP、UDP。客户端之间的数据包始终由服务端中继；VNet
状态与 Proxy、Forward 相互独立。

VNet 只在服务端配置。每个节点的 `ports` 是其他节点访问该节点时的 TCP/UDP 入站
允许列表：

```yaml
virtual_network:
  enabled: true
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
    - client_id: governed-a
      ip: 172.20.0.2
      ports:
        tcp:
          port_ranges:
            - start: 8080
              end: 8080
        udp:
          port_ranges: []
```

这里引用的 ClientID 必须存在于 `governed_clients_path`。TCP 和 QUIC Transport 均使用
`packet_channels`，默认值为 4，允许范围是 1 到 8。

首次激活需要权限时，Portway 调用操作系统的 `sudo` 机制，不读取或保存密码。Linux
使用持久化 TUN `portway0`；macOS 使用进程持有的 `utunN`，对外统一表示为逻辑网络
`portway0`。进程正常退出只停止数据面，不主动卸载系统配置或删除所有权记录。

服务端管理命令如下：

```text
portwayd vnetwork status
portwayd vnetwork install [server.yaml]
portwayd vnetwork repair [server.yaml]
portwayd vnetwork uninstall
```

客户端只能在认证后获得网络参数，因此没有 install、repair 命令，只提供
`portway vnetwork uninstall`。卸载会拒绝外部资源、配置漂移或正被进程锁定的资源。
