# VNet

VNet 使用稳定的私有 IPv4 地址连接 `portwayd` 服务端与显式配置的 Managed 客户端，
支持 Linux 和 macOS 上的 IPv4 TCP、UDP。客户端之间的数据包始终由服务端中继；VNet
状态与 Proxy、Forward 相互独立。

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

Linux 服务端管理命令如下：

```text
portwayd vnetwork status
portwayd vnetwork install [server.yaml]
portwayd vnetwork repair [server.yaml]
portwayd vnetwork uninstall
```

Linux 客户端只能在认证后获得网络参数，因此没有 install、repair 命令，只提供
`portway vnetwork uninstall`。卸载会拒绝外部资源、配置漂移或正被进程锁定的资源。
macOS 调用这些命令时会明确报告 VNet 由 `run` 自动管理。
