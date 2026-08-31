# Proxy 与 Forward 工作模式

Portway 在同一条认证客户端-服务端隧道上提供两种互补的流量模式。Proxy 将
`portway` 可访问的服务发布出去；Forward 则让用户从本地访问 `portwayd`
所在网络中经过授权的服务。

## 流量方向

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
Proxy 使用域名；客户端通过嵌套的 `local` 节点声明本地目标。

```yaml
proxies:
  - name: ssh
    type: tcp
    local: {ip: 127.0.0.1, port: 22}
    public: {port: 22022}
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
    listen: {ip: 127.0.0.1, port: 15432}
    target: {ip: 10.20.1.15, port: 5432}
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

## 如何选择

| 需求 | 模式 | Listener 所有者 | 目标位置 |
| --- | --- | --- | --- |
| 发布客户端私有服务 | Proxy | `portwayd` | 客户端网络 |
| 从本地访问受保护的服务端侧服务 | Forward | `portway` | 服务端网络 |

Shared 或 Governed 客户端可以同时配置两种模式。两者都可使用 TCP 或 QUIC 作为
底层传输，并在隧道中保持应用协议语义。
