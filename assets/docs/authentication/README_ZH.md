# 多模式认证与配置控制

Portway 可以在同一个服务端上同时管理自有设备、由不同人员操作的客户端以及
完全由服务端集中配置的节点。Shared 客户端配置 Token，并可使用自动生成的
ClientID；Governed 和 Managed 客户端同时配置服务端记录中的 ClientID 与
Token。Token 唯一选择认证记录和配置控制模式，ClientID 匹配后才能注册 Session。

## 如何选择模式

| 模式 | 适用场景 | 客户端控制代理配置 | 服务端控制范围 |
|---|---|---:|---|
| Shared Token | 服务端和全部客户端由同一可信操作者管理 | 是 | 全局运行限制 |
| Governed | 服务端和客户端由不同人员管理 | 是，但必须位于授权范围内 | 客户端身份、代理类型、公网端口/域名和配额 |
| Managed | 服务端必须定义客户端完整行为 | 否 | 客户端身份和完整代理配置 |

三种模式可以在同一个服务端同时启用。客户端不配置也不声明模式。在同一个服务端
的有效认证配置中，Token 必须在 Shared、Governed、Managed 三种模式之间唯一，
因此一个 Token 只能关联其中一条认证记录。这个约束不跨不同 Portway 服务端实例
执行。

服务端确认所选模式后，客户端会再次校验本地代理配置。Shared 和 Governed
客户端必须至少配置一个本地代理；Managed 客户端不得定义本地代理。服务端也会
独立拒绝 Shared 或 Governed 客户端提交的空代理集合。

## Shared Token

当一个可信操作者控制完整部署，或者少量地位相同的客户端可以安全共享凭据时，
使用 Shared Token。

服务端：

```yaml
authentication:
  shared_token: REPLACE_WITH_AT_LEAST_32_RANDOM_BYTES
```

客户端：

```yaml
authentication:
  token: REPLACE_WITH_AT_LEAST_32_RANDOM_BYTES

proxies:
  - name: ssh
    type: tcp
    local_ip: 127.0.0.1
    local_port: 22
    remote_port: 22022
```

Shared 客户端自行声明完整代理集合。客户端生成或配置的 ClientID 用于标识运行时
资源，但不是独立认证身份。所有持有共享 Token 的客户端具有相同认证权限。

如果客户端由不同人员管理、需要单独吊销或者需要不同权限，应选择其他模式。

## Governed 客户端

当客户端可以自行选择本地服务，但服务端操作者必须控制公网暴露范围和资源消耗
时，使用 Governed 模式。

服务端：

```yaml
authentication:
  governed_clients_path: ./governed
```

创建 `governed/customer-a.yaml`：

```yaml
client_id: customer-a
token: REPLACE_WITH_A_UNIQUE_RANDOM_TOKEN_AT_LEAST_32_BYTES

permissions:
  proxy_types: [tcp, http]

  tcp:
    remote_port_ranges:
      - start: 20000
        end: 20999

  http:
    public_schemes: [https]
    domains:
      - app.customer-a.example.com
      - "*.customer-a.example.com"

  limits:
    max_proxies: 20
    max_tcp_proxies: 10
    max_udp_proxies: 5
    max_http_proxies: 10
    max_active_links: 100
```

文件名只是面向操作者的标签，不要求与 `client_id` 一致。客户端配置匹配的
ClientID、该记录的 Token 和期望代理：

```yaml
client_id: customer-a

authentication:
  token: REPLACE_WITH_A_UNIQUE_RANDOM_TOKEN_AT_LEAST_32_BYTES

proxies:
  - name: app
    type: http
    public_schemes: [https]
    domain: app.customer-a.example.com
    local_ip: 127.0.0.1
    local_port: 8080
```

Token Proof 通过后，服务端必须在注册 Session 前确认客户端声明的 ClientID
与该 Token 绑定的身份完全一致。ClientID 为空或不匹配属于不可重试认证失败。
随后服务端按照代理类型、TCP/UDP 端口、HTTP 域名、代理数量和活动 Link 限制
校验完整代理集合。任意一项越权都会拒绝整批更新并关闭被拒绝的控制会话，
服务端不会静默发布部分代理。

`proxy_types` 中列出的每种类型都必须配置非空的对应规则：TCP 和 UDP 至少包含
一个 `remote_port_ranges` 区间，HTTP 至少包含一个域名；`public_schemes` 留空或
省略时默认只授权 HTTP。未列入 `proxy_types` 的类型必须省略对应规则或保持为空。配置多个区间可以
分配互不连续
的公网端口段，而不必授权这些区间之间原本不应开放的端口。

Governed 配额字段缺省时使用生产安全默认值：代理总数 20、TCP 代理 10、UDP
代理 5、HTTP 代理 10，以及 Pending 与 Active Link 合计 100。显式配置值必须
大于零。每客户端代理数量的程序硬上限为 128，Active Link 的程序硬上限为
512；各类型代理上限不得超过 `max_proxies`。

Governed 控制的是公网暴露范围。当前客户端代理声明不会发送 `local_ip` 和
`local_port`，因此服务端不能限制客户端实际访问的私网目标。

## Managed 客户端

对于必须由服务端提供完整代理配置的集中管理节点，使用 Managed 模式。

服务端：

```yaml
authentication:
  managed_clients_path: ./managed
```

创建 `managed/internal-node.yaml`：

```yaml
client_id: internal-node
token: REPLACE_WITH_A_UNIQUE_RANDOM_TOKEN_AT_LEAST_32_BYTES

configuration:
  revision: 1
  proxies:
    - name: ssh
      type: tcp
      local_ip: 127.0.0.1
      local_port: 22
      remote_port: 22022
```

Managed 客户端配置匹配的 ClientID 和 Token，不能在本地定义 `proxies`：

```yaml
client_id: internal-node

authentication:
  token: REPLACE_WITH_A_UNIQUE_RANDOM_TOKEN_AT_LEAST_32_BYTES
```

认证后，服务端通过 Prepare/Activate 交互下发完整配置。客户端完成校验和暂存后，
服务端才发布对应公网 Binding。Managed 客户端不能通过普通代理注册消息覆盖
服务端配置。

每次修改 Managed 代理配置都必须递增 `configuration.revision`。相同 revision
对应不同内容会被拒绝。

Managed 完整代理集合最多包含 128 个 TCP、UDP 和 HTTP 代理。超过硬上限会阻止
服务端启动；热加载时会拒绝整个候选配置、保留上一份有效快照，并记录不包含凭证
的明确校验错误。

所有 Managed 记录之间的 TCP 公网端口、UDP 公网端口和 HTTP 域名必须分别全局
唯一。TCP 与 UDP 使用不同网络协议，因此可以使用相同的数字端口。发生冲突时
Managed 资源即使在客户端离线时也为其配置的 ClientID 保留，Shared 或
Governed 客户端不能抢占。发生冲突时阻止启动，或者在发布前拒绝整个热加载
候选。

Managed 模式约束的是 Portway 协议和官方客户端行为。它不是远程证明；如果客户端
所有者修改二进制程序或操作环境，服务端无法据此保证客户端主机本身可信。

## 同时运行多种模式

三个入口可以组合：

```yaml
authentication:
  shared_token: REPLACE_WITH_AT_LEAST_32_RANDOM_BYTES
  governed_clients_path: ./governed
  managed_clients_path: ./managed
```

服务端启动和每次配置热加载都会验证：

- 每个独立 ClientID 唯一；
- Token 在当前服务端的 Shared、Governed、Managed 认证记录之间唯一；
- 同一个 ClientID 不能同时出现在 Governed 和 Managed 目录；
- 权限、配额、端口、域名和 Managed 代理集合全部合法。

客户端不配置模式。Token 选择唯一认证记录，Governed 和 Managed 还要求本地
ClientID 与记录完全匹配；身份校验完成后，服务端通过受保护通道返回关联模式
和已确认的 ClientID。

## 热加载、吊销和失败行为

服务端将主配置和认证目录作为一个完整候选进行热加载。候选格式错误、发生冲突、
超过限制或者内容不完整时会整批拒绝，上一份有效配置继续运行。

凭据和策略变化采用 fail-closed 行为：

- 新增、删除、替换或重新归属任意 Shared、Governed、Managed Token 时，会先发布新
  认证快照，再强制下线全部客户端，包括处于恢复窗口的 Session；
- 凭据未变化的客户端可继续使用原 Token 重连，凭据已变化的客户端必须使用新发布
  的 Token；
- 修改 Governed 权限会关闭该客户端的 Session、Binding、Pending Ticket 和
  Active Link；
- 修改 Managed 代理配置会执行在线 Prepare/Activate 切换；切换未完整完成时
  Session 保持不可用，并通过重连向最新期望配置收敛。

仅发生策略变化或 Managed 配置变化时，无关客户端保持在线。Transport 类型、
监听地址等不能安全热加载的字段会返回需要重启的错误，不会与其他字段一起部分应用。

## 运维建议

- 使用密码学安全随机源生成至少包含 32 字节熵的 Token。
- 不要在客户端、模式、服务端或其他系统之间复用 Token。
- 不要把 Token 提交到版本控制，也不要放入命令行或日志。
- 为 Governed 客户端配置满足业务需求的最小端口、域名和配额范围。
- 更新认证记录时使用原子文件替换。
- 将认证目录视为服务端敏感配置。
- 继续使用操作系统防火墙、云安全组和上游访问控制。

完整注释示例见
[`config/zh/server.yaml`](../../../config/zh/server.yaml)、
[`config/zh/governed/governed-client.yaml`](../../../config/zh/governed/governed-client.yaml)
和
[`config/zh/managed/managed-client.yaml`](../../../config/zh/managed/managed-client.yaml)。
