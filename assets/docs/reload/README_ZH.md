# 服务端配置热加载

Portway 可以在不重启 `portwayd` 的情况下更新认证、授权和服务端托管的客户端
配置。热加载采用 fail-closed 和配置代际机制：完整候选通过全部校验后，运行时
状态才会发生变化。

## 监听范围

使用显式配置文件启动 `portwayd` 后，服务端每 3 秒扫描：

- 当前服务端 YAML 文件；
- `authentication.governed_clients_path`；
- `authentication.managed_clients_path`；
- 上述目录第一层的普通 `*.yaml` 文件。

认证目录不递归扫描，拒绝符号链接。相对目录以服务端配置文件所在目录为基准，
不依赖任意的进程工作目录。

## 完整候选与原子发布

每次扫描将主配置和全部 Governed/Managed 记录构建成一个候选：

```text
读取全部来源
→ 严格解析 YAML
→ 应用默认值和硬上限
→ 校验跨文件身份及资源规则
→ 与当前有效代际比较
→ 原子发布
```

候选只能全部成功或全部失败。如果同时新增两个客户端文件，其中一份正确、另一份
错误，两份都不会发布。服务端继续使用上一代配置，现有 Session、Listener、
Binding 和代理行为均保持不变。

如果服务端因为 `shared_token` 为空，或未配置独立认证目录且省略该字段，而在启动时
自动生成了 Shared Token，后续扫描会复用同一个有效 Token，不会静默生成新凭据。

该规则避免只发布部分凭证、Token/ClientID 所有权不明确，以及 Managed
端口和域名预留落在不同代际。

## 支持热加载的配置

当前实现支持：

- `log_level`；
- 显式配置的 Shared Token；
- Governed/Managed 目录路径及内容；
- Governed 权限和配额；
- Managed 客户端完整配置。
- `forwards.enabled`、全局 Forward 规则和客户端 Forward 权限。

认证变化会立即影响运行时：

- 新增、删除、替换或重新归属任意 Shared、Governed、Managed Token 时，全部客户端
  都会被强制下线，包括处于恢复窗口的 Session；
- 凭据未变化的客户端可使用原 Token 重连，凭据已变化的客户端必须使用新发布的
  Token；
- 修改 Governed 权限会关闭该客户端的 Session 和资源，使其按新策略重连；
- 仅修改 Managed 配置仍使用在线切换，不会下线无关客户端。

关闭 `forwards.enabled` 时，客户端声明和权限作为休眠状态保留。在线及关闭期间
启动的客户端均保持连接，只关闭 Forward 监听和连接，并记录 `forward_disabled`；
重新开启后在同一 Session 内按最新规则自动恢复仍获授权的监听。

## 必须重启的配置

以下字段会被校验，但不能在线应用：

- `transport.type`、`transport.listen_address`；
- QUIC 证书和私钥；
- `proxies.bind_ip`、`proxies.http.listen_address`、
  `proxies.https.listen_address`；
- HTTP、UDP、安全限制及其他运行时组件参数。

其中任意字段发生变化时，整个候选以 `restart_required` 拒绝。同一候选里的
其他可热加载字段也不会被部分应用。

公网 HTTPS 证书内容、路径和 `proxies.https.certificates` 条目属于例外：完整有效的 SNI
证书集合会原子发布而不替换 HTTPS Listener；无效候选继续使用上一代集合。

## Managed 在线切换

Managed 记录变化后成为新的期望状态。客户端在线时执行：

```text
managed_config_prepare
→ managed_config_prepared
→ managed_config_activate
→ managed_config_applied
```

客户端先校验并暂存完整配置，服务端在 Prepare 与 Activate 之间同步公网
Binding。切换失败或未完成时不会把新配置标记为有效；对应 Session 会被关闭或
保持不可用，并通过重连向最新期望 revision 收敛，其他客户端不受阻塞。

每次修改 Managed 配置内容都必须递增 `configuration.revision`；相同 revision
对应不同内容会被拒绝。

## 校验失败与日志

常见失败原因包括：

- YAML 格式错误、未知字段或缺少必填字段；
- Token 太短或全局重复；
- ClientID 非法或重复；
- Governed 规则或配额非法；
- Managed 本地目标、域名、端口或代理数量非法；
- Managed TCP 端口、UDP 端口或 HTTP 域名跨文件重复；
- 新增 Managed 预留资源与活动 Binding 冲突；
- 修改了必须重启的字段。

失败日志包含可操作原因、稳定 `error_code` 和当前 generation，不记录 Token
或原始认证内容。相同错误只记录一次，不会每次扫描重复刷屏；后续候选成功时
会记录恢复和应用事件。

## 安全更新方式

建议使用原子文件替换：

1. 在相同文件系统创建临时文件；
2. 写入并关闭完整 YAML；
3. 设置所有者和权限；
4. 使用 rename 覆盖目标文件。

不要缓慢地直接编辑多个线上文件。Watcher 可能看到中间组合并产生临时校验
失败。原子候选会保护当前有效配置，原子文件替换则能让发布意图和日志更清晰。

中文完整示例见
[`config/zh/server.yaml`](../../../config/zh/server.yaml)、
[`config/zh/governed/governed-client.yaml`](../../../config/zh/governed/governed-client.yaml)
和
[`config/zh/managed/managed-client.yaml`](../../../config/zh/managed/managed-client.yaml)。
