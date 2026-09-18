# 选择连接模式

Portway 提供三种彼此独立的连接模式。应根据入口和目标所在位置进行选择；同一部署
可以同时使用多个模式。

| 需求 | 模式 | 入口 | 目标 |
| --- | --- | --- | --- |
| 发布一个私有服务 | [Proxy](../proxy/README_ZH.md) | `portwayd` 公共端口或域名 | `portway` 可访问的服务 |
| 将公共 TCP/UDP 输入复制给受控消费者 | [镜像 Proxy](../proxy/README_ZH.md#镜像-proxy) | `portwayd` 公共端口 | 多个客户端服务；一个 Primary 回复 |
| 通过本地端口使用远端私有服务 | [Forward](../forward/README_ZH.md) | `portway` 本地 Listener | `portwayd` 可访问且获准的服务 |
| 通过稳定私有 IPv4 地址连接受管节点 | [VNet](../vnetwork/README_ZH.md) | 每个节点的虚拟地址 | 服务端或 Managed 客户端 |

以下专题文档分别说明使用场景、网络流程、配置、安全边界和运行注意事项：

- [Proxy：发布客户端侧服务](../proxy/README_ZH.md)
- [Forward：访问服务端侧网络](../forward/README_ZH.md)
- [VNet：连接受管节点](../vnetwork/README_ZH.md)
