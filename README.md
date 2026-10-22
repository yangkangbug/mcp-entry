# mcp-entry

A nonproduction Go MCP gateway foundation: one entry point, explicit per-user tool authorization, and isolated synthetic downstream credentials. Local demo only. No OAuth or real account binding yet.

## 当前范围

模块化单体原型，使用官方 Go MCP SDK v1.7.0 的 Streamable HTTP 服务端和客户端，不自行实现 MCP 协议。提供两个模拟系统（crm、docs）、两个虚构用户（alice、bob）。公开示例中的 token 全为虚构值，不能用于生产。

- 单一入口：`http://127.0.0.1:8080/mcp`
- 稳定名称：`crm__echo`、`docs__echo`，由本地配置决定，不接受下游动态覆盖。
- alice 能看到并调用两个工具；bob 只能看到并调用 crm 工具。
- 列表过滤不作为唯一安全边界；每次调用再次检查用户及工具授权。
- 下游凭证按「用户 × 系统」选择；每次调用使用独立 MCP 客户端，不共享用户会话。
- 无自动工具重试；断连可能导致调用结果未知，不能直接再次执行有副作用的操作。
- 只监听回环地址，拒绝带 Origin 的浏览器请求，下游地址只允许字面回环 IP；拒绝重定向。

## 本地运行

需要 Go 1.25 或更新版本。SDK 版本固定在 go.mod。无需真实账号或环境密钥。

```sh
go mod download
go run ./cmd/demo
```

兼容 Streamable HTTP 的 MCP 客户端连接 `/mcp`，请求头使用 `Authorization: Bearer demo-alice` 或 `Authorization: Bearer demo-bob`。两个模拟下游自动分配回环端口。Ctrl+C 关闭服务。

```sh
go test ./...
go test -race ./...
go vet ./...
go build -o bin/mcp-entry ./cmd/demo
```

## 架构

`cmd/demo` 负责启动和关闭；`internal/gateway` 负责静态身份、策略、名称路由与下游调用；`internal/mock` 提供真实 MCP 传输上的模拟系统。详情见 [架构与威胁模型](docs/architecture.md) 和 [验收记录](docs/acceptance.md)。

## 尚未完成，不可投入生产

OAuth/OIDC、授权码与 PKCE 流程、安全的网页登录和账号绑定、真实下游集成、持久化加密凭证库、管理界面、租户隔离、审计日志、动态策略撤销、限流、生产 TLS 和密钥轮换均未实现。当前 bearer token 只是固定演示身份，并不是可信认证方案。

只支持这两个静态工具；不代理 resources、prompts、sampling、任务扩展或任意远程 MCP 地址。工具返回值应视为不可信内容，网关不提供提示注入净化保证。

## 协议与依赖依据

2026-10-22 核对官方 [Go SDK](https://github.com/modelcontextprotocol/go-sdk) 和 [v1.7.0 go.mod](https://github.com/modelcontextprotocol/go-sdk/blob/v1.7.0/go.mod)。v1.7.0 支持 MCP 2026-07-28，并兼容 2025-11-25、2025-06-18、2025-03-26 和 2024-11-05；SDK 的客户端 OAuth 支持仍有实验性部分。本项目未启用 OAuth，也未声称完整实现所有协议功能。

项目许可证尚未选定，暂不添加 LICENSE。第三方依赖遵循各自许可证。
