# 验收记录

日期：2026-10-22。

## 已覆盖测试

- 官方 MCP SDK 客户端通过 Streamable HTTP 初始化、列工具并调用。
- alice 可见两个工具，bob 仅可见 crm；返回正确系统与虚构用户。
- 绕过列表直接调用未授权工具仍被拒绝。
- 错误用户、错误 bearer token、伪造前缀与地址形式工具名被拒绝。
- 并发调用不能串用用户凭证。
- 下游 503 被脱敏且不重试。
- 非回环地址、重复或歧义路由被拒绝。
- 重定向不把凭证发送给目标。
- 非法工具字符与超长名称被拒绝；响应读取有 1 MiB 上限。
- 缺失下游凭证时不发请求，输入配置后续修改不改变已构建策略。

## 执行状态

在 Linux amd64 云端目录运行，使用官网下载的 Go 1.27.3。归档 SHA256 已与 `https://go.dev/dl/?mode=json` 官方元数据核对：

`65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40`

工具链、依赖缓存及构建缓存均位于忽略的 `.tools/`，没有修改系统 Go 或用户电脑。

- `gofmt`：通过，无未格式化 Go 文件。
- `go mod tidy`：通过，已生成 go.sum。
- `go test -count=1 ./...`：通过，gateway 包含 12 个测试函数，另有 alice/bob 子测试。
- `go test -race -count=1 ./...`：通过，无检测到的竞态。
- `go vet ./...`：通过。
- `go build -buildvcs=false -o bin/mcp-entry ./cmd/demo`：通过。
- `go mod verify`：通过，所有模块校验成功。
- 编译产物烟测：通过；真实启动 `/mcp`，使用 2025-06-18 initialize，验证 alice/bob 工具列表及调用返回的用户身份。
- SIGTERM 优雅关闭：通过，进程正常退出。

普通 `go build` 在当前非仓库工作区被外层 VCS 元数据阻挡（`error obtaining VCS status: exit status 128`）；本地验证因此显式关闭 VCS stamping。这不是代码编译错误。CI 在真实 checkout 中使用普通 build。

新增 `.github/workflows/ci.yml`，仅赋予 contents: read，执行格式、模块校验、普通测试、race、vet 和 build。CI 从 go.mod 选择 Go 版本（最低 1.25.0）；该版本的实际 CI 结果需发布后确认，不能把本次 Go 1.27.3 本地验证等同于 CI 已通过。

## 验证边界

这些结果仅证明当前模拟实现通过列出的检查，不代表生产安全认证或 MCP 全协议一致性认证。OAuth、安全网页绑定、持久化凭证库和管理界面均未完成。未连接真实系统、未验证真实业务副作用、未部署。
