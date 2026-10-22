# 验收记录

日期：2026-10-22。验证只使用虚构用户、模拟凭证及回环 MCP 服务。

## 上一阶段已发布证据

初始静态工具骨架已发布到提交 `146bd924d0d01bee8c7f309df6042c33adb0c8a0`，其 [GitHub Actions](https://github.com/yangkangbug/mcp-entry/actions/runs/39729216020) 已成功。这条 CI 结果仅对应该提交，不代表本阶段新增代码已经通过远端 CI。

## 本阶段：配置驱动与真实工具发现

本阶段目前为本地验证，远端 CI 待新提交发布后核对。

保留第一阶段 12 个测试目的，并迁移到实际发现路径；新增配置和动态目录测试，目前共 24 个顶层测试函数，另含名称/schema/分页边界等子测试。

覆盖：
- alice/bob 初始化、分别列出授权工具、调用并返回正确模拟身份。
- 输入数字、数组、对象及无参数工具；输出对象和数组；输入/输出 schema、描述、标题和注解保留。
- 同一系统针对不同用户公布不同工具及 schema；发现和调用都使用对应用户的凭证。
- 绕过列表直接调用隐藏、其他用户、未知或尚未发现的工具被拒绝。
- 未授权参数、错误身份、伪造前缀、非法名称和通配策略被拒绝。
- 并发调用不串凭证；返回的名称切片或调用方配置修改不会改写内部目录/策略。
- 一系统失败只移除对应系统；其他系统可调用；恢复并刷新后可重新发现。
- 失败初始化不调用 tools/call；真实 tools/call 503 只调用一次且错误脱敏。
- 重复工具名、分页循环、跨页重复、非法输入/输出 schema、null 工具条目被整体拒绝。
- 拒绝 schema 位置的 x-mcp-header 映射，包括 SDK 原本会静默过滤的坏 header 名；预检发生在 SDK 过滤之前。
- 20 个输入/输出引用子用例验证根/嵌套/组合/数组及 draft-07 dependencies 的 $ref/$dynamicRef 均在调用前被拒绝。
- 普通属性名和 example/default 数据中名为 x-mcp-header、$ref、$dynamicRef 或 type 的键保持可用，不误判为 schema 指令。
- 16 页/128 工具边界可接受，17 页/129 工具被拒绝，包含跨页累计数量。
- 缺失凭证、远程地址、重定向、超大响应和非法配置失败关闭。
- 不发布 resources、prompts 或 completions 能力。

## 本地执行结果

环境：Linux amd64，Go 1.27.3，官方下载归档 SHA256 已与 `https://go.dev/dl/?mode=json` 核对：

`65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40`

工具链、依赖与构建缓存均在忽略的 `.tools/` 中，没有修改系统 Go 或用户电脑。

- gofmt：通过。
- go mod tidy：通过；jsonschema-go 现为直接依赖，SDK 仍固定 v1.7.0。
- go test -count=1 ./...：通过。
- go test -race -count=1 ./...：通过，无检测到的竞态。
- go vet ./...：通过。
- go build -buildvcs=false ./...：通过。
- 两个独立二进制 cmd/demo、cmd/gateway：构建通过。
- go mod verify：通过，所有模块校验成功。
- demo 二进制烟测：启动两个模拟下游、真实发现、alice/bob 列表和调用均通过。
- gateway 二进制烟测：读取配置；在下游端口关闭时正常启动但仅公布空目录，不启动下游、不虚构成功。
- 拒绝 0.0.0.0 监听：通过。两个命令 SIGTERM 优雅关闭：通过。

当前云端非 checkout 工作区的外层 VCS 元数据使普通 build 的 VCS stamping 失败（exit 128）；本地构建显式使用 -buildvcs=false。CI 在正常 checkout 中使用普通 `go build ./...`，涵盖两个命令。CI 仅赋予 contents: read，从 go.mod 选择 Go 版本；本阶段最终远端结果需针对新提交另行验证。

## 未完成和未验证

没有 OAuth、安全网页绑定、持久化凭证库、管理界面、真实系统、生产部署、真实写操作验证或完整 MCP 一致性认证。内存发现快照和 schema 校验不是生产安全认证；不声称能隔离所有恶意 schema CPU 消耗，也不信任工具描述/注解/返回内容。
