# 从配置检查到首次接入

这是单实例、非生产、合成凭据预览。只使用虚构身份和本地模拟服务；独立凭据文件不是保险库，也不让本预览具备生产认证、OAuth 或真实账号接入能力。以下命令从仓库根目录运行，需要 Go 1.26+。

## 1. 构建并离线检查

```sh
go mod download
mkdir -p bin
go build -o bin/gateway ./cmd/gateway
go build -o bin/mock ./cmd/mock
./bin/gateway -operation check-config -config configs/demo.json
```

成功返回 JSON，例如：

```json
{"valid":true,"scope":"bootstrap-config","systems":2,"users":2,"discovery_checked":false,"storage_checked":false}
```

`check-config` 检查 JSON、身份、工具白名单、认证头格式、固定端点和网络策略，以及入口/出站/审计配置的静态约束。它不启动监听、不做 DNS 查询或下游发现、不读写数据库，也不读取根密钥。只接受 `-config` 和可选的 `-credentials-file`，不能附带 serve、数据库或维护选项。

**成功仅表示引导配置有效，不表示工具可用或服务已就绪。** 它不验证下游是否接受凭据、不获取工具 schema、不证明端口空闲，也不证明持久状态可打开。缺少某系统凭据仍可通过静态配置校验，但该用户的系统发现会失败；它不是匿名访问模式。account/remote-test 的有限期强入口认证要求仍由实际启动校验，不能用这个结果替代。

## 2. 首次运行与客户端验收

在两个终端分别运行模拟下游：

```sh
./bin/mock -system crm -listen 127.0.0.1:9001
./bin/mock -system docs -listen 127.0.0.1:9002
```

第三个终端运行内存入口：

```sh
./bin/gateway -config configs/demo.json -listen 127.0.0.1:8080
```

gateway 不启动或托管下游。检查启动日志的 discovery issue 数量；零问题后，用支持 Streamable HTTP 的客户端连接 `http://127.0.0.1:8080/mcp`：

| 合成用户 | 请求头 | 预期工具 |
| --- | --- | --- |
| alice | `Authorization: Bearer demo-alice` | `crm__echo`、`docs__echo` |
| bob | `Authorization: Bearer demo-bob` | 仅 `crm__echo` |

调用 `crm__echo`，参数 `{"message":"hello"}`；同时确认 bob 不可调用 `docs__echo`。这是接入验收，不只是检查进程存活。命令在启动时发现目录；修改配置或下游工具后，停止并重启入口。Ctrl+C 会关闭网关，但两个 mock 需要各自停止。

要保存撤权、绑定和策略状态，改用[持久入口步骤](cli-preview.md#2-显式初始化持久入口)。仅首次创建不存在的数据库使用 `-init-db`；根密钥通过 `-key-file` 或 `-key-stdin` 提供，不放进参数值。普通重启去掉 `-init-db`。初始化可能在后续端口绑定失败前已经提交；先检查已有状态，不要删除数据库重试。

## 3. 可选：把引导凭据与拓扑配置分开

默认示例仍可原样运行。若希望避免把凭据写在拓扑配置里，可用 `-credentials-file` 在**内存启动或首次初始化**时补齐凭据。不使用环境变量展开，不接受命令行明文凭据，不改变既有请求头模式。

在可信私有目录中准备两个文件；以下内容均为公开虚构测试数据。凭据文件必须是 owner-only 普通文件（例如 POSIX `0600`），不能是符号链接，最大 256 KiB。路径及其父目录也应由可信操作者控制，不可让其他进程替换。

`configs/private/topology.json`：

```json
{
  "systems": [{"name":"crm","endpoint":"http://127.0.0.1:9001/mcp"}],
  "users": {"alice":{"allowed":["crm__echo"]}}
}
```

`configs/private/credentials.json`：

```json
{
  "users": {
    "alice": {
      "token": "demo-alice",
      "credentials": {"crm":"mock-crm-alice"}
    }
  }
}
```

先检查，再在 crm mock 已运行时启动：

```sh
./bin/gateway -operation check-config -config configs/private/topology.json \
  -credentials-file configs/private/credentials.json
./bin/gateway -config configs/private/topology.json \
  -credentials-file configs/private/credentials.json -listen 127.0.0.1:8080
```

文件合并是补充，不是覆盖：

- 只能为拓扑中已存在的用户和系统提供非空 `token` / `credentials` 值；不能创建身份、增加白名单或改变网络策略。
- 已有非空入口 token，或同系统已有内联 credential 键，均视为冲突并拒绝；即使两个值相同也不悄悄覆盖。
- 未知字段、无效格式和超限文件被拒绝。JSON 字符串的值按原文使用，不自动 trim、删前缀或补 `Bearer`；[认证模式约束](downstream-auth.md)不变。
- 错误不回显凭据或文件内容。请勿为排错把文件、命令输出中的业务数据或真实凭据提交到仓库。

持久初始化时可以同时使用 `-db`、`-key-file`、`-init-db` 与 `-credentials-file`。**重开已有数据库时必须省略 `-credentials-file`**；凭据、撤权和策略以认证后的存储为准，不能通过旧配置重新导入。保留匹配的拓扑与根密钥：拓扑文件可不含引导 token/credentials，重开不要求旧引导凭据存在。离线维护也不接受 `-credentials-file`。

`check-config` 只检查引导材料；只有拓扑、没有引导 token 的重开配置不一定能通过它，不能据此判断数据库损坏。对已有持久状态使用停止服务后的 `status` 操作检查，见下一节。

## 4. 重启与升级：不要重新初始化

1. 停止 gateway 并等待退出，不要让维护命令与服务并发持有数据库。
2. 升级前保留干净关闭后的冷备份、匹配拓扑和单独保管的匹配根密钥；数据库单独备份不够。
3. 当前 v4 存储使用原路径和 key 重开，不加 `-init-db`，不加 `-credentials-file`。内存模式没有可迁移状态。
4. 只有认证后的 v2/v3 旧存储才用显式 `-operation migrate` 迁移到 v4。其他旧版本不受支持，不能靠重新初始化绕过。迁移和状态检查示例见[离线维护](maintenance.md#explicit-migration-to-v4)。
5. 迁移后先离线 `status` 检查目标身份，再启动、验证 tools/list 与拒绝行为。迁移保留原策略、绑定、入口有效期；不会从配置恢复撤销的权限。旧入口会保守地标为非强凭据，启用 account/remote-test 前需按维护文档替换为有限期入口凭据。

迁移/维护输出失败不证明变更没有提交；先确认实际存储状态，再决定下一步。不要自动重试变更、删库、删 journal、解除锁或盲目回滚备份。完整旧备份仍可能恢复旧权限，本预览没有外部新鲜度见证或自动安全恢复能力。

## 5. 常见问题按阶段排查

| 现象 | 检查与下一步 |
| --- | --- |
| `invalid command options` | 先看 `./bin/gateway -help`；check-config 不接受 listen/db/key/account 等参数，已有数据库不接受 credentials-file。不要把 key/token 值直接写进参数。 |
| 配置无法打开、JSON 或配置校验失败 | 确认运行目录、文件可读、单个 JSON 对象、无未知字段；检查系统名、完整工具名、重复身份及网络策略。错误有意不回显配置内容。 |
| 凭据文件被拒绝 | 检查 owner-only 权限、普通非符号链接文件、大小、严格 JSON、已有用户/系统及内联值冲突；不要放宽到公开可读来排错。 |
| 静态检查成功，但 discovery unavailable | 确认 mock 已启动、端口与 `/mcp` 地址一致、该用户有对应系统凭据且模式正确。静态检查不会连接下游；发现失败仅保留其他健康系统目录，不扩大权限。 |
| `cannot bind configured listener` | 确认没有另一个入口占用端口，或选择其他回环端口并同步客户端地址。若此前带 init-db，检查数据库是否已经创建，之后按普通重开处理。 |
| 错误 key、缺失/损坏/版本不受支持或数据库占用 | 停止服务，保留现状，检查原 key、路径、独占持有者与版本。仅对受支持旧版本显式迁移；不得回退内存、重新初始化或删除数据库。 |
| 客户端认证失败或工具为空 | 使用入口 token 而非下游 token；检查有效期/撤销状态、完整白名单和启动发现结果。客户端 session ID 不能替代身份。 |
| HTTP 429 | 入口或下游准入预算已满；检查测试负载与[预算边界](audit-limits.md)，不自动重试工具写操作。 |

更详细的边界见[持久化](persistence.md)、[维护](maintenance.md)、[本人绑定预览](account-preview.md)及[远程合成测试](remote-testing.md)。先跑通本文默认回环路径，再按需要显式选择扩展能力；静态检查和默认启动都不会自动开启它们。
