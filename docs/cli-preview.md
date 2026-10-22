# 本地可运行预览

仅使用仓库内的合成用户与虚构凭据。需要 Go 1.26+；入口和本页示例地址限字面回环 IP，没有公共管理 API。可选受控 HTTPS 下游见 [网络策略](network-policy.md)。请从仓库根目录运行。

## 1. 构建并显式启动模拟下游

```sh
mkdir -p bin
go build -o bin/gateway ./cmd/gateway
go build -o bin/mock ./cmd/mock
```

在两个终端分别运行：

```sh
./bin/mock -system crm -listen 127.0.0.1:9001
./bin/mock -system docs -listen 127.0.0.1:9002
```

每个进程只运行一个固定的合成 MCP 服务，路径为 /mcp；crm 包含 alice/bob，docs 仅包含 alice。gateway 不会启动、托管或停止这些下游进程。

## 2. 显式初始化持久入口

以下固定字符串是公开测试 key，不可用于真实凭据。数据库和 key 必须放在可信、私有、稳定路径的本地目录，不能交给不可信进程修改或替换。

```sh
umask 077
mkdir -p configs/private
printf '%s' '0123456789abcdef0123456789abcdef' > configs/private/demo.key
./bin/gateway -config configs/demo.json -db configs/private/demo.sqlite \
  -key-file configs/private/demo.key -init-db -listen 127.0.0.1:8080
```

key 文件必须是 owner-only 普通文件，不能是符号链接，内容恰为 32 个原始字节，无换行。也可用 -key-stdin 代替 -key-file，通过标准输入提供恰好 32 字节后 EOF；不接受 argv 中的 key 值，不自动生成真实密钥。

只有首次创建不存在的数据库才使用 -init-db。正常重启去掉该标志，其余配置不变。已有数据库不会被覆盖；缺失数据库、错误 key 或损坏状态不会回退到内存模式。key/config/store 校验失败前不打开监听端口。

显式初始化可能在之后的端口绑定或发现失败之前已经提交。此时保留数据库，排除故障后以不带 -init-db 的命令重开；不要删除数据库来掩盖启动失败。发现失败保留健康系统目录，不放宽授权。

默认不带 -db 的 gateway 和 cmd/demo 仍为内存模式。不能把内存演示与持久实例当作同一个授权状态。

## 3. 连接客户端

使用标准 Streamable HTTP，地址 http://127.0.0.1:8080/mcp。客户端请求头分别使用公开演示值 Authorization: Bearer demo-alice 或 Authorization: Bearer demo-bob。

alice 可见 crm__echo 与 docs__echo，bob 仅可见 crm__echo。调用参数例如 {"message":"hello"}；bob 直接请求 docs__echo 仍被拒绝。客户端不得使用 session ID、工具参数或用户名字段代替入口 token。

## 4. 停止入口后执行受信本地操作

先在 gateway 终端按 Ctrl-C 或发送 SIGTERM，并等待退出。关闭会停止新准入、取消在途工作并释放数据库；不保证下游回滚。数据库的独占所有权会拒绝仍在运行的入口与本地操作并发使用。

查询目标身份的策略和绑定元数据，不返回凭据：

```sh
./bin/gateway -config configs/demo.json -db configs/private/demo.sqlite \
  -key-file configs/private/demo.key -operation status -tenant demo -principal alice
```

读取实际 Generation 后撤销某个绑定，下面的 1 只适用于刚初始化的示例：

```sh
./bin/gateway -config configs/demo.json -db configs/private/demo.sqlite \
  -key-file configs/private/demo.key -operation revoke-binding \
  -tenant demo -principal alice -system docs -expected-version 1
```

其他操作为 -operation disable-principal，以及 -operation set-policy。二者的 -expected-version 对应 Policy.Version，不是绑定 Generation；set-policy 用重复的 -allow 指定完整工具名，省略所有 -allow 表示清空整个白名单。过期版本拒绝修改，不自行重试。

这些命令只操作本地存储，不启动监听、执行发现或访问下游。它们是受信任操作者工具，不是用户自助认证；能访问配置、数据库和 key 的操作者掌握管理权限。没有绑定凭据导入、恢复禁用身份或 token 颁发命令。

重新启动 gateway 时不带 -init-db。再次连接客户端验证被撤销的工具不再出现且直接调用被拒绝；旧配置不能恢复权限。若输出结果失败，变更可能已经提交，应先查询 status，不能把没有输出当作未执行。

## 验证与限制

```sh
go test ./cmd/gateway -run TestGatewayExecutablePersistentLifecycle -count=1 -v
```

此回归构建真实可执行文件，通过官方 Go SDK 客户端连接实际子进程，覆盖发现/调用、双用户隔离、关闭重开、离线撤权/禁用、错误 key/数据库与无监听失败。它不是桌面客户端 GUI 验证。

密钥轮换、旧备份新鲜度证明、生产账户与网络、审计和跨节点撤权仍不在本预览内。完整旧数据库与相同 key 的回滚可能恢复旧权限，详见 [持久化边界](persistence.md)。

## 独立客户端回归

已用官方 MCP Inspector CLI 2.12.0 对真实 gateway 子进程执行 modern 与 legacy 两种 protocol-era：双用户/双下游列举和调用、重启后的撤权与禁用均通过。没有记录实际协商版本，因此不把 era 标志当作具体协议版本证据；未验证 GUI，绑定凭据更新流程尚待下一阶段。

已安装该版本时，可将以下虚构配置保存到 owner-only 的私有客户端配置文件：

```json
{"mcpServers":{"gateway":{"type":"http","url":"http://127.0.0.1:8080/mcp","headers":{"Authorization":"Bearer demo-alice"}}}}
```

```sh
mcp-inspector --cli --config configs/private/client.json --server gateway \
  --method tools/list --format json --quiet --stored-auth-only --protocol-era modern
mcp-inspector --cli --config configs/private/client.json --server gateway \
  --method tools/call --tool-name crm__echo --tool-args-json '{"message":"hello"}' \
  --format json --quiet --stored-auth-only --protocol-era legacy
```

测试使用隔离的 HOME、XDG_CONFIG_HOME 和 MCP_CLIENT_CONFIG_DIR，不读取真实账号或自动发起 OAuth。Inspector 的隐藏工具拒绝发生在客户端工具发现预检查；服务端直接调用越权由 SDK 回归独立验证。

## 可选本人绑定页面

`-account` 默认关闭，仅用于 serve；即使显式传入 false，也不能与离线操作组合。它要求预配置的 32 字节 base64url 格式入口 token 与有限有效期，原 demo-alice/demo-bob 不满足要求。准备合成配置、绑定替换、定向刷新和重启验证见 [本人绑定预览](account-preview.md)。页面 Origin 自动取实际回环监听地址，没有任意 Origin 开关。
