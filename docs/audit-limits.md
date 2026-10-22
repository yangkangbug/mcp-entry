# 元数据审计、入口与出站准入

这是单实例合成测试能力，不是完整的生产审计或入口防护平台。

## 审计范围

成功的绑定替换/撤销、策略变更和 principal 禁用，与状态在同一 SQLite 事务提交审计。发现和调用先提交 start，再出站，最后提交 terminal。记录动作、阶段、时间、耗时、策略/绑定版本、脱敏关联标识、固定结果类别及 MCP isError；不保存参数、结果正文、头、token 或下游错误原文。标识为用途隔离的 HMAC 摘要，不代表匿名化保证。

拒绝授权、未认证请求和限流拒绝不写持久审计，而是使用下述固定空间的进程内拒绝摘要；HTTP 访问日志、完整管理审计、完整保留策略仍待完善；已有受信任离线导出与检查点归档。Audit 是受信任的库接口，不是公开查询 API。

内存模式使用有界环形记录，淘汰数量通过 Dropped 可见。持久模式默认最多 4096 条，可通过 config.audit.capacity 调整到 1–65536；不自动删除。离线 archive-audit 在私有新文件持久导出后，以事务检查点替换已导出的完整日志，保持序号递增；当前进程仍有 Pending 时拒绝归档；崩溃遗留 start 原样导出且累计未知结果数保留于检查点与 ArchivedUnfinished 状态，详见[维护说明](maintenance.md)。每个出站操作预留 terminal 空间，容量不足在准入前拒绝，不能取消已获准的操作。日志链及头部纳入完整性认证。存储故障关闭准入；终结记录写失败不会改写已确认的下游成功，也不会自动重试。完整旧数据库仍可能回滚，HMAC 不证明备份新鲜度。

AuditStatus.Pending 表示当前进程尚未清理完的操作；Unfinished 表示存在 start 但没有 terminal 的记录，包含恢复出的崩溃遗留。后者只能解释为结果未知，不能推定失败、成功或允许重试。Close 停止准入、取消并等待操作清理和终结记录后释放数据库；内部写入预算不是 Close 的硬性墙钟上限。

停止服务后，可用同一配置和独立 key 文件读取自己的指定身份记录：

```sh
./bin/gateway -config configs/private.json -db private/state.db -key-file private/test.key \
  -operation audit -tenant demo -principal alice -after-sequence 0 -limit 100
```

这是本机文件拥有者权限，不是调用者自报 tenant 即获得远程授权。输出只有元数据；limit 范围为 1–1000。

## 出站限额

Config.limits 下的 global、principal、tenant、system、shared_quota 都接受 max_concurrent、rate_per_second、burst。默认分别为 64/160/256、8/20/32、16/40/128、32/80/128、16/40/128（并发/每秒/突发）。零值选默认，不表示无限制。System.quota_subject 可将多个系统映射到同一提供方配额主体；仅管理者配置，用户不能创建桶。

发现、定向刷新和调用共用这些桶，原子地检查所有适用范围，超额立即拒绝，队列长度为零。授权和绑定代次在最后准入锁内重新检查；令牌不因调用失败返还，并发槽一直保持到会话清理完成。没有自动重试、后台等待队列或分布式配额。大量启动发现可能命中突发限制并产生部分目录，需按测试规模明确配置。

这些出站限额与下面的入口限额相互独立，不复用计数或令牌。真实试点前仍需部署侧入口治理和代表性负载验收。


## 有界入口（合成单实例）

Config.ingress 的 global、principal 均接受 max_concurrent、rate_per_second、burst，默认分别为 128/320/512、16/40/64；零值使用默认。桶只在启动时按已配置身份分配，未知 token、IP、X-Forwarded-For、URL 和工具名不会创建桶。先取全局许可，再在凭据有效时取本人许可；本人拒绝仍消耗本次全局速率令牌。全局达到上限时不能保证健康用户一定有槽位，这不是公平调度或分布式配额。

Gateway.GuardHTTP 包装整个路由树；Handler 和 AccountHandler 默认也包装，相同 Gateway 的嵌套包装只计一次。守卫中的身份检查只用于选桶，实际路由仍重新验证身份，最终调用仍独立授权。静态 account 页面、未知路径、方法拒绝、错误认证与正常 MCP 请求共用全局边界。超额在解析 body 前返回普通 HTTP 429，不编造 JSON-RPC id、不自动重试。没有排队、按 IP 动态表或取消监视 goroutine；处理函数真正退出才释放并发槽，取消不会提前虚报空闲容量，已经消耗的速率令牌不退回。

解析后的请求头和 URI 总预算为 16 KiB，全路由 body 上限 64 KiB，account JSON 仍限制 8 KiB。守卫通过 ResponseController 在支持的服务器上设最多 15 秒的本次请求读取截止（若请求 context 已有更早截止则使用更早值），并保持至宿主清理未读 body；不用后台 goroutine 模拟超时；该接口无法读取原有宿主截止，守卫会设置自己的预算，不能声称只会收紧任意宿主的更短 ReadTimeout。需更短预算的嵌入宿主可传递更早 context deadline。不支持此接口的嵌入宿主必须自己配置原始头、body 读取时间和连接上限。解析后的检查不能代替宿主解析前 MaxHeaderBytes/ReadHeaderTimeout，函数超时也不能抢占不合作的自定义 Reader。CLI 对连接和 HTTP/2 流另设有限预算；具体配置见 CLI 运行文档。不声称防御所有网络层 DoS 或承诺性能基线。

## 拒绝摘要不是完整请求审计

Gateway.RejectionStatus() 仅供受信任进程内调用，无公开管理端点。Started 标记本进程统计起点；每个固定类别只有 Count、Last、Saturated，计数饱和后不回绕。不保存身份、IP、URL、token、参数、错误原文或不可信工具名，不新增 SQLite 表或持久格式，不占必需事务审计容量，重启后归零。

HTTP 数组按 RejectionIngressGlobal、RejectionIngressPrincipal、RejectionAuthentication、RejectionAuthorization、RejectionRequest、RejectionHTTPUnavailable 顺序计数，每个可观察到的拒绝响应一次。Operations 数组按授权、参数/schema、出站准入、协议拒绝顺序计数（索引为对应枚举减 RejectionOperationAuthorization），包含 HTTP 200 中的前置 MCP 操作拒绝，以及直接库调用拒绝。二者统计单位不同，不能相加宣称“请求总数”；一次 HTTP 请求可以承载多个协议操作。下游已执行后的工具业务错误仍由既有操作审计描述，不冒充入口拒绝。SDK 在方法中间件之前拒绝的协议内容及宿主在 GuardHTTP 之前拒绝的连接/原始头，不保证出现在这些摘要中。它们不是逐请求取证记录、持久访问日志或完整审计覆盖。
