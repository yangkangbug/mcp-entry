# 元数据审计与出站准入

这是单实例合成测试能力，不是完整的生产审计或入口防护平台。

## 审计范围

成功的绑定替换/撤销、策略变更和 principal 禁用，与状态在同一 SQLite 事务提交审计。发现和调用先提交 start，再出站，最后提交 terminal。记录动作、阶段、时间、耗时、策略/绑定版本、脱敏关联标识、固定结果类别及 MCP isError；不保存参数、结果正文、头、token 或下游错误原文。标识为用途隔离的 HMAC 摘要，不代表匿名化保证。

拒绝授权、未认证请求和限流拒绝目前不写审计；HTTP 访问日志、完整管理审计、完整保留策略仍待完善；已有受信任离线导出与检查点归档。Audit 是受信任的库接口，不是公开查询 API。

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

这些限额不覆盖入站连接数、HTTP 元数据读取或 account 页面请求，不是完整的抗过载/DoS 边界。真实试点前仍需入口治理和负载验收。
