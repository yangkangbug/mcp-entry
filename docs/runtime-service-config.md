# 受控服务配置应用（合成管理环境）

独立管理员可以在**持久模式**在线新增服务、修改现有服务 `timeouts`。成功表示配置及相关空绑定已经在 SQLite 事务中保存并发布，不表示下游连通、凭据有效或工具已发现。内存模式仅可静态校验，不能冒充持久应用。

## 支持边界

- 新增服务：复用固定端点、认证头、网络策略、超时、配额输入校验；最多 16 服务。所有用户的新绑定无凭据，普通用户为 unbound、禁用用户为 revoked；不自动授予任何工具。
- 修改 timeouts：影响该服务全部身份的目录和新请求。提交后该服务旧目录失效、旧在途操作尽力取消；重新显式发现才能再次列出业务工具。其他服务不受影响。
- 修改已有 endpoint/auth/network/quota_subject、删除、重命名服务：拒绝 `unsupported_destructive_change`。不能借“保存”把已有凭据发送到新接收方。
- 配置预览和应用不联网、不执行发现、不自动调用业务、不重启进程、不重建 DB、不重置限流或审计。
- 已经出站的请求无法保证撤回或下游回滚。取消/超时可能结果未知，不能自动重放。

## 管理 API

全部端点沿用独立管理员鉴权、回环 Host/Origin 约束、限流和 no-store。POST 需要 JSON 与 `X-MCP-Admin: 1`。现有 `/admin/api/config/validate` 仍然只做静态草稿校验。

`GET /admin/api/config/current` 返回：

```json
{"revision":0,"digest":"sha256...","systems":[],"persistent":true,"apply_supported":true,"supported_changes":["add","timeouts"]}
```

`POST /admin/api/config/preview` 输入完整候选（非 patch）：

```json
{"expected_revision":0,"systems":[{"name":"synthetic","endpoint":"http://127.0.0.1:9001/mcp"}]}
```

返回 `preview:true, applied:false, revision, candidate_digest, confirmation_id, confirmation_expires_at, added:string[], updated:string[]`。预览票据绑定规范化候选和基础版本，仅当前 handler 内存可用，最多 64 个，2 分钟到期。

`POST /admin/api/config/apply` 发送相同 `expected_revision` 和 `systems`，另加预览的 `candidate_digest` 与 `confirmation_id`。票据单次使用，每次尝试即消费；服务端重新做校验和 CAS。成功返回 current 视图及 `applied:true, discovery_required:string[]`。revision 从 0 单调增加，最大为 JavaScript 安全整数 2^53−1。

- 400：无效配置/请求，或破坏性修改不受支持。
- 403：内存模式或维护实例不允许应用。
- 409：过期/重放/不匹配票据、基础版本冲突或没有实际变更。
- 存储/审计失败：明确失败，不返回 applied；提交结果不确定会关闭业务准入。

应用响应丢失时先读取 current 的 revision 与 digest。若服务器可用且匹配预览候选的新版本，即可确认已应用；不要无条件重试应用，更不能重复业务调用。若存储已 fail-closed，需要受信恢复后查询，不能假称尚未保存。

## 持久化与重启

v4 增加可选 `runtime_config` 单行认证扩展（format=1、revision、完整规范化 systems JSON，包含 timeouts）。首次应用在同一事务写注册表、所有新绑定、审计事件和完整状态 MAC。

原启动配置的 systems 与 seed identities 仍是**部署锚点**：保留原 topology、key_check 与审计标识密钥 AAD。重开使用原 seed 配置，实际服务与 managed identities 从认证库恢复，绝不重新导入旧配置的 token、授权或凭据。不要将管理端导出的有效服务列表直接覆盖 seed 配置，否则原部署锚点不匹配会拒绝启动。

registry 存在时，现有完整状态 MAC 使用域分离包装，将 manifest 与原主体/绑定/审计状态共同认证。旧二进制不能忽略新增表后成功打开；删除表/行、改 revision 或服务配置均无法降级回旧状态。无 registry 的旧 v4 库保持原格式兼容。任何认证失败都不能 fallback 为旧配置或重新 init-db。

用户操作、绑定变更、审计终态、审计归档、根密钥轮换都继续认证该注册表。配置回退仅能作为新的受支持变更应用，不能恢复旧 DB 或复活撤权。完整数据库历史备份替换的外部反回滚仍不在当前合成存储保证范围内。

## 并发语义与验证

应用和最终调用准入共享 `g.mu`；网络 I/O 不持该锁。Refresh 锁内复制身份值和服务名，再锁外发现。服务版本随只读配置副本进入目录；迟到发现、旧目录、旧 SDK handler 和最终调用准入都复验版本。新增限流桶原位注册，不重置现有桶、令牌或在途许可。

测试覆盖新增/超时恢复、禁用与撤权保留、破坏性拒绝、预览票据/CAS、篡改/降级、旧 v4 MAC 拒绝、用户创建并发、限流保留、根密钥轮换/归档、事务失败和提交 ACK 丢失。合成回环集成覆盖新增→绑定→授权→发现→调用、超时更新拒绝迟到目录、旧 handler context 拒绝及重开后调用；另有 Refresh 并发 race 回归。
