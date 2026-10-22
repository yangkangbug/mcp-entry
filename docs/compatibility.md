# 工具契约与传输兼容性

本文描述当前回环原型的边界，不是完整 MCP 一致性认证或生产接入承诺。

## 工具契约

- 发现使用标准 `tools/list` 分页。公开名称为 `系统名__原工具名`；调用时还原原名称。
- 保留官方 SDK 能表示的工具标题、描述、annotations、`_meta`、icons 和输入/输出 schema。不是未知扩展字段的逐字节透明代理；不支持的 schema 按 [架构限制](architecture.md) 与 [引用准入](schema-references.md) 拒绝。
- schema 中的 `pattern` 与 `patternProperties` 使用 Go `regexp`（RE2 语法子集），不是完整 ECMA-262 正则实现。不支持 lookaround（前瞻/后顾）、反向引用及超过 1000 的计数重复等表达式；获准工具的无效或不支持的表达式在输入/输出 schema 发现准入时拒绝。约束不会被删除或放宽。
- 参数按 JSON 语义转发。网关不填充 schema 默认值、不自动设置 `confirm`，不改写业务游标、幂等键、`request_id`、`task_id` 或 `parent_task_id`。JSON 字段顺序及空白不是契约的一部分。
- 保留下游工具结果的 `content`、`structuredContent`、`isError` 与结果 `_meta`，不追加统一的 message 或成功包装。SDK 按协议添加的 `resultType` 与服务信息元数据不属于业务包装；已有下游服务信息不会被网关身份覆盖。可选 outputSchema 的存在与否保持不变；网关目前不独立验证下游输出。
- annotations 和工具描述是不可信提示，不替代授权。`readOnlyHint`、`idempotentHint` 等不能开放白名单外工具或触发重试。
- 不桥接未实现的请求级交互能力，例如 sampling、elicitation、自动多轮输入或 MCP 任务扩展。工具定义/结果的 `_meta` 保留不表示所有请求级元数据都会跨会话转发。

入口拒绝、连接失败与未知调用结果使用固定脱敏错误；下游正常工具错误保留其结果语义。当前不是完整的认证失败分类平台。schema 准入失败可返回固定 `downstream_schema_rejected` 分类和有界 `schema_reason`（`invalid_or_unsupported` 或 `regexp_invalid_or_unsupported`），不公开工具名称、属性路径、正则或原始验证器错误。HTTP/传输失败证据仍优先；不据此判断凭证失效或重试安全性。目录按当前授权视图原子发布：白名单外工具的不兼容 schema 不再阻断获准查询工具，也不会进入 SDK 的 schema/header 过滤或日志；任何获准工具准入失败仍清除该绑定的整个授权目录，其他健康绑定保持可用。全量接收目录的名称、跨页重名、数量、字节、分页及 schema 原始结构/深度预算仍检查，不因过滤而绕过。扩权需要重新发现，旧发现不能跨策略版本或绑定代次发布，调用仍独立鉴权。这修复授权视图的可用性隔离，并未增加正则方言支持。

## 业务异步流程

提交和查询可以是普通 MCP 工具。`accepted`、`queued`、`running` 或 `completed` 都只是下游数据，网关不会把它们统一解释成业务成功，也不会自动查询或再次提交。

任务归属、业务幂等与确认规则由下游实施。网关独立控制工具权限并选择对应用户的凭证，但不根据业务 ID 建立自己的任务归属表。客户端断线不证明下游已经取消或回滚；未取得明确结果时按未知结果处理，不自动重放。需要查状态时，由调用方显式调用下游提供的查询工具。

## Streamable HTTP 边界

入口和下游均使用官方 Go SDK 的 Streamable HTTP。下游可以通过同一 POST 请求返回 JSON 或 SSE；入口当前配置为 JSON 响应。SSE 响应不是另一个按 URL 路径选择的 transport，也不代表旧版 HTTP+SSE transport 已支持。

独立 GET SSE、事件重连/恢复与自动 MultiRoundTrip 未启用。HTTP 响应、流读取和 session 清理共享操作预算；已经确认的工具结果不因随后清理失败而被改写。网络中断不提供 exactly-once 保证。

协议矩阵与故障测试的实际执行结果见 [验证记录](acceptance.md)。SDK 能识别旧协议版本，不等于本项目对所有版本、能力和传输组合完成了验证。
