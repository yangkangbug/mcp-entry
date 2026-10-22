# 有界的同文档 schema 引用

当前支持一个保守子集：`$ref` 只能是同一 JSON Schema 文档内的片段 JSON Pointer。工具对外公布的 schema 保持原样，不展开、不扁平化，也不把引用替换成统一参数模型。

例如，输入根仍须显式声明 `type: object`：

```json
{
  "type": "object",
  "$defs": {
    "identifier": {"type": "string", "minLength": 1}
  },
  "properties": {
    "request_id": {"$ref": "#/$defs/identifier"}
  },
  "required": ["request_id"]
}
```

## 支持与拒绝

- 支持 `$defs` 或 draft-07 `definitions` 中的对象/布尔 schema，以及能被验证器准确表示的其他真实 schema 位置。
- 片段先进行一次百分号解码，再逐段进行一次 JSON Pointer `~0`/`~1` 解码；保留 `+`。数组下标必须为规范十进制形式，对象属性名则按原字符串处理。
- 引用目标必须确实存在于原始文档的 schema 位置。不能引用 examples、default、const、普通数据或验证器内部生成的结构。
- schema 关键字区分大小写。拒绝验证器或 SDK 会按不区分大小写方式解释的非规范别名（含 Unicode 折叠），例如 `$REF`、`PROPERTIES`、`X-MCP-HEADER`；不自动改成小写。这避免原始 schema 准入与 typed 解码产生不同含义。普通属性名与示例数据中的同名文本不受此规则影响。
- 拒绝空字符串引用、锚点引用、外部/相对文档引用、`$dynamicRef` 及 schema 位置的 `x-mcp-header`。不会发起 schema 网络请求；验证器另配置拒绝外部加载的 Loader。
- 含引用的文档不接受 schema 位置的 `$id` 或嵌套 `$schema` 声明。根 dialect 仍限于当前支持的 draft-07/2020-12；未声明时使用验证器默认值。
- 所有包含边和引用边组成的图必须无环，包括未使用定义内的环。因此合法但递归的 JSON Schema 也会被拒绝。这是明确的原型兼容性限制，不是通用递归 schema 支持。
- draft-07 的 `$ref` 同级约束忽略规则与 2020-12 的同级约束执行规则仍由原验证器处理。安全准入会保守计算所有 schema 分支，即使某 dialect 在验证时忽略它们。

普通属性名或 example/default 数据中的 `$ref`、`$id` 等文本不会被误当成 schema 指令。

## 资源准入

现有单工具定义 64 KiB、目录总量 1 MiB、请求参数 64 KiB 等边界不变，另增加以下上限：

- 每个 schema 文档原始 JSON 节点 4096、schema 节点 512、引用 128。
- 原始 JSON 深度 32；展开图深度 64；保守展开工作量 4096。
- 每次调用参数 JSON 深度 32、节点 4096。
- 展开 schema 工作量 × 参数节点数不超过 1048576。

根节点深度为 0，节点数量包含根。工作量按包含边和引用边累计，复用定义仍计入每条使用路径，防止小型无环 DAG 产生指数级重复验证。数据节点也纳入原始 JSON 节点计数。

这些限制是保守的资源准入，不是精确的 CPU 计费或硬性墙钟中断。验证器的同步 Validate 没有取消 API；正则、枚举比较和 uniqueItems 等还有额外成本。不会启动超时后台 goroutine 后假装验证已停止，也不声称这些限制构成完整恶意 schema CPU 隔离。现有无引用 schema 同样受准入限制。

发现时先检查目录规模和 schema，再交给 SDK 处理。一个系统任意工具不合格时，整个系统目录拒绝发布，旧目录也被清除；其他健康系统保持可用。调用参数不符合 schema 或资源准入时，不联系下游。下游输出 schema 也接受发现准入，但网关仍不独立验证实际输出内容。

## 正则语法与安全诊断

输入/输出 schema 的 `pattern` 值及 `patternProperties` 的键在真实 schema 位置接受 Go `regexp` 编译准入。使用的是 Go/RE2 语法子集，不是完整 ECMA-262：lookaround（前瞻/后顾）、反向引用、超过 1000 的计数重复等不受支持。现有合法正则的约束保留并执行，不会为了发布目录删除约束。examples、default、const、enum 或未知扩展中的普通数据不会被当作 schema 正则。

发现阶段以固定 `downstream_schema_rejected` 和 `schema_reason` 提供本地诊断：一般准入拒绝为 `invalid_or_unsupported`，无效或不支持的正则为 `regexp_invalid_or_unsupported`。不解析原始错误字符串，不公开工具名、schema/属性路径、表达式或验证器错误文本。HTTP/传输证据优先于 schema 诊断；该分类不改变认证语义，不触发重试。

这只是诊断改进，不是正则兼容性修复或按授权工具隔离目录。任何工具（包括白名单外工具）被拒绝时，该绑定的整个目录仍不可用，旧目录仍清除。审计只记录固定 `schema_rejected` 结果类别，不记录 schema 明细。该新枚举使用现有审计存储格式；旧版本二进制可能不识别包含该枚举的记录，不应把无需格式迁移理解为支持降级读取。
