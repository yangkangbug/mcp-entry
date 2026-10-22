# 下游凭证请求头

连接的 `auth` 只决定如何把当前用户在该系统的凭证写入一个 HTTP 请求头，不改变入口身份、工具授权或业务参数。当前仍仅支持回环 HTTP 和虚构凭证；这不是 OAuth、账号绑定或安全凭据库。

## 配置

`systems` 项可选 `auth`，省略时保持原来的 Bearer 行为：

```json
{
  "systems": [
    {"name": "crm", "endpoint": "http://127.0.0.1:9001/mcp"},
    {"name": "docs", "endpoint": "http://127.0.0.1:9002/mcp", "auth": {"mode": "raw"}},
    {"name": "search", "endpoint": "http://127.0.0.1:9003/mcp", "auth": {"mode": "api_key", "header": "X-API-Key"}}
  ],
  "users": {
    "alice": {
      "token": "demo-alice",
      "allowed": ["crm__echo", "docs__echo", "search__echo"],
      "credentials": {
        "crm": "mock-crm-alice",
        "docs": "Token mock-docs-alice",
        "search": "mock-search-alice"
      }
    }
  }
}
```

以上地址、工具和凭证都是示例，运行前需要自行提供匹配的本地模拟服务；网关不启动下游。内置 `cmd/demo` 的两个模拟服务仍使用 Bearer，不因新增模式自动改变认证方式。已有 `configs/demo.json` 无需修改。

- `bearer`：发送 `Authorization: Bearer <credential>`；空 mode 也采用此默认值。
- `raw`：把完整凭证值直接写入 Authorization，不增加前缀，也不自动删减已有前缀。
- `api_key`：写入配置的 header，例如 `X-API-Key` 或 `Api-Key`；不会同时发送备用 Bearer 凭证。
- bearer/raw 不接受 header 字段。未知模式、模式拼写大小写变化和不兼容字段组合均拒绝。

请求头名称由配置管理员决定，不接受工具参数或下游 schema 动态指定。凭证仍在 `users.<user>.credentials.<system>` 中独立选择，不能由参数中的 user、header 或 token 字段替代。

## 校验与隔离

API-key header 名必须以 ASCII 字母开头，仅含字母、数字、连字符，最长 64 字节；拒绝下划线、空白、控制字符和其他标点。名称按 HTTP 规则规范化，保留值原文。

拒绝已知的协议、路由、代理、连接、内容协商、Cookie、session、转发身份与证书信任头，包括 Authorization、Host、Connection、TE、Upgrade、Trailer、Cookie、Set-Cookie、Forwarded、X-Forwarded-*、Content-*、Accept*、Mcp-*、Sec-* 和 Last-Event-ID 等。保留名单不是对所有私有扩展头语义的完整判断；管理员必须确认所选名称确实用于该下游的 API key，而非其他权限或路由功能。

凭证最长 4096 字节，仅接受可打印 ASCII，拒绝控制字符、非 ASCII 及首尾空格。Bearer 另按其 token 字符集合校验；raw/API-key 可保留内部空格。不会自动 trim、编码或修正凭证。缺失/空凭证仍使该用户的系统发现失败，不会退回入口 token 或匿名请求。

发现、调用和有状态 session 清理使用相同的用户/系统凭证选择。发送前覆盖选定认证头并移除已有 Authorization，处理所有大小写变体；不修改调用方的原始请求。重定向仍全部拒绝，客户端没有 Cookie jar。共享连接池不共享用户认证头。

认证/传输失败沿用固定脱敏错误，不自动重试或切换认证方式。本阶段不提供详细认证错误分类、动态凭证更新、密钥轮换、真实账户接入或生产部署保证。正常工具返回内容仍是不可信下游数据，不承诺内容级秘密过滤。
