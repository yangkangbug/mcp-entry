# 本人绑定预览

这是默认关闭的本地合成测试入口，不是账号注册、OAuth 门户或生产认证平台。启动 `cmd/gateway -account` 后，在实际回环监听地址访问 `/account`。入口与页面仍是 HTTP，不得部署到公网，也不要填写真实账号凭据。

页面默认中文，可在右上角切换中文 / English。标题、表单、绑定状态、固定提示、错误及撤销确认随语言切换，日期按所选语言显示当地时间。切换只影响当前页面显示，不发起请求，也不改变身份、凭据、绑定、工具权限或未提交的表单内容；刷新页面后恢复中文。不在浏览器持久保存语言或凭据。下游系统标识保持原值，未知的服务端提示保留原文。

## 准备与启动

先按 [CLI 预览](cli-preview.md) 构建 gateway、mock，并分别运行 crm、docs。以下生成公开、固定的合成入口 token 和一小时有效期，不生成生产访问凭据：

```sh
umask 077
mkdir -p configs/private
python3 - <<'PY'
import base64, datetime, json
with open('configs/demo.json') as f:
    config = json.load(f)
expires = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).isoformat()
for index, user in enumerate(config['users'].values(), start=1):
    user['token'] = base64.urlsafe_b64encode(bytes([index]) * 32).decode().rstrip('=')
    user['token_expires_at'] = expires
with open('configs/private/account.json', 'w') as f:
    json.dump(config, f, indent=2)
PY
printf '%s' '0123456789abcdef0123456789abcdef' > configs/private/demo.key
./bin/gateway -config configs/private/account.json -account \
  -db configs/private/account.sqlite -key-file configs/private/demo.key \
  -init-db -listen 127.0.0.1:8080
```

页面地址为 `http://127.0.0.1:8080/account`。复制该私有测试配置中的本人入口 token 到页面；MCP 客户端仍使用同一个 token 的 Authorization Bearer 请求头连接 `/mcp`。公开示例 token 不具备保密性，不能用于真实访问。

正常重启去掉 `-init-db`，不要重新运行上述配置生成步骤来改变既有 token 的有效期。数据库校验要求原 token 和有效期保持一致。v1 数据库不兼容，详见 [版本边界](persistence.md)。省略 `-db` 仍可运行内存预览，但重启会从配置恢复，不能用于验收持久撤权。

## 身份与操作边界

启用页面要求所有配置入口 token 是无填充 base64url 编码的 32 字节值，并有非零 `token_expires_at`。格式检查不能证明随机性或保密性；过期 token 被拒绝。网关不颁发、轮换或恢复入口 token，不提供密码登录。

页面只使用当前输入的显式 bearer，不使用 Cookie、localStorage 或 sessionStorage；退出会清除页面状态。系统地址、认证头、用户、租户和工具白名单不能通过页面修改。API 身份从入口认证得出，不接受自报身份；提交后只返回本人绑定元数据，不回读凭据。

- GET `/account/api/bindings`：本人系统、状态、generation 与可选到期时间。
- POST `/account/api/bindings/{system}`：`expected_generation`、`credential` 与可选未来 RFC3339 `expires_at`。未提供有效期表示没有本地绑定到期时间，不表示提供方永久有效。
- POST `/account/api/bindings/{system}/revoke`：只接受 `expected_generation`。

JSON 请求体最多 8 KiB，重复/未知字段拒绝；代次冲突返回 409。固定 Host、Origin 与浏览器请求上下文检查防止跨站操作；不接受 URL 中的凭据或任意跨域页面。本人变更在最终准入时再次检查入口有效期与禁用状态。

替换先提交状态，再定向发现本人该系统，不刷新其他用户。凭据保存成功但发现失败时，响应明确区分两者；先检查状态，不要盲目重试变更。受信任管理策略仍独立决定可见工具，保存绑定不授予新权限。

## 过期与故障

入口或绑定过期后，不能取得新的列表/调用准入；不承诺取消此前已获准的远端工作。页面的 expired 是本地有效期判断，不代表提供方撤销状态。下游 401 提示认证被拒绝，403 提示权限不足；两者都不会自动撤销绑定，也不能据此断言 token 已过期。应从提供方获得新的测试凭据后替换，网关不会自动登录或刷新 OAuth。

已通过 HTTP 行为、脚本语法、独立 MCP Inspector CLI 的替换/过期/重新绑定/重启验收；未完成实际浏览器交互或 GUI MCP 客户端验证。无生产页面安全、真实身份、完整审计或负载治理承诺。
