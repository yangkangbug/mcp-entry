# 合成身份与本地撤权内核

已实现单进程授权内核；默认使用内存状态，可选 [SQLite 持久化](persistence.md)。本原型供回环模拟测试和受信任的嵌入调用使用。没有公共管理 HTTP API、OAuth 或真实凭证配置；可显式开启合成身份的 [本人绑定页面](account-preview.md)。它不等于生产租户认证或生产凭证库。

## 身份与对象范围

配置 users 的对象键仍是库方法 Names/Call 使用的登录标识；入口继续验证该用户固定的演示 bearer token。可选 tenant 和 principal 来自服务端配置，默认分别是 demo 和 users 对象键。同一 tenant/principal 组合不能重复，不同租户可有同名 principal。请求参数、session ID 和自报租户不改变身份。

每个身份对每个系统有一条独立 Binding：ID、tenant、principal、system、generation，可选 ExpiresAt，以及 unbound/active/revoked 状态。初始 generation 和策略 version 均为 1；有非空合成凭据的绑定为 active，否则为 unbound。对外返回的绑定元数据不包含凭据。New 内存模式的绑定 ID 仅在当前进程实例中稳定；NewPersistent 重开同一有效数据库时恢复原有 ID。

System 仍是共享、不可变的连接模板，并未实现总体提案中的租户自有连接配置。凭据、绑定、目录与策略按身份隔离。允许列表与 active 绑定也不足以调用工具，仍须属于本身份实际发现且版本匹配的目录。

## 受信任的进程内方法

这些方法不自行验证管理操作者，Identity 参数不是授权凭证。嵌入方不得把它们直接暴露为未经认证的管理接口。

- Policy(Identity) 与 Binding(Identity, system) 返回元数据副本。
- ReplaceBinding(Identity, system, expectedGeneration, credential) 替换合成凭据并增加代次，设置 active。
- RevokeBinding(Identity, system, expectedGeneration) 增加代次，设置 revoked 并清除所持凭据引用。
- SetPolicy(Identity, expectedVersion, allowed) 替换完整白名单并增加策略版本。
- DisablePrincipal(Identity, expectedVersion) 增加策略版本及所有绑定代次，禁用入口身份并撤销全部绑定；本版本没有重新启用方法。

每个成功的变更返回新元数据；重复撤销或禁用仍增加版本。预期版本过期返回 ErrConflict，未知身份或系统返回 ErrDenied；非法策略或凭据不改变状态。禁用身份不能通过 SetPolicy 或 ReplaceBinding 恢复。调用方传入/返回的切片不与内部策略共享。

替换或撤销绑定立即移除该身份该系统的目录，其他系统不受影响；策略更新与身份禁用清除该身份全部目录。恢复绑定或授予权限不会恢复旧目录，必须重新执行 Refresh。默认 CLI 在启动时 Refresh；本人绑定替换调用 RefreshBinding，只更新该身份该系统。库方法不是配置文件热加载。

## 并发与结果语义

列举与调用共享当前授权判断。最终调用准入发生在参数/schema 校验之后，使用同一把锁核对身份状态、策略版本、绑定代次和目录版本，取得对应凭据并登记取消函数。撤权先提交则新准入失败；准入先提交则该请求已算在途，即使首个网络字节稍后才发出。

变更会尽力取消受影响的发现与调用，并使旧发现结果、旧目录和旧 handler 无法恢复权限。发现不持授权锁等待网络；发布时重新检查捕获的版本。旧列表 handler 再次过滤当前权限和目录版本；撤权前形成的列表仍可能稍后抵达，不能据此取得新的调用权限。

取消不保证远端停止或回滚。已由 SDK 确认的工具结果不会因之后的清理/撤权错误被改写；未确认结果仍可能未知，不自动重试或查询。不存在后台重放或业务编排。

使用 New 或默认内存 CLI 时，所有版本、禁用状态与撤销记录都只存在内存中。重启会从配置重新建立初始状态，配置中的旧凭据可能因此再次生效；不能将本内核当作持久化撤销机制。Go 字符串引用清除也不是安全内存擦除。NewPersistent 可保存最新版本及撤销状态，但多副本传播、入口凭据轮换、真实身份提供方与生产密钥管理仍待实现。

## 有效期与定向发现

User.TokenExpiresAt 非零时，入口认证、目录与调用最终准入均检查到期时间。BindingInfo.ExpiresAt 非零时，过期绑定不能发现或调用；本地过期不会自动宣称提供方已撤销凭据。ReplaceBindingExpiring 可设置未来有效期；原 ReplaceBinding 使用无本地到期时间的兼容语义。

RefreshBinding(ctx, identity, system) 不等待全局刷新锁。同一绑定的新请求取消并取代旧发现，发布仍检查代次、策略版本及有效期；失败只清除对应目录。变更后的持久状态可能已提交而后续发现失败，调用方应读取状态而不是盲目重放变更。

到期检查约束新准入，不提供墙钟到期瞬间终止已准入业务的保证。绑定有效期在 v2 存储中经认证持久化；入口有效期不得通过重开时编辑配置延长。可信离线管理方法不是用户认证 API，仍可处理已过期用户的撤权。
