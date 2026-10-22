# 显式远程 MCP 测试

默认行为不变：入口与默认下游只使用回环 HTTP。以下开关专用于隔离网络中的合成测试，不是公网生产部署；代码不会配置防火墙、发布端口、自动签发证书或创建真实凭据。本人绑定页面本次仍只支持本地 HTTP。

## 1. 远程客户端访问网关

先按 [本人绑定预览](account-preview.md) 准备 owner-only 的合成配置，使每个入口 token 是无填充 base64url 编码的 32 字节值，并有非零到期时间。远程模式启动时还要求至少一个当前未禁用、未过期的身份；过期身份始终拒绝请求。格式检查不能证明 token 随机性，公开固定示例不得用于实际访问。

推荐使用测试环境已经准备好的证书和私钥：

```sh
./bin/gateway -config configs/private/account.json \
  -listen 0.0.0.0:8443 -allow-remote-test \
  -tls-cert configs/private/server-cert.pem \
  -tls-key configs/private/server-key.pem
```

客户端使用 `https://测试主机:8443/mcp`，配置本人 Authorization Bearer 请求头，并正常验证证书链和主机名。TLS 最低版本为 1.2，不提供跳过验证开关；测试 CA 必须由客户端明确、可信地配置。不要把监听用的 0.0.0.0 当作客户端目标地址。

确需明文测试时必须再显式开启：

```sh
./bin/gateway -config configs/private/account.json \
  -listen 0.0.0.0:8080 -allow-remote-test -allow-insecure-http-test
```

**明文 HTTP 不保护入口 token、工具参数或返回内容。仅使用隔离测试网络和虚构凭据。** 命令会输出固定警告，不打印秘密。`-allow-remote-test` 单独使用不会隐式启用明文模式；TLS 与明文许可开关不能混用。

监听地址必须是字面 IP；未开启远程测试时仍仅接受 127.0.0.1 或 ::1。远程模式的配置必须是 owner-only 普通文件，拒绝最终路径为符号链接；TLS 私钥同样要求 owner-only、普通且非符号链接文件。父目录仍须可信、私有且稳定。

`-account` 与远程模式或 TLS 参数明确互斥；本次开放的是 MCP 接口，不是远程账号门户。`/mcp` 仍拒绝浏览器 Origin，不允许通过任意页面跨站调用。所有新开关只用于 serve，离线管理操作即使显式指定 false 也会拒绝这些参数。原有 -db/-key-file 初始化、重开和失败关闭规则不变。

## 2. 网关访问远程下游

HTTPS 按 [受控网络策略](network-policy.md) 配置固定 endpoint、精确 allowed_ips 和必要的 trusted_ca_pem。若被测下游只有 HTTP，必须在该系统的 network 中额外声明：

```json
{
  "name": "test",
  "endpoint": "http://mcp.example.test:8080/mcp",
  "network": {
    "allowed_ips": ["192.0.2.10"],
    "allow_insecure_http": true
  }
}
```

这是格式示例，不指向真实服务。明文模式仍执行同样的固定 URL、完整 DNS 结果、数值拨号、IP 允许列表、禁止代理/重定向和元数据地址防护，但**不能加密下游凭据或流量**。HTTP 同时设置 trusted_ca_pem 会拒绝，因为 CA 不能保护明文连接。HTTPS 即使误带 allow_insecure_http=true，也仍必须验证 TLS，不会降级。

入口远程许可与下游网络策略是独立开关；启用一方不会放宽另一方。修改已持久化系统拓扑会拒绝重开，不自动覆写数据库；需要另选纯合成测试数据库或等待明确的迁移流程，不应删除旧状态来掩盖配置错误。

## 验证范围

回归测试只在回环地址实际监听，验证真实 TLS 入口、官方 MCP SDK 客户端发现/调用、未认证拒绝、错误 CA 拒绝、私有文件校验以及无效配置在监听/数据库写入前失败。通配/非回环地址仅验证参数解析，没有实际对外开放端口。跨主机网络连通性、真实证书部署和浏览器 GUI 验收均未执行。
