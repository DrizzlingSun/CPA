# Security Advisory: Management Interface `allow-remote: false` Boundary Bypass via Spoofed `X-Forwarded-For` Header

> **CVE ID:** Pending assignment（待分配）
> **Status:** Vendor notified on 2026-08-15 — no response received. Unfixed as of 2026-09-30; disclosed to MITRE and published on 2026-09-30. Exploit details intentionally omitted.
> **状态：** 已于 2026-08-15 通知厂商——未获回应。截至 2026-09-30 未修复；2026-09-30 向 MITRE 披露并公开本通告。刻意省略可被直接利用的细节。

---

## English Version

### Summary

The Gin engine is created via `gin.New()`, and `SetTrustedProxies` is never called in non-test code. Gin's default behavior — trusting all proxies (`0.0.0.0/0`, `::/0`) — therefore takes effect, and `c.ClientIP()` returns the attacker-supplied `X-Forwarded-For` value. The management middleware treats `clientIP == "127.0.0.1" || clientIP == "::1"` as "local", and local callers are exempt from the `allow-remote: false` restriction. A remote, directly connected caller who sends an `X-Forwarded-For` header containing a loopback address is treated as local and thereby reaches the management interface the operator configured for local-only access.

### Affected Product

| Item | Value |
|---|---|
| Product | CLIProxyAPI |
| Vendor | router-for-me (Router-For.ME) — open-source project |
| Vendor homepage | https://github.com/router-for-me/CLIProxyAPI |
| Affected version | v7.2.134 (commit `b8fbe70b`); all earlier versions presumed affected |
| Fixed version | None — unfixed as of 2026-09-30 |
| Affected component | Management middleware (`internal/api/handlers/management/handler.go`), Gin engine initialization (`internal/api/server.go`); dependency `github.com/gin-gonic/gin` v1.10.1 |

### Severity

**CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L — 7.3 (High)** *(assessed by the reporters)*

CWE-348 (Use of Less Trusted Source) / CWE-290 (Authentication Bypass by Spoofing) — reporter-suggested.

### Prerequisites

The attacker only needs the ability to send an HTTP request to the proxy's listening port. No credentials are required for the boundary bypass itself. The default `host: ""` binds all interfaces.

An operator deploys with `remote-management.allow-remote: false`, relying on the bundled example configuration documentation, which states that this option restricts the management interface to local access only. A spoofed loopback value in `X-Forwarded-For` defeats that boundary; reaching the actual management operations additionally requires a valid management key (the boundary bypass itself is unauthenticated — the difference between a `403 remote management disabled` and a `401 invalid management key` response proves the boundary was crossed).

### Impact

- The `allow-remote: false` management boundary is rendered ineffective: a remote attacker who also holds the correct management key can operate the full management API remotely.
- The response-difference oracle (`403` vs `401`) lets an unauthenticated remote attacker confirm the bypass and probe for key validity.

### Recommended Mitigations (reporter recommendations, pending vendor fix)

- Restrict network access to the management port (bind to loopback; firewall from untrusted networks) — do not rely on `allow-remote: false` alone.
- Upstream: configure trusted proxies explicitly (`SetTrustedProxies` / `TrustedPlatform` / `RemoteIPHeaders`) or disable proxy-header trust, and do not exempt loopback-valued `X-Forwarded-For` from the remote-management check.

### References

- Project repository: https://github.com/router-for-me/CLIProxyAPI

### Credit

Vulnerability reported by [DrizzlingSun](https://github.com/DrizzlingSun) & [jgj212](https://github.com/jgj212) of Asiainfo-sec.

### Disclosure Timeline

| Date | Event |
|---|---|
| 2026-08-15 | Reported to the vendor (router-for-me) |
| — | No vendor response received |
| 2026-09-30 | Disclosed to MITRE (CVE requested); this public advisory published |

---

## 中文版本

### 摘要

Gin 引擎通过 `gin.New()` 创建，且非测试代码中从未调用过 `SetTrustedProxies`，因此 Gin 的默认行为——信任所有代理（`0.0.0.0/0`、`::/0`）——生效，`c.ClientIP()` 会返回攻击者提供的 `X-Forwarded-For` 值。管理中间件将 `clientIP == "127.0.0.1" || clientIP == "::1"` 视为"本地"，而本地调用者可豁免 `allow-remote: false` 限制。远程直连的调用者发送携带回环地址的 `X-Forwarded-For` 头即被视为本地，从而访问到运维人员配置为仅限本地访问的管理接口。

### 受影响产品

| 项目 | 内容 |
|---|---|
| 产品 | CLIProxyAPI |
| 厂商 | router-for-me（Router-For.ME）—— 开源项目 |
| 厂商主页 | https://github.com/router-for-me/CLIProxyAPI |
| 受影响版本 | v7.2.134（commit `b8fbe70b`）；推测更早版本均受影响 |
| 修复版本 | 无 —— 截至 2026-09-30 尚未修复 |
| 受影响组件 | 管理中间件（`internal/api/handlers/management/handler.go`）、Gin 引擎初始化（`internal/api/server.go`）；依赖 `github.com/gin-gonic/gin` v1.10.1 |

### 严重程度

**CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L — 7.3（高）**（由报告人评定）

CWE-348（使用可信度较低的数据源）/ CWE-290（通过欺骗绕过认证）—— 报告人建议。

### 前置条件

攻击者只需要能向代理的监听端口发送 HTTP 请求。边界绕过本身无需凭据。默认 `host: ""` 绑定所有接口。

运维人员以 `remote-management.allow-remote: false` 部署，依据随附示例配置文档——该文档声明此选项将管理接口限制为仅限本地访问。`X-Forwarded-For` 中伪造的回环值即可击穿该边界；实际操作管理功能还需正确的管理密钥（边界绕过本身无需认证——`403 remote management disabled` 与 `401 invalid management key` 的响应差异即可证明边界已被突破）。

### 影响

- `allow-remote: false` 管理边界失效：同时持有正确管理密钥的远程攻击者可远程操作完整的管理 API。
- 响应差异探测（`403` 与 `401`）使未认证的远程攻击者能够确认绕过成功并探测密钥有效性。

### 缓解建议（报告人建议，待厂商官方修复）

- 限制对管理端口的网络访问（绑定回环地址、防火墙隔离不可信网络）——不要单独依赖 `allow-remote: false`。
- 上游修复建议：显式配置受信代理（`SetTrustedProxies` / `TrustedPlatform` / `RemoteIPHeaders`）或禁用代理头信任，并且不将 `X-Forwarded-For` 中的回环值豁免于远程管理检查。

### 参考

- 项目仓库：https://github.com/router-for-me/CLIProxyAPI

### 致谢

漏洞报告人：[DrizzlingSun](https://github.com/DrizzlingSun) & [jgj212](https://github.com/jgj212) of Asiainfo-sec。

### 披露时间线

| 日期 | 事件 |
|---|---|
| 2026-08-15 | 向厂商（router-for-me）报告 |
| — | 厂商未回应 |
| 2026-09-30 | 向 MITRE 披露并申请 CVE；公开本通告 |
