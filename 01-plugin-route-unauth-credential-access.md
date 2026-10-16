# Security Advisory: Plugin Resource Routes Expose Unauthenticated Credential Read/Write Interface

> **CVE ID:** Pending assignment（待分配）
> **Status:** Vendor notified on 2026-08-15 — no response received. Unfixed as of 2026-09-30; disclosed to MITRE and published on 2026-09-30. Exploit details intentionally omitted.
> **状态：** 已于 2026-08-15 通知厂商——未获回应。截至 2026-09-30 未修复；2026-09-30 向 MITRE 披露并公开本通告。刻意省略可被直接利用的细节。

---

## English Version

### Summary

CLIProxyAPI's global router serves `/v0/resource/plugins/<id>/...` routes through `ServeResourceHTTP`, which performs **no authentication by design** — as explicitly stated in both its doc comment and the `ResourceRoute` type comment. Separately, the plugin host exposes `host.auth.list` / `get` / `get_runtime` / `save` callbacks to **any** loaded plugin without any capability gating. The project ships a sample plugin (`examples/plugin/host-callback-auth-files`) that binds these callbacks to a resource route. Once an operator enables that plugin following its bundled `README.md`, any network client able to reach the port can list, fully read, and overwrite the OAuth credentials stored by the proxy — **without any key**.

### Affected Product

| Item | Value |
|---|---|
| Product | CLIProxyAPI |
| Vendor | router-for-me (Router-For.ME) — open-source project |
| Vendor homepage | https://github.com/router-for-me/CLIProxyAPI |
| Affected version | v7.2.134 (commit `b8fbe70b`); all earlier versions presumed affected |
| Fixed version | None — unfixed as of 2026-09-30 |
| Affected component | Plugin resource routing (`internal/api/server_management.go`, `internal/pluginhost`) and bundled example plugin (`examples/plugin/host-callback-auth-files`) |

### Severity

**CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N — 9.1 (Critical)** *(assessed by the reporters)*

CWE-306: Missing Authentication for Critical Function (reporter-suggested).

### Prerequisites

- The operator must have set `plugins.enabled: true` and loaded a plugin that registers a resource route (this is a selective, opt-in configuration; the affected sample plugin ships with the project).
- Given that, the attacker needs **no** credentials of any kind — no management key, no api-key, no local access. The default `host: ""` binds to all interfaces.

### Impact

An attacker able to reach the port can:

- **Exfiltrate** all stored upstream OAuth access/refresh tokens.
- **Implant** attacker-controlled credentials into the proxy's authentication store — allowing the attacker to route the victim operator's traffic to attacker-owned upstream accounts, or to plant credentials the proxy will later use.

This is the most severe finding in this report series; only the opt-in precondition keeps it from being unconditionally critical.

### Recommended Mitigations (reporter recommendations, pending vendor fix)

- Do not enable `plugins.enabled: true` on deployments reachable by untrusted clients until a fix is available.
- Remove / do not deploy the bundled `host-callback-auth-files` example plugin.
- Restrict network access to the service port (bind to loopback where possible; firewall the port from untrusted networks).

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

CLIProxyAPI 的全局调度器通过 `ServeResourceHTTP` 提供 `/v0/resource/plugins/<id>/...` 路由服务，该函数**按设计不进行认证**——其文档注释和 `ResourceRoute` 类型注释均明确说明了这一点。另一方面，插件宿主向**任何**已加载的插件暴露 `host.auth.list` / `get` / `get_runtime` / `save` 回调，且不做任何能力门控。项目随附了一个示例插件（`examples/plugin/host-callback-auth-files`），它将这些回调绑定到一条资源路由上。当运维人员按其随附的 `README.md` 的说明启用该插件后，任何能够访问该端口的网络客户端均可列出、完整读取并覆盖代理存储的 OAuth 凭据——**无需任何密钥**。

### 受影响产品

| 项目 | 内容 |
|---|---|
| 产品 | CLIProxyAPI |
| 厂商 | router-for-me（Router-For.ME）—— 开源项目 |
| 厂商主页 | https://github.com/router-for-me/CLIProxyAPI |
| 受影响版本 | v7.2.134（commit `b8fbe70b`）；推测更早版本均受影响 |
| 修复版本 | 无 —— 截至 2026-09-30 尚未修复 |
| 受影响组件 | 插件资源路由（`internal/api/server_management.go`、`internal/pluginhost`）及随附示例插件（`examples/plugin/host-callback-auth-files`） |

### 严重程度

**CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N — 9.1（严重）**（由报告人评定）

CWE-306：关键功能缺失认证（报告人建议）。

### 前置条件

- 运维人员必须已设置 `plugins.enabled: true` 并加载了一个注册资源路由的插件（属于选择性启用的配置；受影响的示例插件随项目一同发布）。
- 满足上述条件后，攻击者**无需任何凭据**——无需管理密钥、无需 api-key、无需本地访问。默认 `host: ""` 绑定所有接口。

### 影响

能够到达该端口的攻击者可以：

- **窃取**代理存储的所有上游 OAuth 访问令牌 / 刷新令牌。
- 向代理的认证存储中**植入**攻击者控制的凭据——后者允许攻击者将受害运维人员的流量路由至攻击者拥有的上游账户，或植入代理后续将使用的凭据。

这是本系列报告中最严重的发现；仅选择性启用的前置条件使其未达到无条件严重等级。

### 缓解建议（报告人建议，待厂商官方修复）

- 在修复发布前，不要在可被不可信客户端访问的部署上启用 `plugins.enabled: true`。
- 移除 / 不要部署随附的 `host-callback-auth-files` 示例插件。
- 限制对该服务端口的网络访问（尽可能绑定回环地址；用防火墙隔离不可信网络）。

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
