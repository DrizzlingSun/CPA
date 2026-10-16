# Security Advisory: Authentication Fails Open When `api-keys` Is Empty or Absent

> **CVE ID:** Pending assignment（待分配）
> **Status:** Vendor notified on 2026-08-15 — no response received. Unfixed as of 2026-09-30; disclosed to MITRE and published on 2026-09-30. Exploit details intentionally omitted.
> **状态：** 已于 2026-08-15 通知厂商——未获回应。截至 2026-09-30 未修复；2026-09-30 向 MITRE 披露并公开本通告。刻意省略可被直接利用的细节。

---

## English Version

### Summary

When `api-keys` is empty or absent from the configuration, the config-access provider unregisters itself, the access manager returns `(nil, nil)` for zero providers, and the authentication middleware treats that as successful authentication and calls `c.Next()`. With the default `host: ""` (all interfaces), any anonymous network client can use the proxy and consume the operator's upstream credentials.

### Affected Product

| Item | Value |
|---|---|
| Product | CLIProxyAPI |
| Vendor | router-for-me (Router-For.ME) — open-source project |
| Vendor homepage | https://github.com/router-for-me/CLIProxyAPI |
| Affected version | v7.2.134 (commit `b8fbe70b`); all earlier versions presumed affected |
| Fixed version | None — unfixed as of 2026-09-30 |
| Affected component | Access provider registry (`internal/access/config_access`), access manager (`sdk/access`), authentication middleware (`internal/api/server_middleware.go`) |

### Severity

**CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N — 9.1 (Critical)** in the empty-keys state *(assessed by the reporters)*.

CVSS rationale: network-reachable by any client that can connect; low complexity (the attack only requires that `api-keys` be empty — a plausible operator mistake when removing the section or making a YAML error); no privileges required (that is the defect itself); no user interaction; unchanged scope; high confidentiality and integrity impact (full access to upstream credentials and proxy functionality); no direct availability impact (though upstream quotas can be drained).

CWE-287 / CWE-306 (reporter-suggested).

### Prerequisites

The operator must have actively produced an empty-key state: deleting or commenting out the `api-keys` section, or a YAML mistake that parses it as an empty array. This is not the published default, but "removing a section I believed was optional" is a plausible operator action. When it happens, the proxy starts bound to all interfaces with no authentication, logging only "0 API keys" without any warning. A safe-default design would treat zero providers as deny-by-default, or refuse to bind non-loopback interfaces without authentication.

### Impact

An anonymous network client can use the proxy and the operator's upstream credentials:

- **Credential consumption:** the attacker uses the operator's upstream API quota — direct financial loss in pay-per-token scenarios.
- **Data exposure:** requests and responses flow through the proxy; if logging is enabled (e.g., `request-log: true`), prompts and upstream responses land in the operator's logs. A confidentiality violation if the proxy or logs are compromised.
- **Compliance violations:** in regulated environments (healthcare, finance), anonymous external access to an LLM gateway violates data-handling policies.
- Combined with the separately reported management-boundary bypass, an attacker can additionally reach the management API even when nominally `allow-remote: false`.

In hosted/SaaS environments where the operator intended `api-keys` to gate access, this is a complete authentication bypass.

### Recommended Mitigations (reporter recommendations, pending vendor fix)

- Ensure `api-keys` contains at least one strong key before exposing the service; monitor startup logs for the "0 API keys" line, which currently indicates authentication is disabled.
- Bind `host` to loopback (`127.0.0.1` / `::1`) unless external access is required, and firewall the port from untrusted networks.
- Upstream: treat the zero-provider state as deny-by-default, warn loudly at startup, or refuse to bind non-loopback interfaces without authentication.

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

当配置中 `api-keys` 为空或不存在时，config-access 提供商注销自身，访问管理器对零提供商返回 `(nil, nil)`，认证中间件将其视为认证成功并调用 `c.Next()`。在默认 `host: ""`（绑定所有接口）下，任何匿名网络客户端都可以使用代理并消费运维人员的上游凭据。

### 受影响产品

| 项目 | 内容 |
|---|---|
| 产品 | CLIProxyAPI |
| 厂商 | router-for-me（Router-For.ME）—— 开源项目 |
| 厂商主页 | https://github.com/router-for-me/CLIProxyAPI |
| 受影响版本 | v7.2.134（commit `b8fbe70b`）；推测更早版本均受影响 |
| 修复版本 | 无 —— 截至 2026-09-30 尚未修复 |
| 受影响组件 | 访问提供商注册（`internal/access/config_access`）、访问管理器（`sdk/access`）、认证中间件（`internal/api/server_middleware.go`） |

### 严重程度

**CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N — 9.1（严重）**（空密钥状态下；由报告人评定）。

CVSS 依据：网络可达，任何能连接代理的客户端均可攻击；复杂度低（攻击仅要求 `api-keys` 为空——移除该节或 YAML 出错即可产生的合理运维失误）；无需权限（即缺陷本身）；无需用户交互；范围不变；机密性与完整性影响高（完全访问上游凭据与代理功能）；无直接可用性影响（尽管可能耗尽上游配额）。

CWE-287 / CWE-306（报告人建议）。

### 前置条件

运维人员必须主动产生空密钥状态：删除或注释掉 `api-keys` 节，或因 YAML 语法错误解析为空数组。这不是发布的默认配置，但"删除我认为可选的节"是合理的运维操作。一旦发生，代理绑定所有接口且无认证启动，仅记录"0 API keys"而不发出任何警告。安全默认设计会将零提供商视为默认拒绝，或拒绝在无认证的情况下绑定非回环接口。

### 影响

匿名网络客户端可以使用代理和运维人员的上游凭据：

- **凭据消费：** 攻击者使用运维人员的上游 API 配额。在按令牌付费的场景中，这是直接的财务损失。
- **数据暴露：** 请求和响应通过代理传递；若启用日志（如 `request-log: true`），攻击者的提示词与上游响应会记录在运维人员日志中。若代理或日志被攻陷或可访问，即构成机密性违规。
- **合规违规：** 在受监管环境（医疗保健、金融）中，允许匿名外部访问 LLM 网关违反数据处理政策。
- 与本系列另行报告的管理边界绕过结合时，攻击者即使面对名义上的 `allow-remote: false` 也能访问管理 API。

在运维人员打算用 `api-keys` 门控访问但配置错误的托管/SaaS 环境中，这是完全的认证绕过。

### 缓解建议（报告人建议，待厂商官方修复）

- 在暴露服务前确保 `api-keys` 至少包含一个强密钥；监控启动日志中的"0 API keys"行——当前它意味着认证已关闭。
- 除非确需外部访问，将 `host` 绑定到回环地址（`127.0.0.1` / `::1`），并用防火墙隔离不可信网络。
- 上游修复建议：将零提供商状态视为默认拒绝、启动时大声告警，或拒绝在无认证时绑定非回环接口。

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
