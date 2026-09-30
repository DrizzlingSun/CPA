# Security Advisory: OAuth Credentials and Configuration Files Created World-Readable, Defeating the 0700 Intent

> **CVE ID:** Pending assignment（待分配）
> **Status:** Vendor notified on 2026-08-15 — no response received. Unfixed as of 2026-09-30; disclosed to MITRE and published on 2026-09-30. Exploit details intentionally omitted.
> **状态：** 已于 2026-08-15 通知厂商——未获回应。截至 2026-09-30 未修复；2026-09-30 向 MITRE 披露并公开本通告。刻意省略可被直接利用的细节。

---

## English Version

### Summary

Five provider-credential serializers and two configuration writers create files with `os.Create`, which requests mode 0666 (before umask) and commonly yields 0644. Each of the five call sites is preceded by `os.MkdirAll(dir, 0700)` — but the service already creates the authentication directory with mode 0o755 at startup, and `MkdirAll` does not modify an existing directory, so the 0700 never takes effect. The result is a world-traversable directory holding world-readable files containing long-lived OAuth access/refresh tokens, Vertex service-account private key material, the plaintext provider `api-keys` list, and the `remote-management.secret-key` hash.

### Affected Product

| Item | Value |
|---|---|
| Product | CLIProxyAPI |
| Vendor | router-for-me (Router-For.ME) — open-source project |
| Vendor homepage | https://github.com/router-for-me/CLIProxyAPI |
| Affected version | v7.2.134 (commit `b8fbe70b`); all earlier versions presumed affected |
| Fixed version | None — unfixed as of 2026-09-30 |
| Affected component | Provider credential serializers (`internal/auth/{claude,codex,vertex,xai,kimi}`), configuration writers (`internal/config/config_yaml.go`, `internal/api/handlers/management/config_basic.go`), auth-directory creation (`sdk/cliproxy/service_lifecycle.go`) |

### Severity

**CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N — 6.5 (Medium)** *(assessed by the reporters)*

CWE-732: Incorrect Permission Assignment for Critical Resource (reporter-suggested).

### Prerequisites

Ability to execute code as any unprivileged local user on the host running the proxy.

### Impact

Any local unprivileged user can obtain the long-lived OAuth refresh tokens of all configured upstream providers, Vertex service-account private keys, the proxy's own `api-keys`, and the management-key hash. Refresh tokens can be used directly against provider token endpoints, entirely independently of this proxy — revoking the proxy's access does not contain the leak.

### Recommended Mitigations (reporter recommendations, pending vendor fix)

- Until a fix is available, manually tighten permissions after each provider login: `chmod 700` on the auth directory and `chmod 600` on the credential files; consider a restrictive umask for the service.
- Upstream: create credential/config files with 0600 (as the project's own stores `internal/store/objectstore.go`, `gitstore.go`, `postgresstore.go` already do), create the auth directory with 0700, and reconcile the mode of pre-existing directories.

### References

- Project repository: https://github.com/router-for-me/CLIProxyAPI

### Credit

Vulnerability reported by [DrizzlingSun](https://github.com/DrizzlingSun) and [jgj212](https://github.com/jgj212).

### Disclosure Timeline

| Date | Event |
|---|---|
| 2026-08-15 | Reported to the vendor (router-for-me) |
| — | No vendor response received |
| 2026-09-30 | Disclosed to MITRE (CVE requested); this public advisory published |

---

## 中文版本

### 摘要

五个提供商凭据序列化器和两个配置写入器均使用 `os.Create` 创建文件，该调用请求模式 0666（umask 之前）并依赖 umask，在常见默认值下产生 0644。这五个调用点的上一行均为 `os.MkdirAll(dir, 0700)`——但服务在启动时已以 0o755 模式创建了认证目录，而 `MkdirAll` 不会修改已存在的目录，因此 0700 永远不会生效。结果是一个全局可遍历的目录中存放着全局可读的文件，其中包含长期有效的 OAuth 访问令牌和刷新令牌、Vertex 服务账户私钥材料、明文提供商 `api-keys` 列表以及 `remote-management.secret-key` 哈希。

### 受影响产品

| 项目 | 内容 |
|---|---|
| 产品 | CLIProxyAPI |
| 厂商 | router-for-me（Router-For.ME）—— 开源项目 |
| 厂商主页 | https://github.com/router-for-me/CLIProxyAPI |
| 受影响版本 | v7.2.134（commit `b8fbe70b`）；推测更早版本均受影响 |
| 修复版本 | 无 —— 截至 2026-09-30 尚未修复 |
| 受影响组件 | 提供商凭据序列化器（`internal/auth/{claude,codex,vertex,xai,kimi}`）、配置写入器（`internal/config/config_yaml.go`、`internal/api/handlers/management/config_basic.go`）、认证目录创建（`sdk/cliproxy/service_lifecycle.go`） |

### 严重程度

**CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N — 6.5（中等）**（由报告人评定）

CWE-732：关键资源权限分配不当（报告人建议）。

### 前置条件

能够以运行代理的主机上的任意非特权本地用户身份执行代码。

### 影响

任何本地非特权用户均可获取所有已配置上游提供商的长期 OAuth 刷新令牌、Vertex 服务账户私钥、代理自身的 `api-keys` 以及管理密钥哈希。刷新令牌可直接用于访问提供商的令牌端点，完全独立于此代理——撤销代理访问权限无法遏制泄露。

### 缓解建议（报告人建议，待厂商官方修复）

- 修复发布前，每次提供商登录后手动收紧权限：认证目录 `chmod 700`、凭据文件 `chmod 600`；可为服务设置严格 umask。
- 上游修复建议：以 0600 创建凭据/配置文件（项目自身的 `internal/store/objectstore.go`、`gitstore.go`、`postgresstore.go` 已如此），以 0700 创建认证目录，并校正已存在目录的模式。

### 参考

- 项目仓库：https://github.com/router-for-me/CLIProxyAPI

### 致谢

漏洞报告人：[DrizzlingSun](https://github.com/DrizzlingSun)、[jgj212](https://github.com/jgj212)。

### 披露时间线

| 日期 | 事件 |
|---|---|
| 2026-08-15 | 向厂商（router-for-me）报告 |
| — | 厂商未回应 |
| 2026-09-30 | 向 MITRE 披露并申请 CVE；公开本通告 |
