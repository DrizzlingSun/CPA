# Security Advisory: Unbounded Pre-Authentication zstd Decompression Enables Unauthenticated Denial of Service

> **CVE ID:** Pending assignment（待分配）
> **Status:** Vendor notified on 2026-08-15 — no response received. Unfixed as of 2026-09-30; disclosed to MITRE and published on 2026-09-30. Exploit details intentionally omitted.
> **状态：** 已于 2026-08-15 通知厂商——未获回应。截至 2026-09-30 未修复；2026-09-30 向 MITRE 披露并公开本通告。刻意省略可被直接利用的细节。

---

## English Version

### Summary

The request-logging middleware (`internal/api/middleware/request_logging.go`) performs an **unbounded** `io.ReadAll` on a zstd decoder for any request body labeled `Content-Encoding: zstd`. This runs in middleware **before route authentication**. An attacker can send a small decompression bomb (e.g., 1 MB compressed → 10 GB decompressed) and exhaust memory, causing denial of service. The decompression path is active when the operator sets `request-log: true` in the configuration. Although this is not the default mode, it is a supported configuration option that operators may enable for debugging or logging purposes — and once enabled, the vulnerability becomes exploitable **without authentication**.

### Affected Product

| Item | Value |
|---|---|
| Product | CLIProxyAPI |
| Vendor | router-for-me (Router-For.ME) — open-source project |
| Vendor homepage | https://github.com/router-for-me/CLIProxyAPI |
| Affected version | v7.2.134 (commit `b8fbe70b`) when `request-log: true` is enabled; all earlier versions presumed affected |
| Fixed version | None — unfixed as of 2026-09-30 |
| Affected component | Request-logging middleware (`internal/api/middleware/request_logging.go`) — pre-authentication request-body capture and zstd decoding |

### Severity

**CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H — 7.5 (High)** *(assessed by the reporters)*

The attack vector is network-accessible and requires no authentication (decompression happens in middleware ahead of the authentication check). Attack complexity is low: a standard HTTP client can send the required `Content-Encoding: zstd` header and compressed payload. The impact is high availability loss via memory exhaustion, potentially crashing or hanging the service.

The vulnerability exists in a supported configuration mode (`request-log: true`). Although not enabled by default, this is a legitimate operating mode users may enable — not an unsupported or undocumented feature.

CWE-409 (Improper Handling of Highly Compressed Data — Zip Bomb) and CWE-400 (Uncontrolled Resource Consumption), per the original report.

### Prerequisites

- The operator must have enabled `request-log: true` (a supported configuration option used for debugging/auditing).
- The attacker needs only network reachability to the service port — no valid API key, credentials, or prior access.

### Impact

- **Availability:** unauthenticated denial of service via memory exhaustion — process crash (OOM kill), unresponsiveness under GC pressure, resource starvation for legitimate requests, and cascading failure if multiple instances are targeted. Attackers can amplify cheaply: roughly 1 MB of attacker bandwidth per request can force 1+ GB of allocation; concurrent requests multiply the pressure.
- **Operational risk:** operators who enable `request-log: true` for debugging or auditing are unlikely to know this configuration exposes a pre-authentication resource-exhaustion vector. The option carries no warning, and there is no documented guidance to place the proxy behind a body-size-limiting gateway when this mode is enabled.
- Textbook zip-bomb economics: the decompression ratio is bounded only by what the attacker can transmit and what zstd can achieve; 1000:1 or higher ratios are practical.

### Recommended Mitigations (reporter recommendations, pending vendor fix)

- Do not enable `request-log: true` on instances reachable from untrusted networks until a fix is available.
- Place the service behind a gateway that enforces request-body size limits.
- Upstream: bound decompression (a size-limited reader variant already exists in-tree for another code path) and apply it to the request-logging path.

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

请求日志中间件（`internal/api/middleware/request_logging.go`）对任何标记为 `Content-Encoding: zstd` 的请求体在 zstd 解码器上执行**无上限**的 `io.ReadAll`，该操作在中间件中运行，**先于路由认证**。攻击者可以发送一个小型压缩炸弹（例如 1 MB 压缩 → 10 GB 解压）并耗尽内存，导致拒绝服务。当运维人员在配置中设置 `request-log: true` 时，解压中间件处于活动状态。虽然这不是默认模式，但它是运维人员可能为了调试或日志记录目的而启用的受支持配置选项——一旦启用，该漏洞在**无需认证**的情况下即可被利用。

### 受影响产品

| 项目 | 内容 |
|---|---|
| 产品 | CLIProxyAPI |
| 厂商 | router-for-me（Router-For.ME）—— 开源项目 |
| 厂商主页 | https://github.com/router-for-me/CLIProxyAPI |
| 受影响版本 | v7.2.134（commit `b8fbe70b`，启用 `request-log: true` 时）；推测更早版本均受影响 |
| 修复版本 | 无 —— 截至 2026-09-30 尚未修复 |
| 受影响组件 | 请求日志中间件（`internal/api/middleware/request_logging.go`）—— 认证前的请求体捕获与 zstd 解码 |

### 严重程度

**CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H — 7.5（高）**（由报告人评定）

攻击向量网络可达且无需认证（解压发生在认证检查之前的中间件中）。攻击复杂度低：标准 HTTP 客户端即可发送所需的 `Content-Encoding: zstd` 头和压缩负载。影响为内存耗尽导致的高可用性损失，可能使服务崩溃或无响应。

该漏洞存在于受支持的配置模式（`request-log: true`）中。虽然默认未启用，但这是用户可能启用的合法运行模式，而非不受支持或未记录的功能。

CWE-409（压缩数据处理不当 —— Zip 炸弹）与 CWE-400（不受控制的资源消耗），依据原报告。

### 前置条件

- 运维人员必须已启用 `request-log: true`（用于调试/审计的受支持配置项）。
- 攻击者只需要能到达服务端口的网络路径——无需有效 API 密钥、凭据或先前访问。

### 影响

- **可用性：** 通过内存耗尽实现的未认证拒绝服务——进程崩溃（OOM kill）、内存压力下的无响应（GC 抖动）、合法请求资源匮乏，以及多实例被攻击时的级联故障。攻击者可以低成本放大：每请求约 1 MB 攻击带宽可强制 1 GB 以上内存分配；并发请求成倍增加压力。
- **操作风险：** 为调试或审计启用 `request-log: true` 的运维人员可能不知道此配置会暴露认证前资源耗尽向量。该选项没有任何警告，也没有文档指导在启用此模式时服务应置于具备请求体大小限制的网关之后。
- 教科书式压缩炸弹经济学：解压比仅受攻击者可传输量与 zstd 算法能力限制；1000:1 或更高的比率是实际的。

### 缓解建议（报告人建议，待厂商官方修复）

- 在修复发布前，不要在可被不可信网络访问的实例上启用 `request-log: true`。
- 将服务置于强制限制请求体大小的网关之后。
- 上游修复建议：为解压设置上限（代码树内已存在带大小限制的读取器变体，供另一条代码路径使用），并将其应用到请求日志路径。

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
