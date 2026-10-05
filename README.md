# FastAPI 会话与作用域访问控制

基于 FastAPI 的本地可验证会话与访问控制服务：会话凭据的签发/轮换/失效、
默认拒绝的授权判定、按来源的失败限流与临时锁定，以及请求追踪、本地审计
查询与运行期状态观测。全部状态为进程内存储，不依赖任何外部服务、真实凭据
或付费资源。

## 架构

```
main.py               应用工厂 create_app()，装配配置/中间件/异常处理器/路由
app/config.py         运行参数（环境变量可覆盖，缺省保持既有默认行为）
app/errors.py         RejectionReason 枚举 + AccessDeniedError（统一异常链路）
app/models.py         Session / Resource / AuthzDecision 数据模型
app/session_store.py  进程内会话仓库（签发、校验、轮换、撤销，线程安全）
app/authz.py          默认拒绝授权器（作用域 + 归属双条件）
app/rate_limit.py     按来源失败计数、限流与临时锁定（线程安全）
app/audit.py          有界审计存储（单调序号、筛选分页、容量淘汰，线程安全）
app/tracing.py        请求追踪中间件 + 统一错误结构 + 未预期异常兜底
app/routes.py         HTTP 路由，把上述能力接入请求处理与异常链路
```

## 请求追踪

- 每个进入服务的请求都分配一个稳定追踪标识 `trace_id`，通过响应头
  `X-Trace-Id` 返回——无论请求成功、被凭据/授权/限流拒绝，还是触发未预期异常。
- 所有错误分支（凭据拒绝、授权拒绝、限流、内部异常兜底）响应体结构一致：
  `{"error": <reason>, "detail": <说明>, "trace_id": <标识>}`，
  且 `trace_id` 与响应头 `X-Trace-Id` 相同。
- 未预期异常统一返回 500 `{"error": "internal_error", ...}`，不泄露堆栈或
  内部细节；完整堆栈连同同一 `trace_id` 记入服务端日志，可按标识回查。

## 本地审计查询

每一次访问判定（签发、轮换、撤销、资源访问的放行与各类拒绝）都会写入本地
审计存储，记录：单调递增 `seq`、时间戳 `ts`、`trace_id`、来源 `source`、
主体 `subject`、动作 `action`、目标资源 `resource_id`、结果 `outcome`
（allowed/denied）、判定依据 `reason` 与附加信息 `detail`。

```
GET /audit?start_ts=&end_ts=&subject=&outcome=&offset=0&limit=100
```

- 支持按时间范围、主体、结果筛选，`offset`/`limit` 分页；返回
  `{"total": <命中总数>, "records": [...]}`，按 `seq` 升序（即写入顺序）。
- 并发写入在同一把锁内完成：不丢、不重，`seq` 即全局写入顺序。
- 容量有界（默认 10000 条），写满后淘汰最旧记录并累计 `evicted` 计数；
  审计存储与会话、失败计数、锁定状态完全独立，淘汰不影响任何在生效的状态。

## 运行期状态观测

```
GET /status?source=<可选，缺省为请求来源>
```

只读返回，不暴露凭据：

```json
{
  "source": "127.0.0.1",
  "locked": false,
  "locked_until": null,
  "active_sessions": 3,
  "audit": {"size": 12, "capacity": 10000, "evicted": 0, "total_appended": 12}
}
```

- `locked` / `locked_until`：该来源是否锁定、何时恢复（epoch 秒）。
- `active_sessions`：当前有效会话数（未撤销、未轮换、未过期）。
- `audit`：审计存储占用（当前条数/容量/已淘汰条数/累计写入条数）。

## 运行参数配置（环境变量）

| 环境变量 | 含义 | 默认值 |
|---|---|---|
| `SAC_SESSION_TTL_SECONDS` | 会话有效期（秒） | `3600` |
| `SAC_MAX_FAILURES` | 连续失败锁定阈值 | `5` |
| `SAC_LOCKOUT_SECONDS` | 锁定时长（秒） | `30` |
| `SAC_AUDIT_CAPACITY` | 审计记录容量上限 | `10000` |

未设置时保持既有默认行为不变；`create_app(...)` 的显式参数优先于环境变量，
便于测试按需覆盖。

## 凭据轮换与失效规则

- **签发**：`POST /sessions`，返回 `token` 与 `expires_at`（默认 TTL 3600s）。
- **校验**：请求头 `X-Session-Token`。拒绝原因可区分：
  - `credential_missing`（401）未提供凭据
  - `credential_unknown`（401）凭据不存在
  - `credential_expired`（401）凭据已过期
  - `credential_revoked`（401）凭据已被撤销
  - `credential_rotated`（401）凭据已被轮换取代
- **轮换**：`POST /sessions/rotate`。旧凭据立即失效（后续使用得到
  `credential_rotated`），新凭据继承原 subject/roles/scopes 并重置 TTL。
  "校验旧凭据 + 标记轮换 + 登记新凭据"在同一把锁内完成，因此**同一凭据的
  并发轮换恰好只有一次成功**；失败方收到 `credential_rotated`，且不会获得
  任何可用凭据。
- **撤销**：`POST /sessions/revoke`，撤销后凭据得到 `credential_revoked`。

## 授权模型（默认拒绝）

访问 `GET /resources/{id}` 需**同时**满足两个条件，否则拒绝：

1. **作用域**：会话 scopes 包含资源要求的 scope（`admin` 角色隐含全部作用域）；
2. **归属**：资源 owner 等于会话 subject（`admin` 角色豁免）。

- 作用域不足 → 403 `forbidden_role`
- 跨归属访问 → 403 `forbidden_ownership`
- 资源不存在 → 404 `resource_not_found`

越权与不存在的响应均不含资源内容（不返回 `owner` 等字段），不泄露资源是否
存在。每次判定生成 `AuthzDecision`（allowed/reason/matched_scope/matched_owner）
并写入审计，测试日志中打印输入、判定依据与结果，可复现。

## 限流与锁定策略

- 按来源（客户端 IP）计数：凭据校验失败与授权失败各计一次，成功访问清零。
- 连续失败达到 `max_failures`（默认 5）即锁定 `lockout_seconds`（默认 30s），
  锁定期间该来源请求直接得到 429 `rate_limited`。
- 锁定到期后自动恢复（惰性清除），恢复时机 = 锁定截止时刻。
- 计数读写在同一把锁内完成，并发下不重复、不丢失；各来源相互隔离，
  单个来源的异常不影响其他来源。

## 本地验证

```bash
uv sync                 # 安装依赖（含 dev 组 pytest/httpx）
uv run pytest           # 运行全部测试（日志直接打印各用例的业务场景与结果）
uv run uvicorn main:app # 本地启动服务
```

手工验证示例：

```bash
# 签发
TOKEN=$(curl -s -X POST localhost:8000/sessions \
  -H 'Content-Type: application/json' \
  -d '{"subject":"alice","roles":["user"],"scopes":["doc:read"]}' | jq -r .token)
# 访问自有资源 -> 200（响应头含 X-Trace-Id）
curl -si localhost:8000/resources/doc-1 -H "X-Session-Token: $TOKEN"
# 访问他人资源 -> 403 forbidden_ownership（响应体含 trace_id）
curl -s localhost:8000/resources/doc-2 -H "X-Session-Token: $TOKEN"
# 轮换后旧凭据 -> 401 credential_rotated
curl -s -X POST localhost:8000/sessions/rotate \
  -H 'Content-Type: application/json' -d "{\"token\":\"$TOKEN\"}"
# 审计查询：只看被拒绝的判定
curl -s 'localhost:8000/audit?outcome=denied&limit=10'
# 状态观测：当前来源锁定情况、有效会话数、审计占用
curl -s localhost:8000/status
# 环境变量配置示例
SAC_MAX_FAILURES=3 SAC_AUDIT_CAPACITY=100 uv run uvicorn main:app
```

## 测试覆盖

- `tests/test_sessions.py`：签发/校验、过期、撤销、轮换后旧凭据拒绝、
  重复使用旧凭据轮换、16 路并发轮换恰好一次成功。
- `tests/test_authz.py`：放行、缺作用域、跨归属、不存在不泄露、admin 豁免。
- `tests/test_rate_limit.py`：阈值锁定与恢复、成功清零、50 路并发计数精确、
  来源隔离。
- `tests/test_api.py`：端到端凭据生命周期、越权/不存在响应形态、
  12 路并发轮换、限流锁定与恢复。
- `tests/test_tracing.py`：成功与各类失败分支的追踪标识一致性、响应结构
  统一、未预期异常的兜底形态与日志回查。
- `tests/test_audit.py`：审计写入与单调序号、筛选分页、容量淘汰、
  8 线程并发写入不丢不重、淘汰不影响会话与限流状态。
- `tests/test_status.py`：状态观测（锁定/恢复时刻、有效会话数、审计占用、
  不暴露凭据）。
- `tests/test_config.py`：环境变量配置的默认值兼容、覆盖与显式参数优先级。
