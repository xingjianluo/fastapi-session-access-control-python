# FastAPI 会话与作用域访问控制

基于 FastAPI 的本地可验证会话与访问控制服务：会话凭据的签发/轮换/失效、
默认拒绝的授权判定、按来源的失败限流与临时锁定。全部状态为进程内存储，
不依赖任何外部服务、真实凭据或付费资源。

## 架构

```
main.py               应用工厂 create_app()，注册追踪中间件、异常处理器与路由
app/config.py         运行参数配置（环境变量 -> Settings，缺省回退默认值）
app/errors.py         RejectionReason 枚举 + AccessDeniedError（统一异常链路）
app/models.py         Session / Resource / AuthzDecision 数据模型
app/session_store.py  进程内会话仓库（签发、校验、轮换、撤销，线程安全）
app/authz.py          默认拒绝授权器（作用域 + 归属双条件）
app/rate_limit.py     按来源失败计数、限流与临时锁定（线程安全）
app/audit.py          本地审计日志（容量上限、FIFO 淘汰、筛选分页，线程安全）
app/tracing.py        请求追踪标识（contextvar 传递）
app/routes.py         HTTP 路由 + 只读运维端点，把上述能力接入请求处理与异常链路
```

所有拒绝都通过 `AccessDeniedError` 进入 FastAPI 异常处理器，响应结构统一为
`{"error": <reason>, "detail": <说明>, "trace_id": <追踪标识>}`，`error` 取值即可区分的拒绝原因。

## 请求追踪

- 每个请求都有稳定的追踪标识：所有响应（成功/拒绝/异常）都带 `X-Trace-Id`
  响应头；错误响应体中同时含 `trace_id` 字段，与响应头一致。
- 调用方可通过请求头 `X-Trace-Id` 传入自己的标识（非空即被沿用），否则服务端
  自动生成。
- 未预期异常统一返回 `500 {"error": "internal_error", "detail": "服务内部错误",
  "trace_id": ...}`，不暴露堆栈与内部细节；堆栈只写入服务端日志，并挂在同一个
  `trace_id` 下，可按标识关联查询。
- 每条审计记录都带 `trace_id`，可用响应中的标识在 `/ops/audit` 里查到同一次判定。

## 本地审计查询

每一次访问判定（签发/轮换/撤销/资源访问，无论放行或拒绝）都会写入进程内审计
日志，记录：序号 `seq`、追踪标识、时间戳、来源、主体、动作、目标资源、判定结果
与依据说明。

```
GET /ops/audit?since=<ts>&until=<ts>&subject=<主体>&outcome=<结果>&offset=0&limit=50
```

- 全部筛选参数可选；`since`/`until` 为 Unix 时间戳（闭区间），`subject`/`outcome`
  精确匹配；`offset`/`limit` 分页（`limit` 上限 500），响应含 `total` 便于翻页。
- 写入在锁内完成：并发下不丢、不重，`seq` 单调递增且与写入顺序一致，结果按
  `seq` 升序返回。
- 容量上限 `audit_capacity`（默认 10000），满时 FIFO 淘汰最旧记录；淘汰只影响
  审计数据本身，不影响会话、失败计数或锁定状态。

## 运行状态观测

```
GET /ops/status?source=<来源IP>
```

只读返回：指定来源的锁定状态与恢复时刻（`locked`/`locked_until`，不传 `source`
则省略）、当前有效会话数（未撤销/未轮换/未过期）、审计存储占用
（`capacity`/`size`/`evicted`/`next_seq`）。不返回任何凭据内容。

## 运行参数配置

以下参数可通过环境变量配置，未配置（或值为空/非法）时保持既有默认行为：

| 环境变量 | 含义 | 默认值 |
| --- | --- | --- |
| `SESSION_TTL_SECONDS` | 会话有效期（秒） | `3600` |
| `RATE_LIMIT_MAX_FAILURES` | 连续失败锁定阈值 | `5` |
| `RATE_LIMIT_LOCKOUT_SECONDS` | 锁定时长（秒） | `30` |
| `AUDIT_CAPACITY` | 审计记录容量上限 | `10000` |

`create_app()` 的显式入参优先于环境变量，便于测试构造不同参数的实例。

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
存在。每次判定生成 `AuthzDecision`（allowed/reason/matched_scope/matched_owner），
测试日志中打印输入、判定依据与结果，可复现。

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
uv run pytest           # 运行全部测试（-s 打印判定日志）
uv run uvicorn main:app # 本地启动服务
```

手工验证示例：

```bash
# 签发
TOKEN=$(curl -s -X POST localhost:8000/sessions \
  -H 'Content-Type: application/json' \
  -d '{"subject":"alice","roles":["user"],"scopes":["doc:read"]}' | jq -r .token)
# 访问自有资源 -> 200
curl -s localhost:8000/resources/doc-1 -H "X-Session-Token: $TOKEN"
# 访问他人资源 -> 403 forbidden_ownership
curl -s localhost:8000/resources/doc-2 -H "X-Session-Token: $TOKEN"
# 轮换后旧凭据 -> 401 credential_rotated
curl -s -X POST localhost:8000/sessions/rotate \
  -H 'Content-Type: application/json' -d "{\"token\":\"$TOKEN\"}"
# 查看审计（可按 subject/outcome/时间范围筛选、offset/limit 分页）
curl -s 'localhost:8000/ops/audit?subject=alice&limit=10' | jq
# 查看运行状态（锁定情况、有效会话数、审计占用）
curl -s 'localhost:8000/ops/status?source=127.0.0.1' | jq
# 用响应头中的 X-Trace-Id 反查本次请求对应的审计记录
```

## 测试覆盖

- `tests/test_sessions.py`：签发/校验、过期、撤销、轮换后旧凭据拒绝、
  重复使用旧凭据轮换、16 路并发轮换恰好一次成功。
- `tests/test_authz.py`：放行、缺作用域、跨归属、不存在不泄露、admin 豁免。
- `tests/test_rate_limit.py`：阈值锁定与恢复、成功清零、50 路并发计数精确、
  来源隔离。
- `tests/test_api.py`：端到端凭据生命周期、越权/不存在响应形态、
  12 路并发轮换、限流锁定与恢复。
- `tests/test_tracing.py`：成功/凭据拒绝/授权拒绝/限流/未预期异常下的追踪标识
  一致性、调用方传入标识的沿用、追踪标识与审计记录的关联。
- `tests/test_audit.py`：审计写入与结果序列、筛选与分页、容量淘汰不影响会话与
  限流状态、16 路并发写入计数精确、单元级 FIFO 淘汰顺序。
- `tests/test_ops.py`：状态端点（锁定与恢复时刻、有效会话数、审计占用、不暴露
  凭据）、环境变量覆盖与默认值兼容。

测试运行时通过 `-s` 与 `log_cli` 输出各用例的业务场景、判定依据与结果日志。
