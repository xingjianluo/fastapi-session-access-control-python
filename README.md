# FastAPI 会话与作用域访问控制

基于 FastAPI 的本地可验证会话与访问控制服务：会话凭据的签发/轮换/失效、
默认拒绝的授权判定、按来源的失败限流与临时锁定。全部状态为进程内存储，
不依赖任何外部服务、真实凭据或付费资源。

## 架构

```
main.py               应用工厂 create_app()，注册异常处理器与路由
app/errors.py         RejectionReason 枚举 + AccessDeniedError（统一异常链路）
app/models.py         Session / Resource / AuthzDecision 数据模型
app/session_store.py  进程内会话仓库（签发、校验、轮换、撤销，线程安全）
app/authz.py          默认拒绝授权器（作用域 + 归属双条件）
app/rate_limit.py     按来源失败计数、限流与临时锁定（线程安全）
app/routes.py         HTTP 路由，把上述能力接入请求处理与异常链路
```

所有拒绝都通过 `AccessDeniedError` 进入 FastAPI 异常处理器，响应结构统一为
`{"error": <reason>, "detail": <说明>}`，`error` 取值即可区分的拒绝原因。

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
```

## 测试覆盖

- `tests/test_sessions.py`：签发/校验、过期、撤销、轮换后旧凭据拒绝、
  重复使用旧凭据轮换、16 路并发轮换恰好一次成功。
- `tests/test_authz.py`：放行、缺作用域、跨归属、不存在不泄露、admin 豁免。
- `tests/test_rate_limit.py`：阈值锁定与恢复、成功清零、50 路并发计数精确、
  来源隔离。
- `tests/test_api.py`：端到端凭据生命周期、越权/不存在响应形态、
  12 路并发轮换、限流锁定与恢复。
