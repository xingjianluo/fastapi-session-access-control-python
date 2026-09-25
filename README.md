# FastAPI 会话与作用域访问控制（本地可验证）

在现有 FastAPI 服务的请求处理与异常链路内，实现一套**仅依赖本地内存**的会话凭据与默认拒绝授权能力，覆盖：

- 会话凭据的签发、轮换与失效（过期 / 已撤销 / 已轮换，拒绝原因可区分）；
- 默认拒绝的授权判定（角色/作用域 **且** 资源归属，越权不泄露资源是否存在）；
- 按来源的连续失败限流与临时锁定（并发计数不重不漏、来源隔离、恢复时机确定）；
- 每次判定都留下包含“输入 / 判定依据 / 结果”的审计记录，可复现。

无外部服务、无数据库、无真实凭据、无付费资源；所有状态都是进程内数据结构。

## 快速开始

```bash
uv sync --group dev          # 安装 fastapi + pytest/httpx
uv run pytest                # 运行全部 35 个用例（带判定日志）
uv run python main.py        # 启动服务（默认 127.0.0.1:8000）
```

## 规则说明

### 1. 凭据轮换与失效规则

- 凭据为不透明随机 token（`secrets.token_urlsafe`，仅本地使用），签发时记录
  `issued_at / expires_at / version`，默认有效期 300 秒。
- 认证与轮换时按以下**固定优先级**给出可区分的拒绝原因：

  | 状态 | reason | HTTP |
  | --- | --- | --- |
  | 未携带凭据 | `missing_credential` | 401 |
  | 存储中不存在 | `credential_unknown` | 401 |
  | 已撤销（`revoked`） | `credential_revoked` | 401 |
  | `now >= expires_at` | `credential_expired` | 401 |
  | 已被轮换（`superseded`） | `credential_rotated` | 401 |

  撤销优先级高于过期，保证同一输入永远得到同一结论。
- **轮换（`POST /auth/rotate`）**：在会话存储的同一把锁内原子完成
  “校验旧凭据 → 旧凭据标记 `superseded` → 写入新凭据”。
  因此同一凭据的并发轮换**恰好一次成功**；失败方得到 `credential_rotated`，
  响应体不含任何新凭据。新凭据 `version` 沿轮换链递增，并通过
  `previous_token` 指向上一代，可追溯。
- 已过期 / 已撤销 / 已轮换的凭据都不能再认证或再轮换；撤销接口幂等。

### 2. 授权模型（默认拒绝）

受保护资源 `GET /resources/{resource_id}` 必须**同时**满足：

1. 已通过凭据认证；
2. 资源存在，且 `resource.owner == principal.subject`（归属一致）；
3. 拥有资源声明的角色与作用域（AND 语义；未声明的条件不检查）。

任一不满足即拒绝：

- 角色/作用域不足：`forbidden_role_or_scope`，HTTP 403；
- **跨归属访问与资源不存在对外完全一致**：统一
  `resource_not_found` / HTTP 404 / 相同 message，无法据此枚举资源；
  真实原因 `forbidden_ownership` 只写入审计记录，可事后复现。

内置演示资源（进程内）：`doc-alice`、`doc-bob`（需 `doc:read` 且归属匹配）、
`doc-admin`（需 `admin` 角色且 `doc:write` 作用域，归属 alice）。

### 3. 限流与临时锁定策略

- 以 `X-Source-ID` 请求头标识来源（缺省回退客户端 IP），每个来源独立计数。
- 连续失败（认证失败、轮换失败、越权/跨归属等授权失败）计数；
  达到阈值（默认 5，测试中为 3）后立即锁定该来源 `LOCKOUT_SECONDS` 秒（默认 30）。
- 锁定期间所有请求以 `source_locked` / HTTP 429 拒绝，**即使凭据正确也不放行**；
  锁定期内继续失败不会把解锁时间向后推（恢复时机确定）。
- 到达 `locked_until` 后的下一次请求自动解除锁定并清零计数；
  未锁定时一次成功的认证也会清零连续失败数。
- 每个来源一把独立锁：并发失败计数不重不漏；单个来源被锁或发生异常不影响其他来源。
  签发端点 `POST /auth/sessions` 不要求认证，不计入失败。

### 4. 判定依据与异常链路

- 每个请求由中间件生成 `request_id`（响应头 `X-Request-ID` 回传）。
- 认证、轮换、限流、授权各阶段都向进程内环形缓冲
  （`AuditLog`，默认 1024 条）写入一条 `DecisionRecord`，
  同时通过 logging 打印，字段包含：来源、主体、动作、资源、
  `evidence`（TTL 比较值、角色/作用域命中情况、归属、失败计数与锁定时刻等）、
  `decision=allow/deny`、`reason`。
- 所有拒绝都抛 `AccessControlError`，由统一异常处理器输出
  `{"error": {"request_id", "reason", "message"}}`，状态码与原因一一对应。
- 本地辅助端点：`GET /_local/audit?request_id=...&source=...` 查看判定依据；
  `GET /_local/status/{source}` 查看来源失败计数与锁定状态。

## HTTP 接口

| 方法/路径 | 说明 |
| --- | --- |
| `POST /auth/sessions` | 签发凭据，body：`{subject, roles[], scopes[]}` |
| `POST /auth/rotate` | 轮换当前 Bearer 凭据（并发恰好一次成功） |
| `POST /auth/revoke` | 撤销凭据（Bearer 或 body `{token}`，幂等） |
| `GET /resources/{id}` | 受保护资源读取（认证 + 角色/作用域 + 归属） |
| `GET /_local/audit` | 本地审计记录查询 |
| `GET /_local/status/{source}` | 本地来源限流状态查询 |

## 本地验证示例

```bash
# 签发
TOK=$(curl -s -X POST localhost:8000/auth/sessions \
  -H 'Content-Type: application/json' -H 'X-Source-ID: demo' \
  -d '{"subject":"alice","roles":["reader"],"scopes":["doc:read"]}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# 访问自己的资源 -> 200
curl -s -H "Authorization: Bearer $TOK" -H 'X-Source-ID: demo' \
  localhost:8000/resources/doc-alice

# 轮换 -> 旧凭据再用得到 401 credential_rotated
NEW=$(curl -s -X POST -H "Authorization: Bearer $TOK" -H 'X-Source-ID: demo' \
  localhost:8000/auth/rotate | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# 越权访问 bob 的资源 -> 404 resource_not_found（与不存在不可区分）
curl -s -H "Authorization: Bearer $NEW" -H 'X-Source-ID: demo' \
  localhost:8000/resources/doc-bob
```

## 策略配置（环境变量）

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `SESSION_TTL_SECONDS` | 300 | 凭据有效期 |
| `FAILURE_THRESHOLD` | 5 | 连续失败多少次后锁定 |
| `LOCKOUT_SECONDS` | 30 | 锁定时长 |
| `SOURCE_HEADER` | X-Source-ID | 来源标识请求头 |
| `AUDIT_CAPACITY` | 1024 | 进程内审计缓冲容量 |

## 测试

```bash
uv run pytest                          # 全部用例，打印输入/依据/结果
uv run pytest -k concurrent            # 并发轮换与并发计数
uv run pytest tests/test_api.py -q     # HTTP 链路集成用例
```

覆盖场景：凭据过期、撤销、轮换后重复使用、凭据缺失/未知、并发轮换唯一成功、
跨归属越权、资源不存在不可区分、角色/作用域不足、连续失败锁定、
锁定期满恢复、并发失败计数不重不漏、来源隔离、审计记录可复现。

## 代码结构

```
accesscontrol/
  config.py      策略配置（环境变量覆盖）
  errors.py      可区分拒绝原因 + 统一异常与状态码映射
  store.py       线程安全进程内会话存储（原子更新原语）
  sessions.py    凭据签发 / 认证 / 轮换 / 撤销
  ratelimit.py   逐来源失败计数与临时锁定
  authz.py       Principal/Resource 与默认拒绝授权判定
  audit.py       决策记录环形缓冲 + 结构化日志
  app.py         FastAPI 装配、中间件、依赖链、异常处理器、演示数据
tests/           单元与 HTTP 集成测试（可控时钟、并发屏障）
main.py          uvicorn 入口
```
