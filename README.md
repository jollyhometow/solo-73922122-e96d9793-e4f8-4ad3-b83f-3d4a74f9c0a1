# DNS-01 挑战托管服务

面向 Linux 服务维护人员**并行申请证书**的场景：多个证书签发流程同时需要完成 ACME
DNS-01 挑战时，由本服务统一托管 `_acme-challenge` 的 TXT 记录——及时发布、到期/取消
自动撤回，并保证多个申请的值共存、互不覆盖。

- **单 API 进程 + 独立 worker 进程**：API 只读写 SQLite 并立即返回；所有 DNS 网络等待
  都在 worker 中进行，因此**网络等待不会阻塞取消**。
- **dnspython + TSIG** 对固定权威 DNS 做 RFC 2136 动态更新，只精确增删本模块发布的 TXT。
- **SQLite（WAL）** 保存申请、有效期、发布注册表与运行期开关；崩溃/丢回执后**重查续办**。
- 完整的就绪/撤回 DNS 实况核对，失败保留待办、显示原因并指数退避自动重试。

## 目录结构

```
app/
  config.py      # 环境变量配置（密钥、白名单、TTL 边界、DNS/TSIG、退避、故障开关）
  domain.py      # 域名/TXT 校验、记录名、内容指纹、退避（纯标准库）
  store.py       # SQLite 持久层：申请状态机、发布注册表、引用计数、故障开关
  dns_client.py  # dnspython TSIG 动态更新与 TXT 查询（幂等增删、多值共存）
  worker.py      # 独立后台进程：发布、就绪确认、撤回、对账续办、自动重试
  main.py        # FastAPI：申请/取消/状态/核对/故障开关/健康检查，/docs
  schemas.py     # pydantic v2 请求/响应模型
  cli.py         # worker 命令行入口（python -m app.cli）
bind/            # 本地权威 BIND9 配置（TSIG、acme.test 区域、入口脚本）
tests/           # 5 套测试（领域/持久层/端到端/API/真实进程），python -I 可跑
Dockerfile       # API/worker 同一镜像
Dockerfile.bind  # 本地 BIND 权威 DNS 镜像
docker-compose.yml
.env.example
```

## 快速开始（Docker Compose，含本地 BIND）

```bash
cp .env.example .env          # 按需修改 MANAGEMENT_KEY / TSIG_SECRET
docker compose up --build -d
# 交互式文档：可直接在页面演示申请、取消、状态查询
xdg-open http://127.0.0.1:8080/docs
curl -s http://127.0.0.1:8080/health
```

栈包含三个服务：

| 服务 | 进程 | 职责 |
| --- | --- | --- |
| `bind` | BIND9 权威 DNS | 固定权威，持有 `acme.test`，仅接受 TSIG 动态更新 |
| `api` | uvicorn（单 API 进程） | HTTP 接口、鉴权、读写 SQLite，**不做 DNS 网络等待** |
| `worker` | `python -m app.cli`（独立进程） | 独占 DNS 写入；`restart: unless-stopped` 保证崩溃后续办 |

API 与 worker 共享命名卷 `dnsdata` 上的同一个 SQLite。容器以非 root 运行，
`read_only` 根文件系统、`no-new-privileges`、drop 全部 capabilities（BIND 仅额外
保留绑定端口所需能力）。

宿主机可用 dig 经映射端口核对 BIND（`127.0.0.1:5353`）：

```bash
dig +short TXT _acme-challenge.host1.acme.test @127.0.0.1 -p 5353
```

## 核心 API

所有写接口需携带管理密钥：请求头 `X-Management-Key: <key>` 或
`Authorization: Bearer <key>`，恒定时间比较。

### 1. 提交申请（幂等）

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/challenges \
  -H "X-Management-Key: $MANAGEMENT_KEY" -H 'Content-Type: application/json' \
  -d '{"application_id":"cert-0001","domain":"host1.acme.test",
       "txt_value":"KwrTq74fJq8xQ1pV2mN3lK9aBcDeFgHiJkLmNoPqRsTu",
       "ttl_seconds":120}'
```

- `domain` 必须在白名单（`ALLOWED_DOMAINS`，支持精确域与 `*.suffix` 通配），否则 403。
- `ttl_seconds` 闭区间 **[30, 300]**，越界 422。
- **同 `application_id` 同内容重试**：幂等返回当前状态，**不延长有效期**。
- **同 ID 异内容**（域名/TXT/TTL 不同）：返回 **409 拒绝**。
- 内容指纹 = SHA256(规范化域名, TXT 值, TTL)。

### 2. 取消（不被网络阻塞）

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/challenges/cert-0001/cancel \
  -H "X-Management-Key: $MANAGEMENT_KEY" -H 'Content-Type: application/json' -d '{}'
```

取消只在数据库翻转状态并立即返回：尚未发布的直接 `cancelled`；发布中/已就绪的进入
`withdrawing`，由 worker 清理 DNS。worker 在每次网络调用前后核对申请版本号，
**发布途中取消或到期后，迟到的网络结果无法复活申请**。

### 3. 状态与 DNS 核对

```bash
curl -s http://127.0.0.1:8080/api/v1/challenges/cert-0001          # 状态
curl -s http://127.0.0.1:8080/api/v1/challenges                     # 列表
curl -s http://127.0.0.1:8080/api/v1/challenges/cert-0001/verify    # 直查权威 DNS
```

`/verify` 返回权威 DNS 当前该记录名下**全部** TXT（含他方值）、本值是否真实存在、
是否由本模块发布。**就绪必须查到本值；结束必须确认本值已撤回或仍被其它有效申请使用。**

## 状态机

```
pending ──worker认领──▶ publishing ──查到本值──▶ ready
   │                        │                     │
   │（未发布即取消）         └────取消/到期────────┤
   ▼                                             ▼
cancelled                                  withdrawing ──确认撤回/仍被引用──▶ withdrawn
```

到期由 worker 周期性把 `pending/publishing/ready` 翻转为 `withdrawing`（置 expired 标记）。
任何 DNS 步骤失败都会保留待办、写入 `last_error`、按指数退避（`RETRY_BASE_DELAY` 起，
封顶 `RETRY_MAX_DELAY`）自动重试。

## 多值共存与安全撤回

- 新增按精确 RDATA 幂等添加，**多个申请的 TXT 值在同一记录名下共存**。
- `dns_publications` 只登记本模块真正发布过的 `(记录名, 值)`。
- 撤回时仅当某值**已无任何有效申请引用**（pending/publishing/ready 且未到期，排除撤回中的
  自身）才精确删除该 RDATA；仍被引用则保留 TXT 并结束本申请。
- 同名的其它 TXT（含外部系统发布的）**永不触碰**。

## 崩溃、丢回执与重启续办

worker 启动及运行中会周期性**重查权威 DNS 对账**：

- DNS 已更新但回执丢失（注册表无记录）→ 补登记并据 DNS 实况补确认 `ready`。
- 注册表有记录但 DNS 已无该值 → 清除孤儿登记，交回正常流程重试。
- 注册表中的孤儿发布（已无申请引用）→ 安全撤回并清理。
- 进程在发布途中退出 → 重启后重查续办，版本号保证迟到结果不复活已取消/到期申请。

### 故障注入开关（演示用）

```bash
# lost_receipt: 0 关 | 1 DNS 接受更新但丢弃回执 | 2 丢回执并令 worker 退出(模拟崩溃)
curl -s -X POST http://127.0.0.1:8080/api/v1/admin/faults \
  -H "X-Management-Key: $MANAGEMENT_KEY" -H 'Content-Type: application/json' \
  -d '{"lost_receipt":1,"delay_seconds":0.5}'
curl -s http://127.0.0.1:8080/api/v1/admin/faults     # 读取
```

- `lost_receipt=1` 演示“**更新生效后丢回执**”：下一轮/重启经重查续办恢复。
- `lost_receipt=2` 演示“**进程退出**”：worker `os._exit(70)`，compose 的
  `restart: unless-stopped` 拉起后重查续办。
- `delay_seconds` 在每次 DNS 调用前额外睡眠，模拟权威 DNS **延迟回复**（验证取消不被阻塞）。

开关存于 SQLite（`kv_config`），运行期可改、重启保留；环境变量 `FAULT_LOST_RECEIPT` /
`FAULT_DELAY_SECONDS` 仅作初始默认值。

## 配置（环境变量）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `MANAGEMENT_KEY` | dev-management-key | 写接口管理密钥 |
| `DATABASE_PATH` | /data/challenges.db | SQLite 路径（API/worker 共享） |
| `ALLOWED_DOMAINS` | acme.test,*.acme.test | 域名白名单，逗号分隔，支持 `*.suffix` |
| `MIN_TTL_SECONDS` / `MAX_TTL_SECONDS` | 30 / 300 | 有效期边界 |
| `DNS_SERVER` / `DNS_PORT` | bind / 53 | 固定权威 DNS |
| `TSIG_KEY_NAME` / `TSIG_SECRET` / `TSIG_ALGORITHM` | acme-key. / … / hmac-sha256 | TSIG 凭据 |
| `DNS_UPDATE_TIMEOUT` / `DNS_QUERY_TIMEOUT` | 5 / 4 | DNS 调用超时（秒） |
| `WORKER_POLL_INTERVAL` | 1.0 | worker 轮询间隔 |
| `READY_POLL_INTERVAL` / `READY_POLL_MAX` | 1.0 / 5 | 就绪/撤回确认轮询间隔与上限 |
| `RETRY_BASE_DELAY` / `RETRY_MAX_DELAY` | 2 / 30 | 失败自动重试退避 |
| `FAULT_LOST_RECEIPT` / `FAULT_DELAY_SECONDS` | 0 / 0 | 故障开关初始值 |

## 本地 Python 运行（不用 Docker）

```bash
pip install -r requirements.txt
# 需要一个可达的权威 DNS；可先用 tests/fake_dns_server.py 起一个内存伪权威
DATABASE_PATH=./data/challenges.db DNS_SERVER=127.0.0.1 DNS_PORT=<port> \
  TSIG_SECRET=<b64> uvicorn app.main:app --host 127.0.0.1 --port 8080   # API
DATABASE_PATH=./data/challenges.db DNS_SERVER=127.0.0.1 DNS_PORT=<port> \
  TSIG_SECRET=<b64> python -m app.cli                                   # worker
```

## 测试

无需 Docker/BIND；端到端与进程测试内置一个实现 RFC 2136 子集 + TSIG 校验的内存伪权威
DNS，走 dnspython 真实协议路径。

```bash
python3 -I tests/test_domain.py    # 领域校验/指纹/白名单/退避（31 项）
python3 -I tests/test_store.py     # SQLite 状态机/版本防护/引用计数（38 项）
python3 -I tests/test_e2e.py       # 伪 DNS 端到端：共存/撤回/丢回执/孤儿/TSIG（28 项）
python3 -I tests/test_api.py       # FastAPI + 真实 worker 线程（35 项）
python3 -I tests/test_process.py   # 真实独立进程：崩溃重启续办、优雅停止（19 项）
```

## 设计边界

- 区域名取域名最右两级（演示用固定策略）；接入多区域权威时可在 `domain.zone_of` 扩展。
- TXT 值按单条 RDATA ≤255 字符校验；ACME DNS-01 令牌通常远小于该上限。
- 就绪/撤回确认采用有界轮询（`READY_POLL_MAX`），超时即记为失败并整体自动重试，
  避免无限等待；权威 DNS 的传播延迟由重试覆盖。
- 伪权威 DNS 仅用于测试，生产请使用 compose 中的 BIND 或对接既有 TSIG 权威。
