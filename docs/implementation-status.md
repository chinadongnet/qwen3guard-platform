# P0 / P1 交付状态与功能有效性核查清单

更新：2026-10-25。本表汇总当前平台版本 `3.0.0`（运行入口 `http://127.0.0.1:8092/dashboard` 及局域网 HTTP 控制台）中**已生效可用**与**尚未开发完成（已在控制台界面置灰 `disabled` + `待开发` 标签）**的全部功能。原版功能映射见 [功能覆盖表](feature-coverage.md)，全量 GPU 质量回归见 [全量模型质量验收](model-quality-acceptance.md)。

## 一、已有效并完整闭环的功能清单（✅ 可直接使用）

| 模块 / 页面 | 已生效功能 | 后端接口 / 核心实现 |
| --- | --- | --- |
| **登录与账户权限** | 管理员与成员登录、会话 Cookie + CSRF 校验、登录限流、修改个人密码（撤销该用户全部活跃会话）、项目创建、项目成员角色分配（`admin` / `operator` / `developer` / `auditor`）、新增成员账户 | `/api/admin/auth/*`、`/api/admin/projects/*`、`/api/admin/users`（`admin.py`、`security.py`） |
| **Native GPU 与局域网部署** | Windows 原生 RTX 3090 GPU 加速启动、后台异步非阻塞加载三模型（`Qwen3-0.6B`、`Qwen3Guard-Gen-0.6B`、`Qwen3Guard-Stream-0.6B`）、`transformers 5.x` RoPE/pad_token 兼容补丁、非 HTTPS 局域网 IP 访问下的 UUID 生成与剪贴板降级兼容 | `start.ps1`、`app/model_manager.py`、`app/console/api.js` |
| **运营总览 (`overview`)** | 按生产/沙盒环境及 24h / 7d / 30d 时间窗统计真实检测条目、检测成功率、P50/P95/P99 耗时、阻断数与阻断率、待处理风险事件数、最近检测列表（自动排除评测与历史未知数据） | `GET /api/admin/overview`（`admin.py`） |
| **应用接入 (`applications`)** | 创建业务应用、编辑应用设置（名称、生产/沙盒环境、绑定已发布策略）、启用/停用应用、控制台在线验证接入（沙盒隔离）；API Key 创建（仅首次显示明文、仅存哈希）、列表脱敏、RPM 额度与暂停/恢复设置、密钥轮换（24h 过渡期）、立即撤销 | `/api/admin/applications/*`、`/api/admin/keys/*`（`admin.py`） |
| **检测记录 (`detections`)** | 按应用 ID、凭证 ID、Request ID、决策、来源、归档状态筛选与游标分页；查看检测详情；受控调阅加密原文（限角色、留痕、默认 7 天过期返回 410）；追加人工复核；沉淀为题库样本；JSON / CSV 导出（防公式注入）；当前页归档与恢复 | `/api/admin/detections/*`、`/api/admin/workbench/detections/*`、`/audit/*`（`admin.py`、`workbench.py`） |
| **安全策略 (`policies`)** | 创建策略草稿、新建不可变版本、查看版本配置与差异对比、发布门禁（首次可直接发布，后续新版本须完成带标签回归评测且全部通过方可发布，历史已发布版本可回滚）；支持风险阈值、PII 动作（`block`/`mask`/`audit`）、超时、失败处置、流式窗口、争议内容开关与附加拦截词 | `/api/admin/policies/*`（`admin.py`、`service.py`） |
| **API 资产 (`endpoints`)** | 注册外部 OpenAI 兼容模型端点（SSRF 地址校验、DNS 固定、内网白名单校验、Fernet 凭证加密存储）、端点连接测试、供后台评测任务拉取目标模型回复 | `/api/admin/endpoints/*`（`admin.py`、`network.py`） |
| **评测任务 (`evaluations`)** | 创建评测任务（直接文本审核回归 / 外部 API 回复评测 / 候选策略版本门禁评测）、幂等键防重、单协调器微批异步执行、任务取消（`cancel`）与中断/失败恢复（`resume`）、查看评测详情 | `/api/admin/evaluations/*`（`admin.py`、`tasks.py`） |
| **风险事件 (`incidents`)** | 阻断或待复核请求自动生成风险事件、查看关联检测证据与复核时间线、指派负责人并追加复核状态（`investigating` / `resolved` / `false_positive` / `open`） | `/api/admin/incidents/*`（`admin.py`、`service.py`） |
| **题库管理 (`qbank`)** | 一键导入原始精选库（142 条）与完整库（1607 条）、自定义 JSON 批量导入/新增题目、导出题库 JSON；多维筛选与分页；题目编辑（乐观锁 `expected_revision` 防并发冲突）、版本历史查看与一键恢复、归档与恢复；选中题目或全库发起文本回归 / 批量生成对比评测 | `/api/admin/workbench/banks/*`、`/cases/*`（`workbench.py`） |
| **提示词调测 (`tuning`)** | 四种行业/场景预设载入、恢复默认草稿、原版测试样例填入、ChatML Prompt 编译预览、Baseline vs Candidate 同输入真实 GPU A/B 对比、保存为策略新版本草稿 | `/api/admin/workbench/presets`、`/prompt-preview`、`/ab-test`（`workbench.py`） |
| **检测与攻防 (`inspector`)** | 单轮/多轮文本审核实验、Stream 模型离线 Token 染色与截断位点诊断、裸模型 vs 护栏生成同屏对比、反混淆与脱敏工具、持久化实验记录查询 | `/api/admin/workbench/token-scan`、`/compare-generation`、`/deobfuscate`、`/runs`（`workbench.py`） |
| **评测报告 (`reports`)** | 实时凭证审计对账汇总、按审核对象/来源题库/TC260 子类/攻击方法分层统计、逐题结果筛选与证据查看、两次评测任务 Baseline vs Candidate 对比、导出 JSON / CSV / Markdown、打印/保存 PDF、查看旧版只读历史报告 | `/api/admin/workbench/reports/*`、`/audit/summary`、`/history/benchmark`（`workbench.py`） |
| **API 在线调试与开发者中心** | 12 个 `/v1/*` 数据面接口在线调试、可视化参数与 Raw JSON 切换、OpenAPI 契约查看、SSE 流式响应实时读取与取消、5 语言（Python/cURL/Node/Go/Java）代码生成与复制、会话保护的 `/docs` 与 `/openapi.json` | `app/console/workbench.js`、`app/enterprise/data_api.py` |
| **系统管理 (`settings`)** | 实时 GPU/显存/三模型状态、推理队列占用、数据库状态；告警 Webhook 新增（HMAC-SHA256 签名密钥单次展示）、停用、Outbox 投递记录与自动重试（最多 5 次）；项目操作审计日志；`/health/live` 与 `/health/ready` 探针 | `/api/admin/system`、`/webhooks/*`、`/operations`、`/health/*`（`admin.py`、`tasks.py`） |

---

## 二、尚未开发完成并在前端置灰的功能清单（🚧 已置灰 `待开发`）

以下功能尚未开发完成（或仅有部分底层预留而未完成端到端闭环），已在控制台对应位置**置灰显示（`disabled` + `待开发` 徽标与悬浮说明）**，防止误导操作：

| 所属模块 / 页面 | 未开发完成功能 | 当前后端与前端状态 | 控制台置灰位置 | 对应 Backlog 编号 |
| --- | --- | --- | --- | --- |
| **全局侧边栏 / 多模态** | **多模态内容审核（图片/OCR、音频/ASR、视频抽帧、PDF/Office 文档）** | 后端 `/api/admin/system` 标记 `image/audio/video/document: todo`；`/v1/guard/detect` 对非 `text` 请求直接返回 `422` | 左侧导航栏“规划中（待开发）”、系统管理“模块与多模态能力状态”面板、开发者中心、检测与攻防实验室 | `M01`～`M06` |
| **全局侧边栏 / 可观测性** | **Prometheus / OpenTelemetry 指标暴露与分阶段耗时** | 尚未提供 `/metrics` 接口；`timings_ms` 仅含 `total` 与 `model_reported`，未拆分 `queue` 与 `rules` 耗时 | 左侧导航栏“Prometheus 监控（待开发）” | `P1 / O01` |
| **全局侧边栏 / 身份治理** | **企业 SSO / OIDC 单点登录与组织同步** | 仅支持本地数据库账号密码认证，未实现 OIDC 登录与企业组织权限映射 | 左侧导航栏“SSO 与组织治理（待开发）”、系统管理顶部“SSO / OIDC（待开发）”按钮 | `P2 / S03` |
| **安全策略 (`policies`)** | **策略按比例灰度发布与异常自动回滚** | 仅支持全量发布切换与手动回滚，未实现流量百分比灰度与指标触发自动回滚 | 策略卡片底部操作栏“灰度发布（待开发）”置灰按钮 | `P1 / P01` |
| **安全策略 (`policies`)** | **结构化自动放行白名单覆盖规则** | 旧版自定义允许词为空实现（`pass`）已移除；新结构化白名单规则尚未开发 | 安全策略页顶部“自动白名单规则（待开发）”置灰按钮 | `R10` |
| **API 资产 (`endpoints`)** | **在线业务 Chat 自动路由转发至外部上游 API 及重试** | 已登记的 API 端点仅用于连接测试与后台评测任务，`/v1/chat/completions` 仅调用本地模型，未接入上游业务代理转发 | API 资产页顶部“业务网关上游路由（待开发）”及端点列表操作列“设为 Chat 上游（待开发）”置灰按钮 | `R09` |
| **API 资产 (`endpoints`)** | **API 资产端点编辑与启停切换** | 数据库 `model_endpoints` 含 `enabled` 字段，但未开发修改 URL/模型/凭证及切换启停的后端接口与弹窗 | API 资产列表操作列“编辑（待开发）”、“停用（待开发）”置灰按钮 | `P1 / U02、E01` |
| **评测任务 (`evaluations`)** | **Cron 定时周期自动评测** | 仅支持手动提交评测任务，未实现定时调度器与独立周期预算 | 评测任务页顶部“定时周期评测（待开发）”置灰按钮 | `P1 / E02` |
| **评测任务 / 题库管理** | **独立盲测集 (Holdout) 隔离与多人协同标注流转** | 目前仅支持 `curated` / `full` / `custom` 三类题库及单人 JSON 编辑，未实现 Holdout 盲测权限隔离与多人标注审核工作流 | 评测任务页“独立盲测集 Holdout（待开发）”按钮、题库管理页“多人协同标注（待开发）”按钮及题库下拉框置灰项 | `P1 / E03`、`R11b`、`Q06` |
| **检测与攻防 (`inspector`)** | **在线生成流式护栏接入 Stream 模型实时逐 Token 熔断** | 在线 `/v1/chat/completions` 使用 `Gen` 模型按累积字符窗口审核；`Stream` 模型目前仅用于离线完整文本 Token 诊断回放 | 检测与攻防页“实验类型”下拉框中“在线生成 Stream 实时逐 Token 熔断（待开发 D05）”置灰选项 | `P1 / D05` |
| **风险事件 (`incidents`)** | **风险事件超时自动升级与 SLA 规则** | 支持生成事件、指派负责人与人工追加复核，尚未实现超时自动升级规则 | 风险事件页顶部“自动升级规则（待开发）”置灰按钮 | `P1 / A02` |
| **开发者中心 (`developers`)** | **独立封装的官方多语言 SDK 发布包** | 已提供 5 语言标准 HTTP/SSE 调用代码生成，尚未发布独立封装的 pip/npm/go/maven SDK 包 | 开发者中心顶部“官方 SDK 包下载（待开发）”置灰按钮 | `P1 / C01` |
| **系统管理 (`settings`)** | **成员账户列表展示与启停前端管理** | 后端已实现 `GET /api/admin/users` 与 `PUT /api/admin/users/{id}/enabled`，但前端尚未完成成员列表管理与启停界面 | 系统管理顶部“账户启停管理（待开发）”置灰按钮 | `P1 / U02` |
| **系统管理 (`settings`)** | **主密钥 (`PLATFORM_SECRET`) 在线轮换重加密工具** | 加密数据依赖 `PLATFORM_SECRET`，尚未提供在线解密并重加密历史数据的迁移工具 | 系统管理顶部“主密钥轮换（待开发）”置灰按钮 | `P0 / O03` |
| **系统管理 (`settings`)** | **Webhook 通知模板配置、手动连通性测试与失败投递人工重投** | 支持新增/停用 Webhook 及后台最多 5 次自动重试，未实现报文模板定制、一键测试发送与人工重投 | 系统管理“告警 Webhook”及“最近投递”面板中的“通知模板配置”、“测试发送”、“人工重投”置灰按钮 | `P1 / A02` |
| **系统管理 / 架构扩展** | **多实例分布式任务租约与 Redis 共享限流** | 当前固定为单进程协调器 (`single-coordinator`) 与数据库原子计数，不支持多 worker 并发或多副本水平扩展 | 系统管理“模块与多模态能力状态”面板置灰行 | `P2 / O02` |

---

## 三、已交付工作项映射（历史基线）

| Todo | 当前交付 | 主要代码 |
| --- | --- | --- |
| F01、S01 | 模块化应用工厂、用户会话、CSRF、项目成员及角色、管理与业务身份分离 | `app/enterprise/application.py`、`security.py` |
| F02、A01 | PostgreSQL 持久化；检测、操作、复核、通知记录；旧 JSON 备份与幂等导入 | `db.py`、`scripts/migrate_legacy.py` |
| S02 | API Key 只展示一次、仅存哈希、权限域、到期、撤销、轮换、应用禁用和共享额度 | `security.py`、`admin.py` |
| D01、D02、D03 | 严格请求校验、模型异常不判安全；移除题库标签和“正常样本”覆盖；有界推理队列、超时后保留真实占用、数据库原子额度计数 | `service.py`、`inference.py`、`app/security_shield.py` |
| U01～U03 | 登录、项目/环境切换、应用与凭证、在线测试、隔离审计、真实总览、权限与空态 | `app/console/` |
| P01、D04 | 不可变策略版本、差异、评测发布门禁、并发发布校验、回滚；多轮上下文与 PII 阻断/脱敏/审计 | `admin.py`、`schemas.py`、`service.py` |
| D05 | 真实逐步生成 → 累积窗口审核 → 释放已审核内容；违规截断、超时/断连终止审计 | `data_api.py`、`app/model_manager.py` |
| E01、E02 | 企业 API 登记、凭证加密、SSRF 地址校验与 DNS 固定、连接测试；后台逐项评测、输入加密、快照、幂等、取消/中断恢复 | `network.py`、`tasks.py` |
| E03（部分） | 真实任务样本量、错误数、TP/TN/FP/FN、召回及误报率；标签仅用于结果比较 | `admin.py` |
| A02 | 风险事件、指派与追加复核；签名 Webhook outbox、重试、投递状态、稳定 delivery_id | `service.py`、`tasks.py` |
| C01、O01（部分） | 会话保护 OpenAPI、接口示例、明确支持子集；存活/就绪探针、真实检测指标 | `application.py`、控制台开发者中心 |
| Q01 | 无 GPU 的权限/契约/故障回归，CI；独立真实 GPU 验收脚本 | `tests/`、`.github/workflows/` |

初次发布策略可直接发布以完成初始化。后续新版本需候选版本的已完成评测，所有条目带标签且通过；历史已发布版本可以回滚。该首版门禁不是独立盲测认证。

## 验证证据

- 工程回归：34 项测试通过，覆盖鉴权、跨项目隔离、密钥生命周期、错误脱敏、模型失败、额度、队列超时占用、流式拦截/异常终止、评测取消恢复、策略门禁、SSRF 和通知重试。
- 实际 GPU：已完成安全文本放行、自定义测试词阻断、本应用审计查询、候选策略评测与发布、后台评测、凭证撤销。数据见 [验收记录](live-acceptance.json)。
- 最新真实增量生成验收输出了 10 个已审核片段；首片约 7.5 秒，整流约 51.0 秒。该次运行用于证明链路真实，不能外推并发或延迟 SLO。
- 浏览器已验证登录、项目创建、在线检测、检测详情和人工复核。验证数据属于沙盒；生产总览保持真实零样本。
- 旧记录导入 32 条；再次导入新增 0 条、跳过 32 条。旧应用全部禁用，旧密钥全部撤销；不将历史不明来源计入生产指标。
- 企业外部 API 与 Webhook 协议通过受控适配器测试；尚未使用客户真实地址和接收端联调。

测试适配器与两条验收样本不用于宣称模型准确率。原历史报告涉及曾使用的样本匹配覆盖逻辑，不能作为当前版本独立效果证据。

## 已实现但仍需完善

| 优先级 / Todo | 剩余工作及验收 |
| --- | --- |
| P1 / E02、E03 | 数据集管理、独立 holdout、样本来源与人工标注流程、按风险分类报告、版本对比及报告导出；定时评测和公平资源预算 |
| P1 / P01 | 灰度发布和自动回滚条件；门禁由“样例全通过”升级为经确认的独立数据集和业务阈值 |
| P1 / A02 | 客户真实 Webhook 联调、签名验证和接收端幂等演练；人工重投与通知模板；升级规则 |
| P1 / C01 | SDK 端到端兼容测试与版本发布；当前仅支持声明的文本接口子集 |
| P1 / O01 | Prometheus/OTel、HTTP 请求/限流/拒绝指标、分阶段推理耗时、GPU 指标、告警规则与长期独立计量 |
| P1 / U02、E01 | API 资产编辑/停用、用户/应用停用等管理 API 的完整前端操作；浏览器自动回归 |
| P0 上线门禁 / F02、O03 | 正式迁移版本工具、备份恢复演练、密钥轮换和保留/删除策略；RPO/RTO 验证 |
| P0 上线门禁 / Q01、O02 | 真实 GPU 混合负载、断连和数据库故障注入；单机容量实测，明确队列/流式并发上限 |
| P2 / O02、S03 | 多实例任务租约及协调、独立推理服务、SSO/OIDC 与企业组织治理 |
| 后续 / M01～M06 | 多模态媒体基础、图片/OCR、音频、视频、文档和跨模态独立评测，详见 Todo |

## 实施选择与边界

当前 PostgreSQL 原子计数实现跨 API 进程共享额度，尚未引入 Redis。任务协调器与 GPU 推理仍按单进程部署：不要直接增加 Uvicorn workers 或复制服务实例。默认推理队列最多 8 个任务、单 GPU 执行线程、单生成通道；批量与评测按项执行。

前端采用模块化 ES JavaScript，无大型打包依赖。当前流式护栏使用 Gen 对累积窗口审核，Stream 模型已用于离线 Token 诊断，尚未作为在线增量生成审核器接入。已经发送的安全窗口无法撤回；PII 脱敏如果涉及累计输出改写，会保守终止生成。

审计列表保存脱敏摘要和结构化结果；在线检测原文已恢复为加密存储、限权查看、读取留痕，默认保留 7 天。评测输入为可恢复执行而加密持久化；密钥和评测数据的解密依赖 PLATFORM_SECRET，必须与数据库共同备份。模型 revision 未确认时明确记录 unknown。

总体状态：可以操作和联调的生产基础首版；企业正式上线仍需完成上表上线门禁及业务质量验收。
