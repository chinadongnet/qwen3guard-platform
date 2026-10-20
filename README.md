# QwenGuard Platform 3.0

基于现有 Qwen3Guard-Gen-0.6B、Qwen3Guard-Stream-0.6B 与 Qwen3-0.6B 部署的文本审核平台。当前交付 P0 基础闭环及 P1 主要业务首版：登录 → 项目/应用 → API Key → 真实模型检测 → 隔离审计 → 事件复核。

当前仅支持文本。多模态已进入 Todo，图片、音频、视频和文档文件不会被当作已支持的安全输入。

已完成原题库 142/1607 条全量 GPU 质量回归及发现的功能修复，见 [质量验收与逐题证据](docs/model-quality-acceptance.md)。原 Excel 的输入/回复标签已恢复；全量执行完成不等于模型质量达标。

## 启动与登录

```powershell
.\start.ps1
```

需要 Docker Desktop、GPU 容器支持和已有 `qwenguard_models` 模型卷。脚本初始化本地配置后构建服务，并启动 PostgreSQL。访问 [控制台](http://127.0.0.1:8092/dashboard)。首次管理员用户名为 `admin`，随机密码保存在本机 `data/bootstrap-credentials.txt`；密码、数据库口令和 PLATFORM_SECRET 不进入 Git。

手动执行：

```powershell
python scripts/setup_platform.py
docker compose up -d --build
docker compose exec qwenguard-server python scripts/migrate_legacy.py
```

初始化脚本不覆盖已有配置。旧 JSON 导入幂等，归入历史项目；旧应用禁用、旧密钥撤销。旧数据备份位于 `data/backups/`。

## 已实现的主要能力

- 管理会话、CSRF、项目角色和成员；业务 Key 不能作为管理身份。
- PostgreSQL 持久化，API Key 单次展示、哈希存储、权限域、过期、撤销和轮换。
- 有界推理、额度控制、严格错误语义；检测失败返回明确错误，不能伪装安全。
- 不可变策略版本、候选评测发布门禁、回滚、PII 处理。
- 真正增量生成和审核窗口 SSE；未通过审核的窗口不下发。
- 企业 API 资产、连接验证、凭证加密、后台评测、进度与中断恢复。
- 检测记录隔离、真实环境指标、人工复核、签名通知与重试。
- 会话保护的 OpenAPI 和开发者中心。

原版功能去向与整改证据见 [功能覆盖表](docs/feature-coverage.md)。题库、提示词调测、Token 诊断、攻防实验、报告和 API 在线调试已恢复。

完整交付范围、证据和未完成项见 [交付状态](docs/implementation-status.md)、[Todo](docs/development-backlog.md) 和 [整改评估](docs/enterprise-remediation-plan.md)。

## 接入

在控制台创建项目，创建并首次发布策略，再创建应用和凭证。业务服务通过 `Authorization: Bearer <API_KEY>` 或 `X-API-Key` 接入；请求正文不接受 API Key。

```http
POST /v1/guard/detect
Authorization: Bearer <API_KEY>
Content-Type: application/json

{"prompt":"介绍一下杭州的历史"}
```

检测结果包含 `request_id`、`audit_id`、`execution_status`、`decision`、`policy`、`model` 和耗时。审核业务结论与执行状态必须同时判断；错误不能视为放行。拥有 `audit:read` 的 Key 可查询 `/v1/audit/logs`，仅返回其所属应用的数据。

真实增量对话使用 `/v1/chat/completions`、`stream=true`、模型名 `Qwen3-0.6B-Guarded`。仅支持文本消息子集；`guarded=false` 明确拒绝。`/v1/guard/stream` 返回完整文本的真实 Stream 模型 Token 诊断；`/v1/guard/stream/sse` 推送带 replay 标记的 Token 事件和汇总。它们是诊断回放，不声称在线生成时序。

`/v1/moderations` 提供文本封装子集，类别为平台自定义策略类别；不宣称完整兼容其他厂商 Moderation 类别。旧管理 API 已关闭并返回受保护的 410，旧审计别名 `/api/audit/logs`、`/api/audit/summary` 同样要求应用 Key 并严格限定本应用。登录后查看 `/docs` 或 `/openapi.json` 获取当前契约。

## 验证

```powershell
python -m pip install -r requirements-platform.txt fastapi pydantic pytest
python -m pytest -q tests
python scripts/verify_platform.py
```

单元/契约测试不加载模型。最后一条会调用真实 GPU，在命名沙盒中创建或更新策略、测试任务和审计记录，并撤销临时凭证；请按需要执行。结果保存于 `docs/live-acceptance.json`。样例验收不代表模型准确率或容量认证。

## 部署边界

当前配置用于已有本机单 GPU 服务。正式域名部署需配置 HTTPS、`COOKIE_SECURE=true` 和明确的 `ALLOWED_ORIGINS`；数据库不暴露宿主机端口。外部 API 默认要求 HTTPS，内网目标需在 `ALLOWED_PRIVATE_HOSTS` 中按主机名显式授权。

不要增加 Uvicorn workers 或复制 GPU 服务实例：当前后台任务协调器和生成通道按单进程实现。尚需完成容量、备份恢复、正式迁移、长期监控和独立质量验收。运行与恢复步骤见 [运行说明](docs/operations.md)。

历史 `BENCHMARK_REPORT.md` 属于旧版自测记录，其中高分不能作为当前版本独立质量证据。
