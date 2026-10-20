# 运行说明

## 服务检查

```powershell
docker compose ps
Invoke-RestMethod http://127.0.0.1:8092/health/live
Invoke-RestMethod http://127.0.0.1:8092/health/ready
docker compose logs --tail 80 qwenguard-server
```

`live` 表示应用可响应；`ready` 同时检查数据库和模型就绪。默认单进程服务，启动需等待模型加载。运行配置由 `.env` 注入；修改 `.env` 后需 `docker compose up -d --force-recreate qwenguard-server`。普通代码更新可以在测试通过后 `docker compose restart qwenguard-server`，依赖变化需要重新构建镜像。

`PLATFORM_SECRET` 保护会话及加密的上游凭证、评测输入和通知签名密钥。当前没有在线轮换迁移工具，切勿只替换这个值；应先设计并验证解密重加密迁移。`BOOTSTRAP_ADMIN_PASSWORD` 仅用于首次创建管理员，修改环境变量不会重置已有账号。

登录后在 **系统管理 → 修改密码** 或顶部 **账户密码** 修改当前账户密码。需要当前密码和两次一致的新密码（8～256 个字符，保留空格）；保存后该账户全部现有会话撤销，必须重新登录。新密码只以哈希存入数据库，操作审计不记录口令。此功能不会同步 `.env` 中的初始化密码或本机凭证文件；数据库中的密码才是实际登录凭证。

修改密码后运行真实 GPU 验收脚本，应通过进程环境变量 `QG_ADMIN_USER` / `QG_ADMIN_PASSWORD` 提供当前凭证，脚本优先使用这两个值，不需要修改初始化配置。

## 备份

正式上线前在独立环境演练恢复。以下命令生成数据库备份，不会删除生产数据：

```powershell
New-Item -ItemType Directory -Force data/backups/manual
docker compose exec -T qwenguard-db pg_dump -U qwenguard -d qwenguard -Fc -f /tmp/qwenguard.dump
docker compose cp qwenguard-db:/tmp/qwenguard.dump data/backups/manual/qwenguard.dump
```

备份数据库、`.env` 中的密钥，以及部署版本和模型版本；放入受限且加密的备份位置。`data/backups` 仅是本机暂存，不构成异地备份。不要使用 `docker compose down -v` 清理生产环境。

恢复时先创建隔离数据库，将 dump 导入新库，使用匹配的 PLATFORM_SECRET 启动隔离实例，再验证登录、审计数量、策略版本、评测任务和加密凭证。验收通过后才能制定切换步骤。当前尚未完成恢复演练，也未承诺 RPO/RTO。

## 旧数据与版本切换

`scripts/setup_platform.py` 首次生成随机凭证并备份旧 JSON。`scripts/migrate_legacy.py` 将旧记录放入固定历史项目，重复执行不会重复导入。旧密钥仅导入哈希并标为撤销，旧应用禁用，历史来源标为 `legacy_unknown`。新服务不再写旧审计 JSON。

v3 已关闭旧管理接口，旧数据面也有明确的兼容边界。不要通过将启动入口切回 `app.legacy_main:app` 来公开回滚，这会重新暴露旧版缺陷。需要版本回退时，应在隔离环境验证代码和数据库兼容性，再使用仍包含权限保护的版本。

当前 schema version 2 为追加表迁移，保留原 version 1 数据；仍无完整增量迁移工具。后续结构变化需附迁移、对账与恢复方案。

## 评测与通知

当前任务协调器为单实例。队列和逐项结果持久化；服务重启后运行中的任务标记 interrupted，需在控制台显式恢复。取消在当前有界调用结束后生效；未审核内容不会继续发送。模型执行超时不会将仍执行的 GPU 槽位错误释放。

Webhook 请求包含 `delivery_id`、`timestamp`、事件和审计 ID；接收方应使用 delivery_id 去重，并检查时间窗。签名为 HMAC-SHA256，位于 `X-QG-Signature`；对解析后的 JSON 使用 UTF-8、按键排序、无额外空格、保留 Unicode 的规范格式计算。接收端应使用常量时间比较。成功响应任意 2xx 即完成投递；失败指数退避，最多 5 次，最终状态可查询。

内网目标需显式加入 `ALLOWED_PRIVATE_HOSTS`。连接使用经校验并固定的 DNS 地址，禁止跟随重定向；不会自动信任环境代理。企业真实端点和接收端联调仍待完成。

## 指标解释

总览单位是检测条目。批量每项计数；聊天输入与终止审核分别计数；中间窗口、离线评测和旧来源均不计在线总览。沙盒与生产按环境及来源双重筛选，无样本显示“—”。

技术成功率为成功执行的检测条目 / 总条目；阻断率分母是成功执行条目。它不是 HTTP 服务可用性，也不是模型准确率。普通检测延迟包含本次排队和审核；聊天终止记录是本次聊天总时长。总体分位数混合不同审核类型，不能用来推导纯推理延迟。

后续监控需补全 HTTP 拒绝/限流、队列、GPU、分接口时延和首片时延等指标，独立于审计保留期。正式部署前应结合真实负载设定阈值，而不是复用旧演示页面的百分比。

## 功能恢复与原文保留

本轮迁移前数据库备份：`data/backups/feature-parity/before-parity.dump`。新增题库、版本、实验记录、归档、Key 暂停和加密原文表。旧 JSON 仍保留；重新运行 `scripts/migrate_legacy.py` 会幂等回填历史原文，不重复导入检测事件。

在线审核原文以 PLATFORM_SECRET 派生密钥加密存储。仅 admin/operator/auditor 可以通过显式原文读取接口查看，访问会记录操作审计；应用 Key 仍只能读取脱敏结果。`AUDIT_RAW_RETENTION_DAYS` 默认 7，允许 1～365 天。过期原文立即不可读，后台协调器在任务调度间隙清理；长任务期间物理清理可能延后。评测样本与实验记录另按其版本数据管理，不受原文保留参数控制。数据库备份也可能包含尚未清除的密文，需配置备份生命周期。

## 全量质量验收复现

在项目根目录、安装了项目依赖的 Python 环境运行。脚本使用当前管理员凭证及已有沙盒应用；运行名应唯一，重复相同名称会复用原任务。

```powershell
python scripts/quality_acceptance.py start --run acceptance-new --target auto
python scripts/quality_acceptance.py status --run acceptance-new
python scripts/quality_acceptance.py export --run acceptance-new
```

`start` 提交精选库及完整库任务，`status` 查询进度，完成后 `export` 保存报告与不一致样本到 `docs/quality-acceptance/`。自动模式按题目来源选择输入或回复审核：回复必须有独立的回复标签，外部 API 新生成回复没有该标签时不计算准确率。精选库包含在完整库中，不可相加作为独立样本量。导出包含题目和回复原文，应按评测数据的访问权限管理。

离线检测批次最多 8 条、16384 padding token，与在线请求共用受控 GPU 推理池；过大的批次退回单条。批次等待时间按实际占用记录，不平均拆分为虚假的单条延迟。执行失败、待复核及未完成样本不计作正常放行。

本轮 `source-validated` 是全量真实 GPU 推理；`postrules` 是同一模型结果在最终规则下的复判，两者保留不同任务和审计来源。`scripts/replay_quality_rules.py` 仅用于这次固定证据集的后处理对比，会校验模型解析与预处理未改变；它不是新模型验收工具，也不能替代模型变更后的真实推理。最终决策变化另经 `scripts/verify_postrule_changes.py` 逐条真实 GPU 验证。完整证据和尚未达标原因见 [质量验收报告](model-quality-acceptance.md)。
