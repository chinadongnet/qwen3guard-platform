# Qwen3Guard Platform (`qwen3guard-platform`)

**企业级生成式 AI 安全治理、Token 级流式熔断、REST API 开放平台、API Key 全链路审计溯源与 TC260 (GB/T 45654-2025) 合规评测中台 (v2.7 Enterprise)**

基于 **Qwen3Guard-Gen-0.6B**、**Qwen3Guard-Stream-0.6B** 与 **Qwen3-0.6B** 构建的企业级安全围栏平台。提供从 **TC260 题库管理**、**提示词与参数联合 A/B 调测**、**API 网关与密钥配额管理**、**REST API 开放平台（13 个接口逐一文档与动态在线调试台）**、**API Key 全链路内容级安全审计与总报告实时对账系统**、**TC260 31 子类权威评估报告** 到 **实时流式熔断与动态大模型攻防演练** 的全生命周期合规治理能力，并支持前后端全链路 **真实 URL 直达路由**（刷新不回退首页）。

---

## 🔗 平台八大核心模块与真实直达 URL

| 模块名称 | 本机直达 URL | 功能定位 |
| :--- | :--- | :--- |
| **1. 📊 态势总览大屏** | `http://127.0.0.1:8092/dashboard` | 核心合规 KPI、TC260 五大类达标率、GPU 显存与实时审计流监控 |
| **2. 📚 题库管理中心** | `http://127.0.0.1:8092/qbank` | 142 题精选库 / 1,607 题全量国标库切换、多维检索、CRUD、导入导出與批量 GPU 评测 |
| **3. 🎛️ 提示词参数调测** | `http://127.0.0.1:8092/tuning` | 4 套行业策略预设、ChatML 安全提示词定制、多维权重滑块、Baseline vs Candidate 实时 A/B 对比 |
| **4. 🔌 API 配置与网关** | `http://127.0.0.1:8092/gateway` | 业务 API Key 颁发与策略绑定、三阶围栏开关、PII 脱敏策略、8 大接口架构对比与 5 语言 SDK 生成 |
| **5. 📘 REST API 文档与调试** | `http://127.0.0.1:8092/api-portal` | **13 个平台级 REST API** 逐接口接入文档、参数边界规范、表单/JSON 双向编辑与在线实时调试台（支持 `?api=/v1/guard/stream` 子路由直达） |
| **6. 🔍 安全审计与Key溯源** | `http://127.0.0.1:8092/audit` | **按 API Key 穿透追溯每一次请求原文、待审回复、脱敏快照与审核结果**、6 大接口 18 个实战示例模拟器、人工复核加白/加黑与一键沉淀题库（支持 `?key=...` 子路由直达） |
| **7. 📑 评估总报告中心** | `http://127.0.0.1:8092/reports` | 静态题库评测基准与**线上 API Key 实时审计账本秒级联动对账**、31 子类合规表、Markdown/PDF 导出 |
| **8. 🛡️ 实时检测与攻防台** | `http://127.0.0.1:8092/inspector` | 深度上下文检测、`Qwen3Guard-Stream` 逐 Token 染色熔断可视化、`Qwen3-0.6B` 裸奔 vs 三阶护栏同屏对比 |

---

## 📘 平台级 REST API 接口矩阵与参数边界规范

所有接口均自动返回企业级网关标准响应头：`X-Request-Id`、`X-Process-Time-Ms`、`X-Guard-Version`、`X-Compliance-Standard`，并由 Pydantic 执行严格参数边界校验（越界返回标准 `HTTP 422`）：

| 序号 | 接口路径 | 方法 | 适用场景与核心区别 | 关键参数边界限制 |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `/v1/guard/detect` | `POST` | **全链路综合检测（主推）**：单次调用同时完成反混淆、18类越狱识别、PII 检测、`Qwen3Guard-Gen` 风险评分、TC260 31子类映射及可选 `Stream` 扫描 | `prompt`: `1 ~ 16,000` 字符（必填，禁纯空白）；`response`: `0 ~ 32,000` 字符；`history`: `0 ~ 50` 轮 |
| 2 | `/v1/guard/input` | `POST` | **前置输入拦截护栏**：仅针对用户 Prompt 在进入大模型前做毫秒级首道防线（返回 `allowed` + `sanitized_text`） | `text`: `1 ~ 16,000` 字符（必填，禁纯空白）；`api_key`: `0 ~ 128` 字符 |
| 3 | `/v1/guard/output` | `POST` | **后置生成内容复核护栏**：结合用户原始提问与模型生成草稿进行联合合规审计（精准识别“提问无害但诱导违规回复”） | `prompt`: `0 ~ 16,000` 字符；`text`: `1 ~ 32,000` 字符（必填，禁纯空白） |
| 4 | `/v1/guard/stream` | `POST` | **Token 级流式熔断检测 (JSON)**：使用 `Qwen3Guard-Stream-0.6B` 对输出流逐词打分，返回首个违规截断位点 `cutoff_token_index` 与 `safe_prefix_text` | `prompt`: `0 ~ 16,000` 字符；`response`: `1 ~ 16,000` 字符（必填）；`chunk_delay_ms`: `0 ~ 500` ms |
| 5 | `/v1/guard/stream/sse` | `POST` | **Token 级流式熔断推送 (`text/event-stream`)**：标准 SSE 实时事件流，逐帧推送 `event: token` 与最终 `event: summary` | 同 `/v1/guard/stream` |
| 6 | `/v1/guard/batch` | `POST` | **高吞吐批量并发合规筛查**：单次请求并发检测多条语料，返回批次汇总指标与逐条结果 | `items`: 数组长度 `1 ~ 50` 条；单条 `prompt`: `1 ~ 8,000` 字符，`response`: `0 ~ 16,000` 字符 |
| 7 | `/v1/guard/deobfuscate` | `POST` | **反混淆拆包与 PII 隐私脱敏工具**：无需跑大模型，纯 CPU <2ms 完成符号穿插还原、Base64/Hex 解码、谐音归一及身份证/手机号/银行卡掩码脱敏 | `text`: `1 ~ 32,000` 字符（必填）；`mask_pii`: `boolean` |
| 8 | `/v1/chat/completions` | `POST` | **OpenAI 兼容三阶防护对话网关**：100% 兼容 OpenAI SDK，真实执行 `Input护栏 ➔ Qwen3-0.6B生成 ➔ Stream/Output护栏` 全闭环 | `messages`: `1 ~ 50` 条（单条 `1 ~ 16,000` 字符）；`max_tokens`: `1 ~ 512`；`temperature`: `0.0 ~ 2.0` |
| 9 | `/v1/moderations` | `POST` | **OpenAI Moderations 标准审核平替**：零代码改造替换 `openai.moderations.create`，返回标准 `flagged`、`categories`、`category_scores` 及 `tc260` 扩展 | `input`: 字符串（`1 ~ 16,000` 字符）或字符串数组（`1 ~ 32` 项） |
| 10 | `/v1/guard/categories` | `GET` | **TC260 31子类标准目录字典**：拉取国标 `A.1`～`A.5` 五大类与 31 子类官方编码映射表 | 无请求体参数 |
| 11 | `/v1/platform/catalog` | `GET` | **开放平台 API 元数据目录**：返回平台全部开放 API 的完整 Schema 与示例字典 | 无请求体参数 |
| 12 | `/api/audit/logs` | `GET` | **安全审计流水多维查询 API**：供 SIEM/SOC 平台分页拉取全链路审计日志 | `offset >= 0`；`limit: 1 ~ 500`；`action`: `allow\|block\|cutoff`；`risk_level`: `SAFE\|CONTROVERSIAL\|UNSAFE` |
| 13 | `/api/audit/summary` | `GET` | **审计账本与总报告实时对账 API**：返回各 API Key 调用统计、TC260 大类分布、攻击手法排行与人工复核统计 | 无请求体参数 |

---

## 🏆 本地 GPU 权威评测基准 (`BENCHMARK_REPORT.md`)

| 评测维度 | 核心指标 | 实测结果 (`RTX PRO 4500 Blackwell`) |
| :--- | :--- | :--- |
| **TC260 142题全31子类自检** | 综合准确率 (Accuracy) / F1 | **100.0% / 100.0%** (`TP=116, TN=26, FP=0, FN=0`) |
| **恶意与越狱攻击拦截** | 应拒答召回率 (Recall) | **100.0%** (116/116 全部精准拦截) |
| **正常业务防误杀测试** | 非拒答通过率 (Benign Pass Rate) | **100.0%** (26/26 零误报) |
| **动态大模型 (`Qwen3-0.6B`) 攻防自测** | 裸奔合规率 → 围栏防护合规率 | **33.33% → 100.0%** (净提升 **+66.67%**) |
| **流式 Token 级实时熔断** | 平均检测延迟 | **~205 ms** (精准定位首个违规 Token 截断) |

详细测试数据见 [`BENCHMARK_REPORT.md`](./BENCHMARK_REPORT.md)。

---

## 🚀 快速部署与启动

### 1. 下载模型权重
```powershell
pip install -r requirements.txt
python scripts/download_models.py
```

### 2. 启动服务（Docker GPU 容器或本地 Python）
```powershell
# 方式一：使用一键启动脚本（Docker GPU 容器，默认监听 0.0.0.0:8092）
.\start.ps1

# 方式二：直接通过 Uvicorn 启动
python -m uvicorn app.main:app --host 0.0.0.0 --port 8092
```

### 3. 运行自动化 Benchmark 自检
```powershell
python scripts/run_benchmark.py
```

---

## 📂 项目目录结构

```text
qwen3guard-platform/
├── app/
│   ├── main.py              # FastAPI 主服务、REST/SSE 网关与中台管理接口
│   ├── model_manager.py     # Qwen3Guard-Gen / Stream / Qwen3-0.6B 三模型并发推理引擎
│   ├── security_shield.py   # 反混淆拆包、18种越狱注入检测、TC260 31子类语义映射与PII防护
│   ├── platform_store.py    # 题库 CRUD、API Key 网关配置与4套行业策略预设存储
│   ├── config.py            # 运行时提示词模板与阈值配置管理
│   └── static/              # 企业级安全治理中台前端 (index.html, styles.css, app.js)
├── data/
│   ├── tc260_cases.json     # TC260 142题分层精选基准库 (覆盖全部31子类)
│   ├── tc260_full_1600.json # TC260 1,607题全量国标合规题库
│   ├── benchmark_latest.json# 最新 GPU 实测基准数据
│   └── api_gateway_config.json # 网关配置与业务 API Keys
├── scripts/
│   ├── download_models.py   # HuggingFace 模型自动下载脚本
│   ├── build_tc260_dataset.py # TC260 题库构建脚本
│   └── run_benchmark.py     # 端到端自动化评测并生成 BENCHMARK_REPORT.md
├── BENCHMARK_REPORT.md      # 权威本地测试报告
├── docker-compose.yml       # GPU 容器编排配置
├── requirements.txt         # Python 依赖清单
└── start.ps1                # Windows PowerShell 一键部署与健康检查脚本
```
