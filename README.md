# Qwen3Guard Platform (`qwen3guard-platform`)

**企业级生成式 AI 安全治理、Token 级流式熔断与 TC260 (GB/T 45654-2025) 合规评测中台**

基于 **Qwen3Guard-Gen-0.6B**、**Qwen3Guard-Stream-0.6B** 与 **Qwen3-0.6B** 构建的企业级安全围栏平台。提供从 **题库管理**、**提示词与参数联合 A/B 调测**、**API 网关与多语言接入配置**、**TC260 31 子类权威评估报告** 到 **实时流式熔断与动态大模型攻防演练** 的全生命周期合规治理能力。

---

## ✨ 平台六大核心模块

### 1. 📊 态势总览与监控中心 (Executive Dashboard)
- **核心合规 KPI 大屏**：实时汇总 TC260 综合合规准确率、应拒答拦截召回率、非拒答正常样本通过率及动态大模型围栏净提升。
- **TC260 五大类达标率态势图**：可视化展示 `A.1`～`A.5` 及 `BENIGN` 非拒答样本的评测分布。
- **GPU 算力与模型集群监控**：实时监测 GPU 显存占用、三大常驻模型健康状态与实时安全审计日志流。

### 2. 📚 TC260 合规题库管理中心 (Question Bank Management)
- **双题库无缝切换**：
  - `data/tc260_cases.json`：**142 题** 分层精选基准库（100% 覆盖 5 大类、31 小类与 18 种越狱/混淆攻击手法）。
  - `data/tc260_full_1600.json`：**1,607 题** 全量国标合规题库。
- **多维检索与分页**：支持按 TC260 大类/子类、题库分类（生成内容安全/应拒答/非拒答/行业拓展）、攻击手法与关键词实时检索。
- **全量 CRUD 与导入导出**：支持在线新增、编辑、删除测试用例，支持 JSON 批量导入导出，以及勾选多题一键发起 GPU 批量评测。

### 3. 🎛️ 提示词与参数联合调测中心 (Prompt & Parameter Tuning Studio)
- **4 套行业策略预设模板**：
  1. `TC260-003 国标合规标准模式 (推荐)`
  2. `政务/金融零容忍严苛防护模式`
  3. `教育/学术/安全研发防误杀宽松模式`
  4. `高并发流式极速熔断模式`
- **结构化提示词工作台**：在线微调 `<BEGIN SAFETY POLICY>`（Input / Output 独立策略）、`<BEGIN UNSAFE CONTENT CATEGORIES>`、企业扩展规则与 `Qwen3-0.6B` 系统提示词，支持 ChatML 完整渲染预览。
- **多维分类权重与阈值滑块**：支持调节全局风险阈值、Stream 熔断阈值及 `A.1`～`A.5`、`JAILBREAK/PII` 独立权重系数。
- **Baseline vs Candidate 实时 A/B 对比调测沙箱**：在保存前并行对比“当前生效策略”与“待调测草稿策略”的拦截判定、风险分与规则命中差异。

### 4. 🔌 API 网关与多语言接入配置 (API Gateway & SDK Center)
- **业务接入密钥 (API Key) 管理**：颁发与管理多业务线 API Key，绑定专属合规预设模板与 QPS 配额。
- **网关全局策略配置**：输入/流式/输出三阶围栏开关、PII 敏感信息处置策略（阻断/脱敏/仅审计）、上游大模型路由及 Webhook 告警。
- **交互式多语言 SDK 生成器**：一键生成 **Python**、**cURL / PowerShell**、**Node.js**、**Go**、**Java** 生产级调用代码。

### 5. 📈 合规评测报告与安全审计中心 (Compliance Report & Audit Center)
- **可视化合规审计看板**：混淆矩阵（`TP / TN / FP / FN`）、TC260 五大类达标率条形图、18 种越狱攻击手法拦截率条形图。
- **权威明细报表**：31 个必测子类合规率明细表、`Qwen3Guard-Stream` Token 级流式熔断基准表、`Qwen3-0.6B` 裸奔 vs 围栏防护对比表。
- **一键导出报告**：支持一键下载 Markdown 报告 (`/api/reports/export/markdown`) 或打印导出 PDF。

### 6. 🛡️ 在线安全检测、流式熔断与攻防演练台 (Live Guard, Stream & LLM Arena)
- **API 深度检测**：支持单轮/多轮上下文风险评分、TC260 子类归因与反混淆拆包还原。
- **SSE 逐 Token 流式熔断可视化**：使用 `Qwen3Guard-Stream-0.6B` 分类头对每个生成 Token 实时打标染色，发现风险立即触发 `cutoff` 熔断截断。
- **动态大模型同屏攻防对比**：直观对比 `Qwen3-0.6B` 裸奔输出与三阶围栏（Input → Stream → Output）防护输出。

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
