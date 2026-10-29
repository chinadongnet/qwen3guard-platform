# Qwen3Guard 平台全量 API 自动化测试与本机算力评测报告

- **生成时间**：`2026-10-29T11:43:23.497161+08:00`
- **测试目标地址**：`http://127.0.0.1:8092`
- **本机 GPU 算力设备**：`NVIDIA GeForce RTX 3090` (显存占用 `15768.0 MB / 24576.0 MB`, 驱动 `616.92`, 精度 `torch.bfloat16`)
- **功能测试用例通过率**：**28 / 28 (100% PASS)**

---

## 一、全链路功能测试用例执行结果（28 项核心用例）

| 用例编号 | 所属测试套件 | 测试用例名称 | 状态 | 耗时 (ms) | 关键验证结果 |
| :--- | :--- | :--- | :---: | :---: | :--- |
| `TC-AUTH-01` | Suite 1: 登录与 API Key 管理 | 管理员账户登录 (/api/admin/auth/login) | ✅ PASS | 75.24 | `user=admin` |
| `TC-AUTH-02` | Suite 1: 登录与 API Key 管理 | 查询系统与本机 GPU 模型状态 (/api/admin/system) | ✅ PASS | 5.41 | `device=None` |
| `TC-KEY-01` | Suite 1: 登录与 API Key 管理 | 登录后一键创建全功能 API Key (POST /api/admin/keys) | ✅ PASS | 9.73 | `prefix=qg_mQDwPRd3 scopes=detect,chat,audit:read,policy:manage` |
| `TC-KEY-02` | Suite 1: 登录与 API Key 管理 | 查询项目 API Key 列表并验证明文脱敏 (GET /api/admin/keys) | ✅ PASS | 6.07 | `total_keys=10` |
| `TC-KEY-03` | Suite 1: 登录与 API Key 管理 | 应用级创建、调额、轮换与撤销凭证闭环 (/api/admin/keys/*) | ✅ PASS | 49.21 | `revoked_status=403` |
| `TC-POL-01` | Suite 2: API Key 策略配置 | 使用 API Key 获取当前生效策略与版本列表 (GET /v1/policies/current) | ✅ PASS | 33.08 | `policy=API-Key-AutoPolicy-1793190758 v4` |
| `TC-POL-02` | Suite 2: API Key 策略配置 | 使用 API Key 直接访问管理面策略接口 (GET /api/admin/policies) | ✅ PASS | 12.02 | `policies_count=3` |
| `TC-POL-03` | Suite 2: API Key 策略配置 | 使用 API Key 创建新策略并自动发布绑定 (POST /v1/policies) | ✅ PASS | 21.42 | `new_policy_id=85db94d42ce8 v1` |
| `TC-POL-04` | Suite 2: API Key 策略配置 | 使用 API Key 热更新自定义黑名单词并验证拦截 (PUT /v1/policies/current) | ✅ PASS | 1442.74 | `decision=block matched=['自定义拦截词:绝密星辰计划X99', 'custom_keyword:绝密星辰计划X99']` |
| `TC-POL-05` | Suite 2: API Key 策略配置 | 使用 API Key 切换 PII 处置为 mask 并验证脱敏返回 (PUT /v1/policies/current) | ✅ PASS | 378.73 | `decision=mask sanitized=普通会议通知：请联系王经理 [PHONE] 或发邮件至 [EMAIL]` |
| `TC-POL-06` | Suite 2: API Key 策略配置 | 使用 API Key 新建策略版本并发布生效 (POST /v1/policies/{id}/publish) | ✅ PASS | 28.62 | `published_version=v4` |
| `TC-API-01` | Suite 3: 检测与护栏 API | 标准单轮输入安全审核 (POST /v1/guard/detect) | ✅ PASS | 786.35 | `safe=allow unsafe=block` |
| `TC-API-02` | Suite 3: 检测与护栏 API | 大模型回复审核与安全拒答识别 (POST /v1/guard/detect response) | ✅ PASS | 1360.43 | `safe_refusal=allow bad_response=block` |
| `TC-API-03` | Suite 3: 检测与护栏 API | 多轮对话上下文联合审核 (POST /v1/guard/detect messages) | ✅ PASS | 731.02 | `decision=block` |
| `TC-API-04` | Suite 3: 检测与护栏 API | 网关前置输入与后置输出专用接口 (/v1/guard/input & /output) | ✅ PASS | 1061.54 | `in_allowed=True out_allowed=True` |
| `TC-API-05` | Suite 3: 检测与护栏 API | 批量检测与 OpenAI Moderations 兼容接口 (/v1/guard/batch & /v1/moderations) | ✅ PASS | 2204.19 | `batch_completed=3` |
| `TC-API-06` | Suite 3: 检测与护栏 API | 混淆文本还原与 PII 脱敏工具接口 (POST /v1/guard/deobfuscate) | ✅ PASS | 17.67 | `methods=[] text=联​系​人 [PHONE] 邮​箱 [EMAIL]` |
| `TC-API-07` | Suite 3: 检测与护栏 API | Qwen3Guard-Stream 逐 Token 风险扫描与 SSE 流诊断 (/v1/guard/stream & /sse) | ✅ PASS | 1613.28 | `tokens_inspected=25 decision=block` |
| `TC-API-08` | Suite 3: 检测与护栏 API | 受控对话生成与实时流式护栏拦截 (POST /v1/chat/completions) | ✅ PASS | 6009.75 | `safe_finish=stop unsafe_finish=content_filter` |
| `TC-API-09` | Suite 3: 检测与护栏 API | 分类目录、能力契约与应用级审计查询 (/v1/guard/categories & /v1/audit/*) | ✅ PASS | 388.71 | `audit_total=186 blocked=68` |
| `TC-LLMG-01` | Suite 3: 检测与护栏 API | llmguard 默认零配置模板与 result 字段解析兼容 (POST /v1/guard) | ✅ PASS | 968.62 | `unsafe_result=['Safety: Unsafe', 'Categories: Politics, Violent, Sexual, A.1.6 宣扬暴力、淫秽色情']` |
| `TC-LLMG-02` | Suite 3: 检测与护栏 API | llmguard IDENTITY_TEMPLATE 身份透传与助手拒答自动识别 | ✅ PASS | 595.6 | `decision=allow caller=claude-code` |
| `TC-LLMG-03` | Suite 3: 检测与护栏 API | llmguard output_streaming 自动路由至 Qwen3Guard-Stream 极速通道 | ✅ PASS | 68.95 | `model=Qwen3Guard-Stream-0.6B latency=68.9ms` |
| `TC-LLMG-04` | Suite 3: 检测与护栏 API | llmguard 超长多轮拼接上下文 (>30,000 字符) 智能窗口截断检测 | ✅ PASS | 2768.18 | `chars=40822 decision=allow` |
| `TC-EFF-01` | Suite 4: 模型效果指标 | Qwen3Guard-Gen-0.6B 多类别安全检测效果评测 (40 样本) | ✅ PASS | 23228.0 | `Accuracy=100.0% Precision=100.0% Recall=100.0% F1=100.0% FPR=0.0%` |
| `TC-EFF-02` | Suite 4: 模型效果指标 | Qwen3Guard-Stream-0.6B 逐 Token 流式检测效果评测 (10 样本) | ✅ PASS | 10194.03 | `Accuracy=100.0% Precision=100.0% Recall=100.0% F1=100.0%` |
| `TC-PERF-01` | Suite 5: 模型性能指标 | Qwen3Guard-Gen-0.6B 单条与并发检测延迟/吞吐基准 (44 次真实推理) | ✅ PASS | 11482.06 | `Model P50=426.44ms P95=579.61ms SeqQPS=2.09 ConcQPS=2.4` |
| `TC-PERF-02` | Suite 5: 模型性能指标 | Qwen3Guard-Stream-0.6B 逐 Token 扫描速度与 SSE 首包延迟基准 | ✅ PASS | 4664.81 | `Stream P50=50.52ms AvgSpeed=397.1 tok/s SSE_TTFT=680.64ms` |

---

## 二、模型效果指标（Effectiveness Metrics · 真实 GPU 推理）

### 2.1 `Qwen3Guard-Gen-0.6B` 生成式安全审核模型效果指标（40 标注样本）

| 指标名称 | 指标值 | 计算说明 |
| :--- | :---: | :--- |
| **总体准确率 (Accuracy)** | **100.0%** | `(TP + TN) / Total` (40 / 40) |
| **精确率 / 查准率 (Precision)** | **100.0%** | `TP / (TP + FP)` (28 / 28) |
| **召回率 / 风险拦截率 (Recall / TPR)** | **100.0%** | `TP / (TP + FN)` (28 / 28) |
| **F1 综合得分 (F1-Score)** | **100.0%** | `2 * P * R / (P + R)` |
| **正常样本放行率 (Specificity / TNR)** | **100.0%** | `TN / (TN + FP)` (12 / 12) |
| **误拦率 (False Positive Rate, FPR)** | **0.0%** | `FP / (FP + TN)` |
| **漏拦率 (False Negative Rate, FNR)** | **0.0%** | `FN / (FN + TP)` |
| **混淆矩阵 (Confusion Matrix)** | `TP=28, TN=12, FP=0, FN=0` | 正类为风险/违规样本 (Unsafe) |

#### 各风险类别细分效果表现

| 类别代码 | 样本数 | 命中/正确数 | 分类准确率 | TP (正确拦截) | TN (正确放行) | FP (误报) | FN (漏报) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `BENIGN` | 12 | 12 | **100.0%** | 0 | 12 | 0 | 0 |
| `A.1` | 4 | 4 | **100.0%** | 4 | 0 | 0 | 0 |
| `A.2` | 5 | 5 | **100.0%** | 5 | 0 | 0 | 0 |
| `A.3` | 6 | 6 | **100.0%** | 6 | 0 | 0 | 0 |
| `A.4` | 4 | 4 | **100.0%** | 4 | 0 | 0 | 0 |
| `JAILBREAK` | 5 | 5 | **100.0%** | 5 | 0 | 0 | 0 |
| `PII` | 4 | 4 | **100.0%** | 4 | 0 | 0 | 0 |

### 2.2 `Qwen3Guard-Stream-0.6B` 流式逐 Token 审核模型效果指标（10 标注样本）

| 指标名称 | 指标值 | 混淆矩阵详情 |
| :--- | :---: | :--- |
| **流式检测准确率 (Accuracy)** | **100.0%** | `TP=5, TN=5, FP=0, FN=0` |
| **流式精确率 (Precision)** | **100.0%** | 恶意流精准熔断定位到具体风险 Token |
| **流式召回率 (Recall)** | **100.0%** | 半途注入毒化内容实时识别与截断 |
| **流式 F1 分数 (F1-Score)** | **100.0%** | 综合流式护栏效果得分 |

---

## 三、模型与平台性能指标（Performance Metrics · 本机 RTX 3090 算力）

### 3.1 核心模型与 API 延迟分布（单位：ms）

| 评测维度 | 平均耗时 (Avg) | 最小 (Min) | 中位数 (P50) | P90 | P95 | P99 | 最大 (Max) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Qwen3Guard-Gen 纯模型推理耗时** | 462.85 | 340.23 | **426.44** | 571.62 | **579.61** | 776.32 | 776.32 |
| **`/v1/guard/detect` 端到端 HTTP 耗时** | 478.42 | 360.68 | **446.32** | 582.62 | **589.73** | 792.7 | 792.7 |
| **4 线程并发压测端到端耗时** | 1547.61 | 373.21 | **1615.91** | 1837.12 | **1851.87** | 1878.7 | 1878.7 |
| **Qwen3Guard-Stream 纯模型扫描耗时** | 58.99 | 49.17 | **50.52** | 77.16 | **77.16** | 77.16 | 77.16 |

### 3.2 不同输入长度下的端到端检测耗时

| 输入长度档位 | 样本字符规模 | 平均耗时 (Avg ms) | P50 (ms) | P95 (ms) |
| :--- | :--- | :---: | :---: | :---: |
| `short_20c` | 短文本 (~20 字符) | 487.68 | 464.65 | 589.73 |
| `medium_180c` | 中等文本 (~180 字符) | 431.92 | 395.71 | 553.61 |
| `long_600c` | 长文本 (~600 字符) | 502.01 | 437.99 | 792.7 |
| `attack_check` | 复合越狱攻击文本 | 492.07 | 446.32 | 582.62 |

### 3.3 吞吐量与流式首包响应指标 (Throughput & TTFT)

| 性能指标项 | 实测数值 | 说明 |
| :--- | :---: | :--- |
| **单线程顺序吞吐量 (Sequential QPS)** | **2.09 req/s** | 单客户端连续调用 `/v1/guard/detect` |
| **4 线程并发吞吐量 (Concurrent QPS)** | **2.4 req/s** | 4 并发客户端同时请求 `/v1/guard/detect` |
| **批量接口吞吐量 (`/v1/guard/batch`, 20 条/批)** | **2.31 items/s** | 单条均摊耗时 **433.2 ms/条** |
| **Qwen3Guard-Stream 逐 Token 扫描吞吐** | **397.09 tokens/s** (峰值 **620.62 tokens/s**) | 逐 Token 前向分类扫描速率 |
| **Stream SSE 首事件响应延迟 (TTFT)** | **680.64 ms** | `/v1/guard/stream/sse` 首包事件到达耗时 |
| **受控对话网关 SSE 首包延迟 (`/v1/chat/completions`)** | **354.16 ms** | 含输入前置安全审核 + 首窗口生成护栏 |

---

## 四、如何复现运行本测试环境

```powershell
# 1. 运行独立全链路 API 自动化测试与算力基准评测脚本（自动输出 JSON 与 Markdown 报告）
.\.venv\Scripts\python.exe scripts/run_api_test_env.py

# 2. 或通过 pytest 运行在线 API 集成与性能断言套件
.\.venv\Scripts\python.exe -m pytest tests/test_live_api_benchmark.py -v -s
```
