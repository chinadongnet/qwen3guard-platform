import {api,state,scoped,esc,date,number,can} from "./api.js?v=3.2.5";
import {button,disabledButton,badge,empty,panel,table,metric,heading,detectionTable,json} from "./components.js?v=3.2.5";
import {renderWorkbench} from "./workbench.js?v=3.2.5";

export const pages=[
  ["overview","运营总览","◈"],["guide","功能与接入指南","✦"],["applications","应用接入","▦"],["detections","检测记录","≡"],
  ["policies","安全策略","◇"],["endpoints","API 资产","⇄"],["evaluations","评测任务","▤"],
  ["incidents","风险事件","◉"],["qbank","题库管理","▥"],["tuning","提示词调测","⚒"],
  ["inspector","检测与攻防","◍"],["reports","评测报告","▤"],["api-portal","API 在线调试","⌘"],
  ["developers","开发者中心","⌘"],["settings","系统管理","⚙"]
];

const plannedNav=[
  ["多模态审核","▣","M01～M06 待开发：图片/OCR、音频、视频、文档解析与跨模态评测尚未开放"],
  ["Prometheus 监控","◫","P1/O01 待开发：Prometheus/OTel 指标暴露、分阶段耗时与长期独立计量尚未实现"],
  ["SSO 与组织治理","⚿","P2/S03 待开发：OIDC 单点登录与企业组织治理尚未实现"]
];

export function shell(){
  const name=state.user.username;
  return `<div class="shell"><aside class="sidebar">
    <div class="brand"><span class="mark">Q</span><div class="brand-text"><strong>QwenGuard</strong><small>AI SECURITY PLATFORM</small></div></div>
    <div class="nav-caption">安全工作空间</div>
    <nav>${pages.map(([id,label,icon])=>`${id==="qbank"?'<div class="nav-caption">平台与接入</div>':""}<button class="nav-button ${state.page===id?"active":""}" data-action="navigate" data-id="${id}"><span class="nav-icon">${icon}</span><span class="nav-label">${label}</span></button>`).join("")}
    <div class="nav-caption">规划中（待开发）</div>
    ${plannedNav.map(([label,icon,reason])=>`<button type="button" class="nav-button disabled-nav" disabled title="${esc(reason)}" aria-disabled="true"><span class="nav-icon">${icon}</span><span class="nav-label">${esc(label)}</span><span class="todo-pill">待开发</span></button>`).join("")}
    </nav>
    <div class="side-foot"><span class="status-dot"></span><strong>企业文本审核</strong><p class="subline">QwenGuard Platform · 3.0</p></div></aside>
    <div class="main"><header class="topbar"><div class="crumb">工作空间 <span>/</span><strong>${esc(pages.find(p=>p[0]===state.page)?.[1]||"运营总览")}</strong></div>
    <div class="top-actions"><select id="project-select" class="project-select" aria-label="当前项目">${state.projects.length?state.projects.map(p=>`<option value="${p.id}" ${p.id===state.project?"selected":""}>${esc(p.name)}</option>`).join(""):'<option value="">未创建项目</option>'}</select>
    ${state.user.is_admin?button("＋ 项目","new-project","","small"):""}<span class="user-avatar">${esc(name.slice(0,1).toUpperCase())}</span><span class="username">${esc(name)}</span>${button("账户密码","change-password","","small quiet")}${button("退出","logout","","small quiet")}</div></header><main class="page" id="page-content"></main></div></div>`;
}

export function loginView(){
  return `<main class="login"><section class="login-aside"><div class="brand"><span class="mark">Q</span><div><strong>QwenGuard</strong><small>AI SECURITY PLATFORM</small></div></div>
    <div><div class="eyebrow">SECURITY, IN EVERY INTERACTION</div><h1>让每一次 AI 调用<br>安全、可控、可追溯。</h1><p>从应用接入到风险处置，在同一工作空间管理内容审核、策略版本与持续评测。</p><div class="login-tags"><span>应用级权限</span><span>版本化策略</span><span>全链路审计</span></div></div>
    <p class="login-footnote">QWENGUARD ENTERPRISE PLATFORM / 3.0</p></section><section class="login-main"><div class="login-box"><h2>登录工作空间</h2><p>使用企业管理员为你提供的账户继续。</p>
    <form id="login-form"><div class="field"><label for="username">用户名</label><input id="username" name="username" autocomplete="username" required placeholder="请输入用户名"></div>
    <div class="field"><label for="password">密码</label><input id="password" name="password" type="password" autocomplete="current-password" required placeholder="请输入密码"></div><div class="error-text hidden" id="login-error"></div><div class="field"></div><button class="primary" type="submit">登录工作空间 →</button></form>
    <div class="login-foot">会话保护 · 项目隔离 · 操作留痕</div></div></section></main>`;
}

async function overview(){
  const [stats,recent,applications,policies]=await Promise.all([
    api(scoped(`/api/admin/overview?environment=${state.environment}&hours=${state.hours}`)),
    api(scoped(`/api/admin/detections?limit=6&source=${state.environment}&environment=${state.environment}&since=${Date.now()/1000-state.hours*3600}`)),api(scoped("/api/admin/applications")),api(scoped("/api/admin/policies"))
  ]);
  const controls=`<select id="environment-select" aria-label="指标环境"><option value="production" ${state.environment==="production"?"selected":""}>生产环境</option><option value="sandbox" ${state.environment==="sandbox"?"selected":""}>沙盒环境</option></select><select id="hours-select" aria-label="时间范围"><option value="24" ${state.hours===24?"selected":""}>最近 24 小时</option><option value="168" ${state.hours===168?"selected":""}>最近 7 天</option><option value="720" ${state.hours===720?"selected":""}>最近 30 天</option></select>${button("刷新","refresh")}`;
  const healthRows=[
    ["▦","接入应用",`${applications.items.length} 个应用`,applications.items.length?"已建立":"待接入"],
    ["◇","已发布策略",`${policies.items.filter(p=>p.published_version>0).length} 个策略`,policies.items.some(p=>p.published_version)?"可用":"待发布"],
    ["◉","待处理风险",`${stats.open_incidents} 个事件`,stats.open_incidents?"待跟进":"暂无待办"],
  ];
  const bar=(label,value,cls)=>`<div class="bar-row"><span>${label}</span><progress value="${value||0}" max="${stats.total||1}" aria-label="${label}"></progress><strong>${number(value)}</strong></div>`;
  return heading("运营总览","观察真实业务调用，及时发现服务异常与内容风险。",controls)+
    `<div class="metrics">${metric("检测条目",number(stats.total),"按指定环境和时间范围统计")}${metric("检测成功率",stats.success_rate===null?"—":number(stats.success_rate)+"%","完成检测 / 全部检测条目")}${metric("P95 检测耗时",stats.p95_ms===null?"—":number(stats.p95_ms)+" ms","包含排队及模型审核")}${metric("风险阻断",number(stats.blocked),stats.block_rate===null?"暂无可计算样本":`阻断率 ${number(stats.block_rate)}%`)}</div>`+
    `<div class="split">${panel("检测结果分布",stats.total?`<div class="panel-body">${bar("已完成",stats.completed,"good")}${bar("已阻断",stats.blocked,"bad")}${bar("执行异常",stats.errors,"bad")}</div><div class="footnote">${esc(stats.definition)}</div>`:empty("等待业务流量","创建应用并完成 API 接入后，这里将显示真实的检测分布。",button("接入应用","navigate","applications","primary small")))}
    ${panel("工作空间状态",`<div class="panel-body">${healthRows.map(([icon,label,value,note])=>`<div class="check-row"><span class="check-icon">${icon}</span><div class="grow"><strong>${label}</strong><p>${value}</p></div><span class="badge">${note}</span></div>`).join("")}</div>`)}</div>`+
    panel("最近检测记录",detectionTable(recent.items),button("查看全部 →","navigate","detections","small quiet"))+
    `<p class="muted help">更新于 ${date(stats.updated_at)} · 评测任务、历史导入和流式中间窗口不计入生产总览。</p>`;
}

async function applications(){
  const [data,keyData]=await Promise.all([api(scoped("/api/admin/applications")),api(scoped("/api/admin/keys")).catch(()=>({items:[]}))]);
  state.cache.applications=data.items;state.cache.keys=keyData.items;
  const action=can("admin","developer")?`${button("＋ 创建 API Key","quick-new-key","","primary")}${button("＋ 创建应用","new-application","")}`:"";
  const rows=data.items.map(item=>`<tr><td><strong>${esc(item.name)}</strong><div class="subline mono">${esc(item.id.slice(0,16))}</div></td><td>${badge(item.environment)}</td><td><code>${esc(item.policy_id.slice(0,12))}</code></td><td>${badge(item.enabled?"可用":"已停用")}</td><td>${date(item.created_at)}</td><td><div class="actions">${can("admin","developer")?button("凭证","keys",item.id,"small"):""}${can("admin")?button("设置","edit-application",item.id,"small")+button(item.enabled?"停用":"启用","toggle-application",item.id,"small"):""}${can("admin","developer","operator")?button("验证接入","test-application",item.id,"small quiet"):""}</div></td></tr>`);
  const keyRows=keyData.items.map(k=>`<tr><td><strong>${esc(k.name)}</strong><div class="subline mono">${esc(k.prefix)}…</div></td><td>${esc(k.application_name||k.application_id.slice(0,12))}</td><td><code>${esc((k.scopes||[]).join(", "))}</code></td><td>${k.rpm} 条/分钟<div class="subline">至 ${date(k.expires_at)}</div></td><td>${badge(k.revoked?"已撤销":k.expires_at*1000<Date.now()?"已过期":k.enabled?"可用":"已暂停")}</td><td><div class="actions">${!k.revoked?button("额度 / 启停","key-settings",k.id,"small")+button("轮换","rotate-key",k.id,"small")+button("撤销","revoke-key",k.id,"small danger"):""}</div></td></tr>`);
  return heading("应用接入与 API Key","为每个业务系统分配独立凭证、环境与安全策略；支持一键创建 API Key 直接调用策略配置与内容检测 API。",action)+
    `<div class="notice">完整密钥（<code>qg_...</code>）仅在创建时显示一次。开启 <code>policy:manage</code> 权限的凭证可同时通过 REST API 配置安全策略（<code>/v1/policies*</code> 或 <code>/api/admin/policies*</code>）并调用检测接口（<code>/v1/guard/*</code>）。</div>`+
    panel("API Key 凭证列表",keyRows.length?table(["凭证名称 / 前缀","所属应用","权限范围 (Scopes)","额度 / 有效期","状态","操作"],keyRows):empty("尚未创建 API Key","点击右上角「＋ 创建 API Key」即可一键生成凭证。",can("admin","developer")?button("＋ 创建 API Key","quick-new-key","","primary"):""))+
    panel("业务应用",rows.length?table(["应用名称","环境","绑定策略","状态","创建时间","操作"],rows):empty("创建第一个业务应用","先发布安全策略，再创建应用并获取独立 API Key。",action));
}

async function detections(){
  const form=state.cache.detectionFilter||{};
  let path="/api/admin/detections?limit=50";
  for(const [key,value] of Object.entries(form))if(value)path+=`&${key}=${encodeURIComponent(value)}`;
  const data=await api(scoped(path));state.cache.nextCursor=data.next_cursor;state.cache.detectionItems=data.items;
  return heading("检测记录","按请求追溯检测决策、策略版本与脱敏证据。",button("刷新","refresh")+button("导出 JSON","export-audit-json")+button("导出 CSV","export-audit-csv")+(can("admin")?button(form.archived==="true"?"恢复本页":"归档本页","archive-audit"):""))+
    `<section class="panel"><form id="detection-filter" class="filters"><input name="application_id" placeholder="应用 ID" value="${esc(form.application_id||'')}"><input name="key_id" placeholder="凭证 ID" value="${esc(form.key_id||'')}"><select name="archived"><option value="false">未归档</option><option value="true" ${form.archived==='true'?'selected':''}>已归档</option></select><input name="request_id" placeholder="完整 Request ID" value="${esc(form.request_id||"")}" aria-label="Request ID"><select name="decision" aria-label="决策"><option value="">全部决策</option>${["allow","block","mask","review"].map(v=>`<option value="${v}" ${form.decision===v?"selected":""}>${({allow:"放行",block:"阻断",mask:"脱敏",review:"复核"})[v]}</option>`).join("")}</select><select name="source" aria-label="来源"><option value="">全部来源</option>${["production","sandbox","evaluation","stream_window","legacy_unknown"].map(v=>`<option value="${v}" ${form.source===v?"selected":""}>${v}</option>`).join("")}</select><button type="submit">筛选</button>${button("重置","reset-filter")}</form>${detectionTable(data.items)}<div class="footnote actions"><span>内容仅展示脱敏摘要 · 每页 50 条</span><span class="spacer"></span>${data.next_cursor?button("下一页 →","next-detections","","small"):""}</div></section>`;
}

async function policies(){
  const data=await api(scoped("/api/admin/policies"));state.cache.policies=data.items;
  return heading("安全策略","先保存草稿，再发布不可变版本；历史请求保留原始策略快照。",button("功能与接入指南","navigate","guide")+(can("admin")?button("＋ 创建策略","new-policy","","primary")+disabledButton("自动白名单规则","R10 待开发：经评审的结构化自动放行白名单覆盖规则尚未实现",""):"" ))+
    `<div class="notice">应用自动使用绑定策略的已发布版本。发布与回滚均记录操作日志，单次检测固定使用一个版本。</div>`+
    (data.items.length?`<div class="cards">${data.items.map(p=>{
      const latest=p.versions[0],published=p.versions.find(v=>v.version===p.published_version),cfg=(published||latest).config;
      return `<article class="policy-card"><div class="actions"><h3 class="spacer">${esc(p.name)}</h3>${badge(p.published_version?`生效 v${p.published_version}`:"未发布")}</div><div class="subline">最新草稿 v${latest.version} · ${date(latest.created_at)}</div><div class="policy-values"><div><span>风险阈值</span>${cfg.risk_threshold}</div><div><span>PII 处理</span>${esc(cfg.pii_action)}</div><div><span>检测超时</span>${cfg.timeout_seconds} 秒</div><div><span>异常处置</span>${esc(cfg.failure_action)}</div></div><div class="actions">${button("版本与差异","policy-detail",p.id,"small")}${can("admin")?button("新建版本","new-version",p.id,"small")+button("发布 / 回滚","publish-policy",p.id,"small primary")+disabledButton("灰度发布","P1/P01 待开发：按流量比例灰度分流与异常自动回滚尚未实现","small"):""}</div></article>`;
    }).join("")}</div>`:panel("策略列表",empty("还没有安全策略","创建策略草稿，确认风险阈值与 PII 处置后发布。")));
}

async function endpoints(){
  const data=await api(scoped("/api/admin/endpoints"));state.cache.endpoints=data.items;
  return heading("API 资产","登记企业模型 API，开展连接验证和持续安全评测。",can("admin")?button("＋ 注册端点","new-endpoint","","primary")+disabledButton("业务网关上游路由","R09 待开发：在线 /v1/chat/completions 自动路由转发至外部上游及重试尚未实现",""):"" )+
    `<div class="notice">填写完整的 Chat Completions 地址。上游凭证加密保存；内网目标需要部署白名单授权。</div>`+
    panel("模型服务端点",data.items.length?table(["名称 / 模型","端点地址","状态","创建时间","操作"],data.items.map(e=>`<tr><td><strong>${esc(e.name)}</strong><div class="subline">${esc(e.model)}</div></td><td><span class="clip mono">${esc(e.url)}</span></td><td>${badge(e.enabled?"可用":"停用")}</td><td>${date(e.created_at)}</td><td><div class="actions">${can("admin")?button("测试连接","test-endpoint",e.id,"small")+disabledButton("编辑","U02/E01 待开发：API 资产端点编辑功能尚未开发","small")+disabledButton("停用","U02/E01 待开发：API 资产端点启停切换尚未开发","small")+disabledButton("设为 Chat 上游","R09 待开发：业务对话请求自动路由至外部上游尚未实现","small"):""}</div></td></tr>`)):empty("尚未注册模型服务","注册目标后，可创建任务检测它的实际回复。直接文本审核不需要配置外部端点。"));
}

async function evaluations(){
  const data=await api(scoped("/api/admin/evaluations"));state.cache.evaluations=data.items;
  return heading("评测任务","使用版本化样本检测业务模型，保留逐项证据与失败记录。",`${button("刷新","refresh")}${can("admin","operator")?button("＋ 创建评测","new-evaluation","","primary")+disabledButton("定时周期评测","P1/E02 待开发：Cron 定时自动回归评测尚未实现","")+disabledButton("独立盲测集 Holdout","P1/E03 待开发：独立 Holdout 盲测集隔离与评审流程尚未实现",""):""}`)+
    `<div class="notice warning">自动评审结果用于回归与风险发现。准确率仅针对提供标签的样本计算，不代表独立认证或线上合规率。</div>`+
    panel("任务队列",data.items.length?table(["任务名称","状态","进度","样本版本","创建时间","操作"],data.items.map(j=>`<tr><td><strong>${esc(j.name)}</strong><div class="subline">${j.endpoint_id?"目标 API 回复评测":"文本检测回归"}</div></td><td>${badge(j.state)}</td><td><progress value="${j.completed}" max="${j.total}" aria-label="任务进度"></progress><div class="subline">${j.completed} / ${j.total}</div></td><td><code>${esc(j.dataset_hash.slice(0,10))}</code></td><td>${date(j.created_at)}</td><td><div class="actions">${button("报告","evaluation-detail",j.id,"small")}${can("admin","operator")?(["running","queued"].includes(j.state)?button("取消","cancel-evaluation",j.id,"small danger"):["interrupted","failed","cancelled"].includes(j.state)?button("恢复","resume-evaluation",j.id,"small"):""):""}</div></td></tr>`)):empty("还没有评测任务","上传 JSON 样本或填写测试集，评测任务将在后台逐项执行。"));
}

async function incidents(){
  const data=await api(scoped("/api/admin/incidents"));state.cache.incidents=data.items;
  return heading("风险事件","将审核发现转为可跟进的工作，追加复核记录并保留机器原判。",button("刷新","refresh")+(can("admin")?disabledButton("自动升级规则","P1/A02 待开发：风险事件超时自动升级与 SLA 规则尚未实现",""):""))+
    panel("事件列表",data.items.length?table(["事件","环境 / 来源","级别","状态","负责人","发现时间","操作"],data.items.map(i=>`<tr><td><code>${esc(i.id.slice(0,14))}</code><div class="subline">${i.reviews.length} 条复核记录</div></td><td>${badge(i.environment)}<div class="subline">${esc(i.source)}</div></td><td>${badge(i.severity)}</td><td>${badge(i.state)}</td><td>${esc(i.assignee||"待分配")}</td><td>${date(i.created_at)}</td><td><div class="actions">${button("证据","detection",i.event_id,"small")}${button("处理记录","incident-detail",i.id,"small")}${can("admin","operator")?button("复核","review-incident",i.id,"small primary"):""}</div></td></tr>`)):empty("暂无风险事件","阻断或待复核的检测将自动生成事件。"));
}

function guide(){
  const supportedScenarios=[
    ["1. 业务前置输入审核（Prompt 防火墙 / 防越狱 / 隐私脱敏）","POST /v1/guard/detect · POST /v1/guard/input","在用户提问发往业务大模型（如 DeepSeek、通义千问、OpenAI 或私有模型）之前进行审核。支持拦截 TC260 31 子类风险、DAN 角色越狱、Prompt 注入、符号插噪/Base64 混淆及自定义黑名单词；若策略配置 pii_action=mask，直接返回 sanitized_content 脱敏文本供下游安全调用。","completed"],
    ["2. 大模型回复后置合规审查与安全拒答识别","POST /v1/guard/detect · POST /v1/guard/output","对业务大模型生成的回答做输出把关。支持结合用户提问语境审核回复合规性，并智能识别 Refusal: Yes（当用户提问违禁问题而助手正常拒绝回答时，精准识别为安全拒答并放行 allow，避免将正常拒答误判为违规）。","completed"],
    ["3. 多轮对话上下文联合审核（防多轮铺垫与拆分越狱）","POST /v1/guard/detect (messages 数组)","针对攻击者将恶意意图拆分在多轮对话中逐步诱导（Payload Splitting）的场景，支持传入最多 50 轮、总长 48,000 字符以内的多轮历史上下文进行联合意图判定。","completed"],
    ["4. 受控增量流式对话生成（边生成、边按窗口审核、违规截断）","POST /v1/chat/completions (Qwen3-0.6B-Guarded)","内置受保护的流式生成通道（需凭证具备 chat 权限域）。先审核输入，生成时严格按策略 stream_window_chars（16～256 字符）累积窗口审核，通过后才向客户端下发 SSE 分片；一旦发现违规或跨窗口 PII 风险立即截断并写入终止审计。","completed"],
    ["5. 离线流式 Token 级风险定位与回放诊断","POST /v1/guard/stream · POST /v1/guard/stream/sse","调用 Qwen3Guard-Stream-0.6B 对完整回复做逐 Token 风险概率扫描与染色，精确定位触发熔断的 Token 下标（cutoff_token_index）、风险分类及截断前的安全前缀（safe_prefix_text）。","completed"],
    ["6. 批量文本审核、OpenAI Moderations 兼容接入与应用自查审计","POST /v1/guard/batch · /v1/moderations · GET /v1/audit/logs","支持单次最多 50 条批量审核、OpenAI Moderations 风格文本子集封装、独立反混淆脱敏工具（/v1/guard/deobfuscate），以及业务系统使用自身 API Key（audit:read 权限）自查本应用审计流水与汇总对账。","completed"]
  ];
  const unsupportedScenarios=[
    ["1. 外部大模型在线业务对话透明反向代理转发（R09）","API 资产模块登记的外部端点目前仅用于“连接测试”与“后台评测任务拉取回复”，/v1/chat/completions 仅调用本机 Qwen3-0.6B 模型，暂不支持作为透明反向代理直接转发线上对话到外部上游。","替代接入方案：由业务后端先调 /v1/guard/detect 审输入 → 业务后端调外部大模型 → 再调 /v1/guard/detect 审输出。","todo"],
    ["2. 图片、音频、视频、PDF/Word 文档等多模态内容审核（M01～M06）","当前仅支持纯文本（content_type=text，请求体上限 2 MiB）。图片 OCR 视觉审核、音频 ASR 转写审核、视频抽帧与文档解析均未开放，传入非 text 类型直接返回 422。","当前边界：请勿将未解析的多模态文件当作已受保护内容放行。","todo"],
    ["3. 命中关键词即跳过模型直接放行的自动白名单规则（R10）","策略仅支持 custom_block_keywords（附加拦截词），不提供强制跳过模型审核的白名单词开关（防止攻击者在越狱指令中拼接白名单词绕过检测）。","替代方案：通过【提示词调测】调整 guard_gen_custom_rules（正向放行语境规则）与 risk_threshold 降低误报。","todo"],
    ["4. 同一应用按流量比例灰度发布策略与异常自动回滚（P01）","一个业务应用同一时刻绑定唯一生效的已发布策略版本，版本切换与回滚均为全量即时生效，暂不支持按百分比（如 10% 流量）线上灰度分流。","替代方案：在沙盒应用验证新策略，或在【提示词调测】中运行 Baseline vs Candidate 离线 A/B 对比。","todo"],
    ["5. 在线流式生成逐 Token 零延迟 Stream 熔断与已发出分片撤回脱敏（D05）","在线 /v1/chat/completions 采用 Gen 模型按字符窗口（stream_window_chars）审核，尚未接入 Stream 模型做逐 Token 在线熔断；且已发往客户端的 SSE 分片无法撤回，流式下触发 PII mask 会保守转为 block 截断。","当前边界：离线逐 Token 诊断请使用 /v1/guard/stream。","todo"],
    ["6. 单应用叠加多策略链及多实例高并发水平扩展（O02）","应用与策略为 N:1 绑定（不可同时叠加多条策略链）；当前推理池为单 GPU 单协调器（队列上限 8，流式通道并发 1），暂不支持多 Worker 或多实例分布式调度。","当前边界：请勿直接增加 Uvicorn workers 数量。","todo"]
  ];
  const paramRows=[
    ["risk_threshold","核心决策","0.5（0.05～0.99）","综合风险得分达到或超过该阈值即判定为 block 拦截"],
    ["pii_action","隐私保护","block（block / mask / audit）","检测到手机号、身份证、银行卡、邮箱、密钥等 PII 时的处置动作"],
    ["timeout_seconds","推理预算","30 秒（1～120 秒）","单次模型审核超时上限；超时不提前释放仍占用的 GPU 槽位"],
    ["failure_action","Fail-Closed","block（block / review）","引擎异常、队列满（503）或超时（504）时的保守处置，绝不伪装为 allow"],
    ["stream_window_chars","流式护栏","48 字符（16～256）","/v1/chat/completions 增量生成时每累积多少字符执行一次窗口审核"],
    ["controversial_as_unsafe","核心决策","true（true / false）","Gen 模型判定为 Controversial（争议内容）时是否直接按风险拦截"],
    ["custom_block_keywords","规则护栏","[]（最多 100 个词）","业务自定义高危黑名单词，命中即触发规则拦截"],
    ["enable_deobfuscation","预处理护栏","true（提示词调测 JSON）","送入模型前自动还原符号插噪、零宽字符、填词陷阱、乱序与 Base64 编码"],
    ["enable_jailbreak_shield","规则护栏","true（提示词调测 JSON）","检测 DAN 角色扮演、系统指令覆盖、翻译劫持、条件触发与 MCP 工具注入"],
    ["enable_tc260_semantic_shield","国标护栏","true（提示词调测 JSON）","启用 TC260-003（GB/T 45654-2025）5 大类 31 子类语义与正则围栏"],
    ["category_weights","国标护栏","A.1～A.5 / JAILBREAK / PII","各风险分类权重系数（0～2.0），参与综合 risk_score 计算"],
    ["guard_gen_safety_policy_input / output","Gen 模型","默认安全准则（最长 6000 字）","直接编译进 Qwen3Guard-Gen-0.6B ChatML Prompt 的输入/输出审核准则"],
    ["guard_gen_unsafe_categories / custom_rules","Gen 模型","9 大类 + TC260 扩展规则","自定义风险类别定义与行业专属审核补充规则（如金融/政务/教育防误报）"],
    ["guard_gen_max_new_tokens / temperature","Gen 模型","24 tokens / 0.0","Gen 审核模型的生成长度与采样温度（0.0 为确定性贪婪解码并支持微批加速）"],
    ["stream_unsafe_threshold / circuit_breaker","Stream 模型","0.5 / true（间隔 3 tokens）","Qwen3Guard-Stream-0.6B 逐 Token 风险概率阈值、熔断开关与语义复核步长"],
    ["llm_system_prompt / max_new_tokens / temperature","受控生成","160 tokens / temp 0.6 / top_p 0.9","Qwen3-0.6B 受控对话与动态攻防实验的系统提示词、生成长度、温度与 thinking 开关"]
  ];
  return heading("功能介绍与安全策略接入指南","全面了解安全策略的配置方式、22 项底层参数作用、已支持的 6 大业务接入场景与当前未开放边界。",`${button("创建 / 管理策略","navigate","policies","primary")}${button("提示词调测","navigate","tuning")}${button("应用接入","navigate","applications")}${button("API 在线调试","navigate","api-portal")}`)+
    `<div class="metrics">${metric("策略可配参数","22 项","快捷表单 7 项 + 调测 JSON 15 项")}${metric("已支持接入场景","6 大类","输入 / 输出 / 多轮 / 流式 / 诊断 / 批量")}${metric("已就绪数据面 API","12 个","/v1/guard/* · /v1/chat/* · /v1/audit/*")}${metric("暂不支持边界","6 类","已在控制台对应位置置灰标注")}</div>`+
    `<div class="split">${panel("一、安全策略的两种创建与配置方式",`<div class="panel-body">
      <div class="numbered"><span>1</span><div><strong>方式 A：快捷表单创建（【安全策略】页面 → ＋ 创建策略 / 新建版本）</strong><p>适合日常快速配置：直接通过可视化表单设置风险阈值、PII 动作（阻断/脱敏/仅审计）、超时时间、异常处置、流式窗口字符数、争议内容开关及附加拦截词等 7 项核心参数。</p></div></div>
      <div class="numbered"><span>2</span><div><strong>方式 B：专家全量调测创建（【提示词调测】页面 → 保存为策略新版本）</strong><p>适合深度定制：可载入 4 套行业预设（标准回归 / 政务金融严格 / 教育防误报 / 流式诊断），编辑包含 Gen 提示词、TC260 分类权重、反混淆/越狱开关、Stream 阈值等全部 22 项参数的 JSON，先通过 Prompt 预览和 Baseline vs Candidate A/B 实测对比，再一键保存为策略新版本。</p></div></div>
      <div class="numbered"><span>3</span><div><strong>版本发布门禁与接入闭环</strong><p>首次创建的 v1 版本可直接发布；后续升级版本（v2+）须在【评测任务】完成带标签回归评测且全部通过方可发布（历史已发布版本可随时回滚）。发布后在【应用接入】绑定该策略并生成 API Key 即可生效。</p></div></div>
    </div>`)}
    ${panel("接入流程速览",`<div class="panel-body">
      <div class="check-row"><span class="check-icon">◇</span><div class="grow"><strong>步骤 1：创建并发布安全策略</strong><p>在【安全策略】或【提示词调测】保存草稿并发布版本</p></div>${button("去配置","navigate","policies","small")}</div>
      <div class="check-row"><span class="check-icon">▦</span><div class="grow"><strong>步骤 2：创建业务应用并绑定策略</strong><p>区分 sandbox（沙盒联调）与 production（生产计量）环境</p></div>${button("去创建","navigate","applications","small")}</div>
      <div class="check-row"><span class="check-icon">⌘</span><div class="grow"><strong>步骤 3：签发受限 API Key 凭证</strong><p>按需勾选 detect、chat、audit:read 权限域与每分钟 RPM 配额</p></div>${button("管理凭证","navigate","applications","small")}</div>
      <div class="check-row"><span class="check-icon">◍</span><div class="grow"><strong>步骤 4：在线调试与多语言代码接入</strong><p>在【API 在线调试】验证响应并复制 Python/Node/Go/Java/cURL 代码</p></div>${button("在线调试","navigate","api-portal","small primary")}</div>
    </div>`)}</div>`+
    panel("二、当前已支持的 6 大业务接入场景（✅ 已完整闭环，可直接接入）",table(["业务接入场景","对应 API 接口","策略生效机制与场景说明","状态"],supportedScenarios.map(([title,apiPath,desc,st])=>`<tr><td><strong>${esc(title)}</strong></td><td><code>${esc(apiPath)}</code></td><td>${esc(desc)}</td><td>${badge(st)}</td></tr>`)),button("前往 API 在线调试 →","navigate","api-portal","small primary"))+
    panel("三、当前不能实现的接入场景与边界说明（🚧 未开发完成或受架构限制，已在界面置灰）",table(["暂不支持的场景","原因与当前状态说明","替代接入方案 / 运行边界","状态"],unsupportedScenarios.map(([title,reason,alt,st])=>`<tr class="todo-row"><td><strong>${esc(title)}</strong></td><td>${esc(reason)}</td><td>${esc(alt)}</td><td>${badge(st)}</td></tr>`)))+
    panel("四、安全策略全量参数词典（共 22 项可配置参数）",table(["参数字段名","所属模块","默认值 / 范围","实际执行与拦截逻辑"],paramRows.map(([k,mod,defVal,desc])=>`<tr><td><code>${esc(k)}</code></td><td>${badge(mod)}</td><td><span class="mono">${esc(defVal)}</span></td><td>${esc(desc)}</td></tr>`)),button("前往提示词调测编辑完整参数 →","navigate","tuning","small"));
}

function developers(){
  const sample=`import os\nimport requests\n\nBASE_URL = "${location.origin}"\nHEADERS = {"Authorization": f"Bearer {os.environ['QG_API_KEY']}"}\n\n# 1. 使用 API Key 动态配置当前应用的安全策略（平台级策略 REST API）\npolicy_resp = requests.put(\n    f"{BASE_URL}/v1/policies/current",\n    headers=HEADERS,\n    json={\n        "risk_threshold": 0.45,\n        "pii_action": "mask",\n        "custom_block_keywords": ["内部机密代号"],\n    },\n    timeout=15,\n)\npolicy_resp.raise_for_status()\n\n# 2. 使用同一 API Key 调用实时内容安全检测 API\ndetect_resp = requests.post(\n    f"{BASE_URL}/v1/guard/detect",\n    headers=HEADERS,\n    json={"prompt": "请帮我整理会议纪要，联系人手机 13812345678"},\n    timeout=35,\n)\ndetect_resp.raise_for_status()\nresult = detect_resp.json()\nprint(result["decision"], result.get("sanitized_content"), result["request_id"])`;
  return heading("开发者中心","通过应用凭证接入真实审核与平台级策略配置 API，按明确的接口契约处理结果。",`${can("admin","developer")?button("＋ 创建 API Key","quick-new-key","","primary"):""}${button("功能与接入指南","navigate","guide")}<a href="/docs" target="_blank" rel="noopener"><button>OpenAPI 文档 ↗</button></a>${disabledButton("官方 SDK 包下载","P1/C01 待开发：独立封装的官方多语言 SDK 包与外部系统兼容认证尚未发布","")}`)+
    `<div class="split">${panel("快速接入（API Key 同时支持策略配置与检测调用）",`<div class="panel-body"><div class="numbered"><span>1</span><div><strong>登录后一键创建 API Key</strong><p>点击右上角「＋ 创建 API Key」（或调用 <code>POST /api/admin/keys</code>），默认授予 <code>detect,chat,audit:read,policy:manage</code> 全功能权限。</p></div></div><div class="numbered"><span>2</span><div><strong>使用 API Key 配置安全策略</strong><p>通过 <code>GET/PUT /v1/policies/current</code>、<code>POST /v1/policies</code> 或 <code>/api/admin/policies</code> 动态创建与更新 22 项安全策略参数。</p></div></div><div class="numbered"><span>3</span><div><strong>使用 API Key 调用检测与护栏</strong><p>调用 <code>/v1/guard/detect</code>、<code>/v1/guard/stream</code>、<code>/v1/chat/completions</code>：allow 放行，block 阻断，mask 使用脱敏文本。</p></div></div><pre class="code-block">${esc(sample)}</pre></div>`)}
    ${panel("接口与处理约定",`<div class="panel-body"><div class="check-row"><div><strong>GET / PUT /v1/policies/current · POST /v1/policies</strong><p>使用 API Key 查询、创建、发布与热更新安全策略配置</p></div>${badge("completed")}</div><div class="check-row"><div><strong>POST /v1/guard/detect · /v1/guard/input · /v1/guard/output</strong><p>文本 / 多轮上下文 / 回复审核 / PII 脱敏</p></div>${badge("completed")}</div><div class="check-row"><div><strong>POST /v1/guard/stream · /v1/guard/stream/sse</strong><p>Qwen3Guard-Stream 逐 Token 风险扫描与熔断诊断</p></div>${badge("completed")}</div><div class="check-row"><div><strong>POST /v1/guard/batch · /v1/moderations</strong><p>最多 50 条批量审核；OpenAI Moderations 兼容接口</p></div>${badge("completed")}</div><div class="check-row"><div><strong>POST /v1/chat/completions</strong><p>真实增量生成与流式护栏；未审核窗口不会释放</p></div>${badge("completed")}</div><div class="check-row"><div><strong>GET /v1/audit/logs · /v1/audit/summary</strong><p>本应用检测审计日志与阻断率统计；要求 audit:read</p></div>${badge("completed")}</div><div class="check-row todo-row" title="M01～M05 待开发：多模态接口尚未实现"><div><strong>多模态审核（图片 / 音视频 / 文档）</strong><p>暂未开放；非 text 类型请求返回 422</p></div>${badge("todo")}</div><div class="section-label">错误处理</div><p class="help">401 认证失败 · 403 权限不足 · 422 参数不支持 · 429 额度耗尽 · 503 过载/引擎不可用 · 504 检测超时。</p></div>`)}</div>`;
}

async function settings(){
  const operations=can("admin","auditor","operator")?await api(scoped("/api/admin/operations")):{items:[]};
  const hooks=can("admin","operator")?await api(scoped("/api/admin/webhooks")):{items:[],deliveries:[]};
  state.cache.hooks=hooks.items;
  let system=null;if(state.user.is_admin)system=await api("/api/admin/system");
  const modalityRows=[
    ["文本内容审核 (Text)","已就绪 · 支持单轮/多轮/流式护栏/Token 诊断","completed",false],
    ["图片 / OCR 视觉审核 (M02)","未开发完成 · 图像及图文跨模态审核待接入","todo",true],
    ["音频 / ASR 语音审核 (M03)","未开发完成 · 音频解码与分段转写审核待接入","todo",true],
    ["视频抽帧与音画审核 (M04)","未开发完成 · 视频抽帧与音轨联合审核待接入","todo",true],
    ["PDF / Office 文档解析 (M05)","未开发完成 · 文档解析、扫描页 OCR 与内嵌图审核待接入","todo",true],
    ["多实例分布式调度与 Redis 限流 (O02)","未开发完成 · 当前为单进程协调器 (single-coordinator)","todo",true],
  ];
  return heading("系统管理","维护成员权限、告警投递与运行状态。",`${button("修改密码","change-password")}${can("admin")?button("项目成员","members"):""}${state.user.is_admin?button("创建账户","new-user")+disabledButton("账户启停管理","U02 待开发：前端成员列表与启停操作界面尚未完成","")+disabledButton("SSO / OIDC","P2/S03 待开发：企业单点登录与组织同步尚未实现","")+disabledButton("主密钥轮换","P0/O03 待开发：PLATFORM_SECRET 在线解密重加密迁移工具尚未实现",""):""}`)+
    (system?`<div class="metrics">${metric("检测引擎",system.model.loaded?"已就绪":"未就绪","沿用已部署模型")}${metric("推理队列",`${system.inference_pending} / ${system.inference_capacity}`,"有界队列 · 超时不提前释放执行槽")}${metric("数据存储",system.database,"事务持久化 · Schema v2")}${metric("支持模态","仅文本","图片 / 音频 / 视频 / 文档已置灰待开发")}</div>`:"")+
    panel("模块与多模态能力状态（未开发完成功能已置灰）",`<div class="panel-body">${modalityRows.map(([title,desc,st,isTodo])=>`<div class="check-row ${isTodo?"todo-row":""}"><div class="grow"><strong>${esc(title)}</strong><p>${esc(desc)}</p></div>${badge(st)}</div>`).join("")}</div>`)+
    (system?panel("GPU 与模型详情",json(system.model)):"")+panel("告警 Webhook",hooks.items.length?table(["通知目标","状态","操作"],hooks.items.map(h=>`<tr><td>${esc(h.url)}</td><td>${badge(h.enabled?"启用":"停用")}</td><td><div class="actions">${can("admin")&&h.enabled?button("停用","disable-hook",h.id,"small danger"):""}${disabledButton("测试发送","P1/A02 待开发：Webhook 手动连通性测试尚未实现","small")}</div></td></tr>`)):empty("尚未配置通知渠道","风险事件已在平台内保存；配置 Webhook 后可签名推送到业务告警系统。"),can("admin")?button("＋ 通知渠道","new-hook","","small")+disabledButton("通知模板配置","P1/A02 待开发：自定义告警报文模板尚未实现","small"):"")+
    panel("最近投递",hooks.deliveries.length?table(["投递 ID","状态","尝试次数","时间","操作"],hooks.deliveries.map(d=>`<tr><td><code>${esc(d.id.slice(0,16))}</code></td><td>${badge(d.state)}</td><td>${d.attempts} / 5</td><td>${date(d.created_at)}</td><td>${disabledButton("人工重投","P1/A02 待开发：失败或历史投递手动重投尚未实现","small")}</td></tr>`)):empty("暂无投递","风险事件与待投递消息在同一事务中保存，失败后最多重试 5 次。"))+
    panel("操作日志",operations.items.length?table(["时间","操作","操作者","对象"],operations.items.map(o=>`<tr><td>${date(o.created_at)}</td><td>${esc(o.action)}</td><td><code>${esc(o.actor_id.slice(0,10))}</code></td><td><code>${esc(o.target_id.slice(0,16))}</code></td></tr>`)):empty("暂无操作日志","项目配置、密钥与复核变更将记录在这里。"));
}

export async function renderPage(){
  if(state.page==="guide")return guide();
  if(!state.project)return heading("开始使用 QwenGuard","建立项目，将业务接入、策略和审计组织在同一工作空间。")+
    panel("创建工作空间",empty("还没有可访问的项目",state.user.is_admin?"创建项目后即可配置策略并接入第一个业务应用。":"请联系管理员将你的账户加入项目。",state.user.is_admin?button("＋ 创建项目","new-project","","primary"):""));
  if(["qbank","tuning","inspector","reports","api-portal"].includes(state.page))return renderWorkbench(state.page);
  return await ({overview,guide,applications,detections,policies,endpoints,evaluations,incidents,developers,settings}[state.page]||overview)();
}
