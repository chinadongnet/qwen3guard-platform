import {api,state,scoped,esc,date,number,can} from "./api.js?v=3.2.2";
import {button,badge,empty,panel,table,metric,heading,detectionTable,json} from "./components.js?v=3.2.2";
import {renderWorkbench} from "./workbench.js?v=3.2.2";

export const pages=[
  ["overview","运营总览","◈"],["applications","应用接入","▦"],["detections","检测记录","≡"],
  ["policies","安全策略","◇"],["endpoints","API 资产","⇄"],["evaluations","评测任务","▤"],
  ["incidents","风险事件","◉"],["qbank","题库管理","▥"],["tuning","提示词调测","⚒"],
  ["inspector","检测与攻防","◍"],["reports","评测报告","▤"],["api-portal","API 在线调试","⌘"],
  ["developers","开发者中心","⌘"],["settings","系统管理","⚙"]
];

export function shell(){
  const name=state.user.username;
  return `<div class="shell"><aside class="sidebar">
    <div class="brand"><span class="mark">Q</span><div class="brand-text"><strong>QwenGuard</strong><small>AI SECURITY PLATFORM</small></div></div>
    <div class="nav-caption">安全工作空间</div>
    <nav>${pages.map(([id,label,icon],index)=>`${index===7?'<div class="nav-caption">平台与接入</div>':""}<button class="nav-button ${state.page===id?"active":""}" data-action="navigate" data-id="${id}"><span class="nav-icon">${icon}</span><span class="nav-label">${label}</span></button>`).join("")}</nav>
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
  const data=await api(scoped("/api/admin/applications"));state.cache.applications=data.items;
  const action=can("admin","developer")?button("＋ 创建应用","new-application","","primary"):"";
  const rows=data.items.map(item=>`<tr><td><strong>${esc(item.name)}</strong><div class="subline mono">${esc(item.id.slice(0,16))}</div></td><td>${badge(item.environment)}</td><td><code>${esc(item.policy_id.slice(0,12))}</code></td><td>${badge(item.enabled?"可用":"已停用")}</td><td>${date(item.created_at)}</td><td><div class="actions">${can("admin","developer")?button("凭证","keys",item.id,"small"):""}${can("admin")?button("设置","edit-application",item.id,"small")+button(item.enabled?"停用":"启用","toggle-application",item.id,"small"):""}${can("admin","developer","operator")?button("验证接入","test-application",item.id,"small quiet"):""}</div></td></tr>`);
  return heading("应用接入","为每个业务系统分配独立凭证、环境与安全策略。",action)+
    `<div class="notice">密钥仅在创建时显示一次。控制台验证使用当前用户权限，验证流量不会计入生产指标。</div>`+
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
  return heading("安全策略","先保存草稿，再发布不可变版本；历史请求保留原始策略快照。",can("admin")?button("＋ 创建策略","new-policy","","primary"):"")+
    `<div class="notice">应用自动使用绑定策略的已发布版本。发布与回滚均记录操作日志，单次检测固定使用一个版本。</div>`+
    (data.items.length?`<div class="cards">${data.items.map(p=>{
      const latest=p.versions[0],published=p.versions.find(v=>v.version===p.published_version),cfg=(published||latest).config;
      return `<article class="policy-card"><div class="actions"><h3 class="spacer">${esc(p.name)}</h3>${badge(p.published_version?`生效 v${p.published_version}`:"未发布")}</div><div class="subline">最新草稿 v${latest.version} · ${date(latest.created_at)}</div><div class="policy-values"><div><span>风险阈值</span>${cfg.risk_threshold}</div><div><span>PII 处理</span>${esc(cfg.pii_action)}</div><div><span>检测超时</span>${cfg.timeout_seconds} 秒</div><div><span>异常处置</span>${esc(cfg.failure_action)}</div></div><div class="actions">${button("版本与差异","policy-detail",p.id,"small")}${can("admin")?button("新建版本","new-version",p.id,"small")+button("发布 / 回滚","publish-policy",p.id,"small primary"):""}</div></article>`;
    }).join("")}</div>`:panel("策略列表",empty("还没有安全策略","创建策略草稿，确认风险阈值与 PII 处置后发布。")));
}

async function endpoints(){
  const data=await api(scoped("/api/admin/endpoints"));state.cache.endpoints=data.items;
  return heading("API 资产","登记企业模型 API，开展连接验证和持续安全评测。",can("admin")?button("＋ 注册端点","new-endpoint","","primary"):"")+
    `<div class="notice">填写完整的 Chat Completions 地址。上游凭证加密保存；内网目标需要部署白名单授权。</div>`+
    panel("模型服务端点",data.items.length?table(["名称 / 模型","端点地址","状态","创建时间","操作"],data.items.map(e=>`<tr><td><strong>${esc(e.name)}</strong><div class="subline">${esc(e.model)}</div></td><td><span class="clip mono">${esc(e.url)}</span></td><td>${badge(e.enabled?"可用":"停用")}</td><td>${date(e.created_at)}</td><td>${can("admin")?button("测试连接","test-endpoint",e.id,"small"):""}</td></tr>`)):empty("尚未注册模型服务","注册目标后，可创建任务检测它的实际回复。直接文本审核不需要配置外部端点。"));
}

async function evaluations(){
  const data=await api(scoped("/api/admin/evaluations"));state.cache.evaluations=data.items;
  return heading("评测任务","使用版本化样本检测业务模型，保留逐项证据与失败记录。",`${button("刷新","refresh")}${can("admin","operator")?button("＋ 创建评测","new-evaluation","","primary"):""}`)+
    `<div class="notice warning">自动评审结果用于回归与风险发现。准确率仅针对提供标签的样本计算，不代表独立认证或线上合规率。</div>`+
    panel("任务队列",data.items.length?table(["任务名称","状态","进度","样本版本","创建时间","操作"],data.items.map(j=>`<tr><td><strong>${esc(j.name)}</strong><div class="subline">${j.endpoint_id?"目标 API 回复评测":"文本检测回归"}</div></td><td>${badge(j.state)}</td><td><progress value="${j.completed}" max="${j.total}" aria-label="任务进度"></progress><div class="subline">${j.completed} / ${j.total}</div></td><td><code>${esc(j.dataset_hash.slice(0,10))}</code></td><td>${date(j.created_at)}</td><td><div class="actions">${button("报告","evaluation-detail",j.id,"small")}${can("admin","operator")?(["running","queued"].includes(j.state)?button("取消","cancel-evaluation",j.id,"small danger"):["interrupted","failed","cancelled"].includes(j.state)?button("恢复","resume-evaluation",j.id,"small"):""):""}</div></td></tr>`)):empty("还没有评测任务","上传 JSON 样本或填写测试集，评测任务将在后台逐项执行。"));
}

async function incidents(){
  const data=await api(scoped("/api/admin/incidents"));state.cache.incidents=data.items;
  return heading("风险事件","将审核发现转为可跟进的工作，追加复核记录并保留机器原判。",button("刷新","refresh"))+
    panel("事件列表",data.items.length?table(["事件","环境 / 来源","级别","状态","负责人","发现时间","操作"],data.items.map(i=>`<tr><td><code>${esc(i.id.slice(0,14))}</code><div class="subline">${i.reviews.length} 条复核记录</div></td><td>${badge(i.environment)}<div class="subline">${esc(i.source)}</div></td><td>${badge(i.severity)}</td><td>${badge(i.state)}</td><td>${esc(i.assignee||"待分配")}</td><td>${date(i.created_at)}</td><td><div class="actions">${button("证据","detection",i.event_id,"small")}${button("处理记录","incident-detail",i.id,"small")}${can("admin","operator")?button("复核","review-incident",i.id,"small primary"):""}</div></td></tr>`)):empty("暂无风险事件","阻断或待复核的检测将自动生成事件。"));
}

function developers(){
  const sample=`import os\nimport requests\n\nresponse = requests.post(\n    "${location.origin}/v1/guard/detect",\n    headers={"Authorization": f"Bearer {os.environ['QG_API_KEY']}"},\n    json={"prompt": "请帮我整理会议纪要"},\n    timeout=35,\n)\nresponse.raise_for_status()\nresult = response.json()\nprint(result["decision"], result["request_id"])`;
  return heading("开发者中心","通过应用凭证接入真实审核，按明确的接口契约处理结果。",`<a href="/docs" target="_blank" rel="noopener"><button>OpenAPI 文档 ↗</button></a>`)+
    `<div class="split">${panel("快速接入",`<div class="panel-body"><div class="numbered"><span>1</span><div><strong>创建应用并绑定策略</strong><p>选择生产或沙盒环境，为业务系统建立独立作用域。</p></div></div><div class="numbered"><span>2</span><div><strong>创建应用凭证</strong><p>按需启用 detect、chat、audit:read。将密钥存入服务端密钥管理器。</p></div></div><div class="numbered"><span>3</span><div><strong>调用并处理结果</strong><p>allow 放行，block 阻断，mask 使用脱敏文本，review 转人工复核。</p></div></div><pre class="code-block">${esc(sample)}</pre></div>`)}
    ${panel("接口与处理约定",`<div class="panel-body"><div class="check-row"><div><strong>POST /v1/guard/detect</strong><p>文本 / 多轮上下文 / 可选回复审核</p></div></div><div class="check-row"><div><strong>POST /v1/guard/batch</strong><p>最多 50 条；额度按条计，逐项报告失败</p></div></div><div class="check-row"><div><strong>POST /v1/chat/completions</strong><p>真实增量生成；未审核窗口不会释放</p></div></div><div class="check-row"><div><strong>GET /v1/audit/logs</strong><p>仅本应用记录；要求 audit:read</p></div></div><div class="section-label">错误处理</div><p class="help">401 认证失败 · 403 权限不足 · 422 参数不支持 · 429 额度耗尽 · 503 过载/引擎不可用 · 504 检测超时。</p><p class="help">OpenAI 风格文本 Chat 子集；Moderation 类别为平台自定义策略评分。多模态输入暂未开放。</p></div>`)}</div>`;
}

async function settings(){
  const operations=can("admin","auditor","operator")?await api(scoped("/api/admin/operations")):{items:[]};
  const hooks=can("admin","operator")?await api(scoped("/api/admin/webhooks")):{items:[],deliveries:[]};
  state.cache.hooks=hooks.items;
  let system=null;if(state.user.is_admin)system=await api("/api/admin/system");
  return heading("系统管理","维护成员权限、告警投递与运行状态。",`${button("修改密码","change-password")}${can("admin")?button("项目成员","members"):""}${state.user.is_admin?button("创建账户","new-user"):""}`)+
    (system?`<div class="metrics">${metric("检测引擎",system.model.loaded?"已就绪":"未就绪","沿用已部署模型")}${metric("推理队列",`${system.inference_pending} / ${system.inference_capacity}`,"有界队列 · 超时不提前释放执行槽")}${metric("数据存储",system.database,"事务持久化 · Schema v2")}${metric("支持模态","文本","图片 / 音频 / 视频 / 文档已加入 Todo")}</div>`:"")+
    (system?panel("GPU 与模型详情",json(system.model)):"")+panel("告警 Webhook",hooks.items.length?table(["通知目标","状态","操作"],hooks.items.map(h=>`<tr><td>${esc(h.url)}</td><td>${badge(h.enabled?"启用":"停用")}</td><td>${can("admin")&&h.enabled?button("停用","disable-hook",h.id,"small danger"):""}</td></tr>`)):empty("尚未配置通知渠道","风险事件已在平台内保存；配置 Webhook 后可签名推送到业务告警系统。"),can("admin")?button("＋ 通知渠道","new-hook","","small"):"")+
    panel("最近投递",hooks.deliveries.length?table(["投递 ID","状态","尝试次数","时间"],hooks.deliveries.map(d=>`<tr><td><code>${esc(d.id.slice(0,16))}</code></td><td>${badge(d.state)}</td><td>${d.attempts} / 5</td><td>${date(d.created_at)}</td></tr>`)):empty("暂无投递","风险事件与待投递消息在同一事务中保存，失败后最多重试 5 次。"))+
    panel("操作日志",operations.items.length?table(["时间","操作","操作者","对象"],operations.items.map(o=>`<tr><td>${date(o.created_at)}</td><td>${esc(o.action)}</td><td><code>${esc(o.actor_id.slice(0,10))}</code></td><td><code>${esc(o.target_id.slice(0,16))}</code></td></tr>`)):empty("暂无操作日志","项目配置、密钥与复核变更将记录在这里。"));
}

export async function renderPage(){
  if(!state.project)return heading("开始使用 QwenGuard","建立项目，将业务接入、策略和审计组织在同一工作空间。")+
    panel("创建工作空间",empty("还没有可访问的项目",state.user.is_admin?"创建项目后即可配置策略并接入第一个业务应用。":"请联系管理员将你的账户加入项目。",state.user.is_admin?button("＋ 创建项目","new-project","","primary"):""));
  if(["qbank","tuning","inspector","reports","api-portal"].includes(state.page))return renderWorkbench(state.page);
  return await ({overview,applications,detections,policies,endpoints,evaluations,incidents,developers,settings}[state.page]||overview)();
}
