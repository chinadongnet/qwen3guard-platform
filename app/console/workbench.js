import {api,state,scoped,esc,date,number,can,notify,uuid,copyText} from "./api.js?v=3.2.2";
import {button,badge,empty,panel,table,heading,field,formModal,modal,json,metric} from "./components.js?v=3.2.2";
import {AB_SAMPLES,DETECT_PRESETS,STREAM_PRESETS,LLM_PRESETS} from "./samples.js?v=3.2.2";
let ui;
export const initWorkbench=value=>{ui=value;};
const base="/api/admin/workbench";
const opts=items=>items.map(i=>({value:i.id,label:i.name}));
const apps=async()=> (await api(scoped("/api/admin/applications"))).items;
const selectedApp=items=>field("application_id","业务应用",{options:opts(items),wide:true});
function exportFile(name,value,type="application/json"){
  const url=URL.createObjectURL(new Blob([typeof value==="string"?value:JSON.stringify(value,null,2)],{type}));
  const a=document.createElement("a");a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
async function fetchDownload(path,name){
  const response=await fetch(path,{credentials:"same-origin"});
  if(!response.ok)throw new Error((await response.json()).error?.message||"导出失败");
  exportFile(name,await response.text(),response.headers.get("content-type"));
}
function caseContent(item){
  return Object.fromEntries(["prompt","response","expected_unsafe","response_expected_unsafe","evaluation_target","label_source","source_quality_result","sub_code","sub_name","major_code","major_name","suite","attack_method","tag"].map(k=>[k,k==="response_expected_unsafe"?(item[k]??null):item[k]]));
}
const appRequired=items=>{if(!items.length)throw new Error("请先创建应用并发布策略");};
const sample={prompt:"请介绍办公室节约用电的方法。",response:"",expected_unsafe:false,response_expected_unsafe:null,sub_code:"BENIGN",attack_method:"无指令攻击"};
const sampleLabels={dan:"角色越狱",obf:"符号混淆",fill:"填词陷阱",edge:"边界争议",benign:"正常问答",cond:"条件触发",sys:"提示词 / 工具注入",pii:"个人信息",plc:"工业控制",bomb:"危险制作",suicide:"自伤风险",monopoly:"商业风险",safe:"正常科普"};
function sampleFields(tuning=false){
  const groups=tuning?{ab:AB_SAMPLES}:{detect:DETECT_PRESETS,stream:STREAM_PRESETS,llm:LLM_PRESETS};
  return field("sample","原版测试样例",{wide:true,options:Object.entries(groups).flatMap(([g,items])=>Object.keys(items).map(k=>({value:g+":"+k,label:`${g} · ${sampleLabels[k]||k}`})))})+button("填入样例","load-sample");
}

async function qbank(){
  const f=state.cache.bankFilter||{dataset:"curated"};
  const query=new URLSearchParams({...f,offset:String(state.cache.bankOffset||0),limit:"30"});
  const data=await api(scoped(`${base}/cases?${query}`));state.cache.bank=data;
  const controls=can("admin","operator")?button("导入原始题库","seed-bank")+button("新增题目","new-case")+button("导入 JSON","import-bank")+button("评测选中 / 全库","evaluate-bank","","primary"):"";
  return heading("题库管理","原始精选与完整题库、项目自有样本；标签用于评测，不参与线上决策。",controls)+
    `<div class="metrics">${metric("当前筛选",data.total,"真实题目数")}${metric("预期拦截",data.stats.unsafe,"人工/原始数据标签")}${metric("预期放行",data.stats.benign,`按标注对象 · 未标注 ${data.stats.unlabeled||0}`)}${metric("覆盖子类",data.stats.subcategories,"原题库分类")}</div>`+
    `<section class="panel"><form id="bank-filter" class="filters"><select name="dataset" aria-label="题库">${["curated","full","custom"].map(k=>`<option value="${k}" ${f.dataset===k?"selected":""}>${({curated:"精选题库",full:"完整题库",custom:"自有样本"})[k]}</option>`).join("")}</select><input name="search" aria-label="题目搜索" placeholder="搜索内容、标签、ID" value="${esc(f.search||"")}"><input name="sub_code" placeholder="分类，如 A.1" value="${esc(f.sub_code||"")}"><input name="attack_method" placeholder="攻击方法" value="${esc(f.attack_method||"")}"><select name="expected_unsafe"><option value="">全部标签</option><option value="true" ${f.expected_unsafe==="true"?"selected":""}>预期拦截</option><option value="false" ${f.expected_unsafe==="false"?"selected":""}>预期放行</option></select><select name="archived"><option value="false">有效题目</option><option value="true" ${f.archived==="true"?"selected":""}>已归档</option></select><button type="submit">筛选</button>${button("导出题库","export-bank")}${button("选择 / 取消本页","select-bank-page")}</form>`+
    (data.items.length?table(["选择","题目 / 版本","内容","分类 / 方法","标签","操作"],data.items.map(i=>`<tr><td><input type="checkbox" name="case-selection" value="${i.id}" ${(state.cache.bankSelection||[]).includes(i.id)?"checked":""} aria-label="选择 ${esc(i.case_key)}"></td><td><code>${esc(i.case_key)}</code><div class="subline">v${i.revision}</div></td><td><span class="clip">${esc(i.prompt)}</span></td><td>${esc(i.sub_code)}<div class="subline">${esc(i.attack_method)}</div></td><td>${i.label_expected_unsafe==null?"未标注":badge(i.label_expected_unsafe?"block":"allow")}<div class="subline">${i.evaluation_target==="output"?"回复标签":"输入标签"}</div></td><td><div class="actions">${button("查看 / 编辑","edit-case",i.id,"small")}${button("历史","case-history",i.id,"small")}${can("admin","operator")?button(i.archived?"恢复":"归档","archive-case",i.id,"small"):""}</div></td></tr>`)):empty("题库尚无样本","导入原始题库或创建项目自己的样本。"))+
    `<div class="footnote actions">${button("上一页","bank-prev","","small")}${button("下一页","bank-next","","small")}<span>第 ${Math.floor((state.cache.bankOffset||0)/30)+1} 页 · ${data.total} 条</span></div></section>`;
}

async function tuning(){
  const [policies,presets,applications]=await Promise.all([api(scoped("/api/admin/policies")),api(scoped(`${base}/presets`)),apps()]);
  state.cache.labApps=applications;state.cache.labPolicies=policies.items;state.cache.presets=presets;
  const cfg=state.cache.tuningConfig||policies.items[0]?.versions[0]?.config||presets.defaults;
  return heading("提示词与参数调测","完整 Prompt、分类权重、推理参数与 A/B 对比；保存草稿后按版本评测发布。")+
    `<div class="notice">${esc(presets.notice)}</div><section class="panel"><form id="tuning-form" class="panel-body"><div class="form-grid">${selectedApp(applications)}${sampleFields(true)}${field("preset","配置预设",{options:opts(presets.items),wide:true})}</div><div class="actions">${button("载入所选预设","load-preset")}${button("恢复默认草稿","default-draft")}</div><br><div class="form-grid">${field("config","完整候选配置 JSON",{type:"textarea",rows:18,wide:true,value:JSON.stringify(cfg,null,2),help:"包含输入/输出安全提示词、分类定义、扩展规则、权重、Gen/Stream/LLM 参数。不会直接热改生产。"})}${field("prompt","调测输入",{type:"textarea",wide:true,value:"请介绍办公室节约用电的方法。"})}${field("response","待审核回复（可选）",{type:"textarea",wide:true,required:false})}</div><div class="actions">${button("编译 Prompt 预览","preview-prompt")}${button("运行 A/B 对比","run-ab","","primary")}${can("admin")?button("保存为策略新版本","save-tuning"):""}</div></form></section>`+
    panel("实验结果",`<div class="panel-body" id="lab-result">${empty("等待调测","Baseline 使用所选应用当前已发布策略；Candidate 使用上方配置。")}</div>`);
}

async function inspector(){
  const applications=await apps();state.cache.labApps=applications;
  return heading("检测与攻防实验室","恢复文本、多轮、反混淆、Stream Token 诊断和裸模型 / 护栏对比。")+
    `<div class="notice">实验流量与生产分离。Token 染色展示完整文本的真实模型诊断；生成前后对比仅在授权实验室内展示。</div><section class="panel"><form id="inspector-form" class="panel-body"><div class="form-grid">${selectedApp(applications)}${sampleFields()}${field("mode","实验类型",{wide:true,options:[{value:"detect",label:"单轮 / 多轮文本审核"},{value:"token-scan",label:"Stream Token 染色与截断诊断"},{value:"compare-generation",label:"裸模型 vs 护栏（同一输出）"},{value:"deobfuscate",label:"反混淆与脱敏工具"}]})}${field("prompt","输入内容",{type:"textarea",wide:true,value:"请介绍杭州的自然风光。"})}${field("response","待审核回复（可选）",{type:"textarea",wide:true,required:false})}${field("messages","多轮上下文 JSON（可选）",{type:"textarea",wide:true,required:false,help:"示例 [{\"role\":\"user\",\"content\":\"你好\"}]；仅文本审核使用。"})}</div><button class="primary" type="submit">运行实验</button></form></section>`+
    panel("实验结果",`<div class="panel-body" id="lab-result">${empty("等待实验","未完成的模型调用不会显示为安全。")}</div>`)+
    panel("最近实验",button("查看持久化实验记录","lab-history"));
}

function tokenResult(result){
  const tokens=result.result?.token_stream||result.token_stream||[];
  return (tokens.length?`<div class="notice">离线 Token 诊断回放 · ${tokens.length} 个 Token · ${esc(result.mode||"offline_token_diagnostic")}</div><div class="token-view">${tokens.map(t=>`<span class="badge ${t.risk_level==="Safe"?"good":"bad"}" title="${esc(`${t.index} · ${t.risk_level} · ${t.action}`)}">${esc(t.token)}</span>`).join("")}</div>`:"")+json(result);
}
function showResult(result){
  document.getElementById("lab-result").innerHTML=tokenResult(result);
}
async function reports(){
  const ledger=await api(scoped(`${base}/audit/summary?source=${state.environment}`));
  const data=await api(scoped("/api/admin/evaluations"));state.cache.reportJobs=data.items;
  return heading("评测报告中心","恢复按分类 / 攻击方法统计、逐题结果、报告导出与历史报告查看。",
    `${button("题库自检","navigate","qbank")}${button("攻防实验","navigate","inspector")}${button("版本报告对比","compare-reports")}${state.user.is_admin?button("旧版历史报告","historical-report"):""}`)+
    panel(`凭证审计对账 · ${state.environment}`,ledger.items.length?table(["凭证","条目","阻断","执行错误"],ledger.items.map(i=>`<tr><td>${esc(i.key_name)}<div class="subline">${esc(i.key_prefix)}</div></td><td>${i.total}</td><td>${i.blocked}</td><td>${i.errors}</td></tr>`)):empty("暂无调用","当前来源没有真实调用记录。"))+panel("已提交评测任务",data.items.length?table(["任务","状态","进度","数据集版本","操作"],data.items.map(j=>`<tr><td>${esc(j.name)}</td><td>${badge(j.state)}</td><td>${j.completed}/${j.total}</td><td><code>${esc(j.dataset_hash.slice(0,16))}</code></td><td>${button("分类报告","report-detail",j.id,"small")}${button("JSON","report-json",j.id,"small")}${button("CSV","report-csv",j.id,"small")}${button("Markdown","report-md",j.id,"small")}</td></tr>`)):empty("尚无评测任务","从题库选题或全库提交评测，结果会持久化在这里。"));
}
const endpointExamples={
  "/v1/guard/detect":{prompt:"请介绍杭州。"},
  "/v1/guard/input":{text:"请介绍杭州。"},
  "/v1/guard/output":{prompt:"介绍杭州",text:"杭州以西湖闻名。"},
  "/v1/guard/batch":{items:[{prompt:"请介绍杭州。"}]},
  "/v1/moderations":{input:"请介绍杭州。"},
  "/v1/guard/stream":{prompt:"介绍杭州",response:"杭州以西湖闻名。"},
  "/v1/guard/stream/sse":{prompt:"介绍杭州",response:"杭州以西湖闻名。"},
  "/v1/guard/deobfuscate":{text:"联系 sample@example.com",mask_pii:true},
  "/v1/chat/completions":{model:"Qwen3-0.6B-Guarded",messages:[{role:"user",content:"介绍杭州"}],max_tokens:64,stream:true},
  "/v1/audit/logs":null,"/v1/audit/summary":null,"/v1/guard/categories":null,"/v1/platform/catalog":null
};
function sdk(language,path,body){
  const url=location.origin+path,method=body===null?"GET":"POST",payload=JSON.stringify(body||{});
  if(language==="curl")return `curl '${url}' -X ${method} \\\n  -H "Authorization: Bearer $QG_API_KEY" \\\n  -H "Content-Type: application/json"${body===null?"":` \\\n  --data '${payload.replaceAll("'","'\\''")}'`}`;
  if(language==="python")return `import os, json, httpx\nwith httpx.stream("${method}", "${url}",\n    headers={"Authorization": "Bearer " + os.environ["QG_API_KEY"]},\n    ${body===null?"":`json=json.loads(${JSON.stringify(payload)}),\n    `}timeout=150) as response:\n    response.raise_for_status()\n    for line in response.iter_lines():\n        print(line)`;
  if(language==="node")return `const response = await fetch(${JSON.stringify(url)}, {\n  method: "${method}",\n  headers: {Authorization: "Bearer " + process.env.QG_API_KEY, "Content-Type": "application/json"}${body===null?"":`,\n  body: JSON.stringify(${payload})`}\n});\nif (!response.ok) throw new Error(await response.text());\nfor await (const chunk of response.body) process.stdout.write(chunk);`;
  if(language==="go")return `package main\nimport ("io";"os";"net/http";"strings";"time")\nfunc main() {\n req,err:=http.NewRequest("${method}",${JSON.stringify(url)},strings.NewReader(${JSON.stringify(body===null?"":payload)})); if err!=nil {panic(err)}\n req.Header.Set("Authorization","Bearer "+os.Getenv("QG_API_KEY"))\n req.Header.Set("Content-Type","application/json")\n client:=http.Client{Timeout:150*time.Second}\n res,err:=client.Do(req); if err!=nil {panic(err)}; defer res.Body.Close()\n if res.StatusCode>=400 {panic(res.Status)}\n io.Copy(os.Stdout,res.Body)\n}`;
  return `import java.net.URI;\nimport java.net.http.*;\nimport java.time.Duration;\nclass Example {\n public static void main(String[] args) throws Exception {\n  var req=HttpRequest.newBuilder(URI.create(${JSON.stringify(url)}))\n   .header("Authorization","Bearer "+System.getenv("QG_API_KEY"))\n   .header("Content-Type","application/json").timeout(Duration.ofSeconds(150))\n   .method("${method}",HttpRequest.BodyPublishers.ofString(${JSON.stringify(body===null?"":payload)})).build();\n  var res=HttpClient.newHttpClient().send(req,HttpResponse.BodyHandlers.ofInputStream());\n  if(res.statusCode()>=400)throw new RuntimeException("HTTP "+res.statusCode());\n  try(var body=res.body()){body.transferTo(System.out);}\n }\n}`;
}
async function portal(){
  const requested=new URLSearchParams(location.search).get("api");
  const path=Object.hasOwn(endpointExamples,requested)?requested:"/v1/guard/detect";
  state.cache.apiSchema=(await api("/openapi.json"));
  return heading("API 文档与在线调试","逐接口参数、可视化表单 / JSON 编辑、真实响应和多语言接入示例。")+
    `<div class="notice">使用你已持有的应用 Key；仅保留在当前表单，不保存到浏览器存储或服务端。调试请求按该应用真实环境计量。</div><section class="panel"><form id="portal-form" class="panel-body"><div class="form-grid">${field("endpoint","接口",{wide:true,options:Object.keys(endpointExamples).map(k=>({value:k,label:k})),value:path})}${field("token","应用 API Key",{type:"password",wide:true})}${field("body","请求 JSON",{type:"textarea",rows:8,wide:true,value:JSON.stringify(endpointExamples[path]||{},null,2)})}</div><div class="actions"><button type="submit" class="primary">发送请求</button>${button("切换可视化表单","portal-fields")}${button("格式化 JSON","portal-format")}${button("接口契约","portal-schema")}${button("取消请求","portal-cancel")}</div></form></section>`+
    panel("真实响应 / SSE",`<pre id="portal-response">等待请求</pre>`)+panel("多语言接入",`<div class="panel-body"><select id="sdk-language" aria-label="示例语言">${["python","curl","node","go","java"].map(k=>`<option value="${k}">${k}</option>`).join("")}</select>${button("生成示例","generate-sdk")}${button("复制示例","copy-sdk")}<pre id="sdk-code">${esc(sdk("python",path,endpointExamples[path]))}</pre></div>`);
}
function showReport(page=0, failures=false){
  const r=state.cache.activeReport,m=r.metrics;
  const items=r.results.filter(x=>!failures||x.result.passed===false||x.result.execution_status!=="completed");
  const pages=Math.max(1,Math.ceil(items.length/50));
  page=Math.max(0,Math.min(page,pages-1));state.cache.reportPage=page;state.cache.reportFailures=failures;
  const pct=x=>x==null?"—":`${(100*x).toFixed(2)}%`;
  const groups=rows=>table(["分类","样本","TP","TN","FP","FN","错误"],rows.map(i=>`<tr><td>${esc(i.label)}</td><td>${i.total}</td><td>${i.tp??"—"}</td><td>${i.tn??"—"}</td><td>${i.fp??"—"}</td><td>${i.fn??"—"}</td><td>${i.errors}</td></tr>`));
  const rows=items.slice(page*50,page*50+50).map(x=>{const v=x.result;return `<tr><td>${esc(v.case?.case_id||x.position)}</td><td>${v.expected_unsafe==null?"未标注":v.expected_unsafe?"拦截":"放行"}</td><td>${badge(v.decision||v.execution_status)}</td><td>${esc(v.model_assessment?.safety||"—")}</td><td>${v.passed===true?"通过":v.passed===false?"不一致":"未评分"}</td><td>${button("证据","report-item",x.id,"small")}</td></tr>`;});
  modal("评测报告",`${button("打印 / 保存 PDF","print-report")}<p class="notice">自动评测，标签未独立核验。${esc(r.name)} · ${esc(r.state)} · ${r.completed}/${r.total}。准确率只统计已评分样本；完整通过率将错误、待复核和未完成项计为未通过。</p>
    <div class="metrics">${metric("准确率",pct(m.accuracy),"已评分样本")}${metric("完整通过率",pct(m.acceptance_pass_rate),"全部标注样本")}${metric("漏报 / 误报",`${m.fn} / ${m.fp}`,"FN / FP")}${metric("执行错误",m.errors,`评分覆盖 ${pct(m.coverage)}`)}</div>
    <details><summary>完整指标与分母</summary>${json(m)}</details><h3>审核对象</h3>${groups(r.by_target||[])}<h3>来源题库</h3>${groups(r.by_suite||[])}<h3>风险分类</h3>${groups(r.by_subcategory)}<h3>攻击方法</h3>${groups(r.by_attack)}
    <h3>逐题结果</h3><div class="actions">${button(failures?"显示全部":"仅看不一致 / 错误","report-filter")}${button("上一页","report-prev")}${button("下一页","report-next")}<span>第 ${page+1}/${pages} 页 · ${items.length} 条</span></div>${table(["题目","标签","平台决策","模型分类","结果","明细"],rows)}`);
}
export async function renderWorkbench(page){
  return await ({qbank,tuning,inspector,reports,"api-portal":portal}[page])();
}
let requestController;
export const workbenchActions={
  async "original-detection"(id){modal("原始内容（访问已记录）",json(await api(`${base}/detections/${id}/original`)));},
  "load-sample"(){const form=document.getElementById("tuning-form")||document.getElementById("inspector-form");const [group,key]=form.elements.sample.value.split(":");const value=({ab:AB_SAMPLES,detect:DETECT_PRESETS,stream:STREAM_PRESETS,llm:LLM_PRESETS})[group][key];form.elements.prompt.value=typeof value==="string"?value:value.prompt;form.elements.response.value=typeof value==="string"?"":value.response||"";if(form.elements.mode)form.elements.mode.value=group==="stream"?"token-scan":group==="llm"?"compare-generation":"detect";},
  async "seed-bank"(){
    const f=state.cache.bankFilter||{dataset:"curated"};
    const dataset=f.dataset==="full"?"full":"curated";
    const r=await api(scoped(`${base}/banks/seed?dataset=${dataset}`),{method:"POST"});
    notify(`新增 ${r.inserted} 条，跳过已有 ${r.skipped} 条`);await ui.refresh();
  },
  "new-case"(){formModal("新增题目",field("content","题目 JSON",{type:"textarea",wide:true,rows:12,value:JSON.stringify(sample,null,2)}),async v=>{
    await api(scoped(`${base}/cases/import`),{method:"POST",body:{dataset:state.cache.bankFilter?.dataset||"curated",items:[JSON.parse(v.content)]}});await ui.saved("题目已保存");
  });},
  "import-bank"(){formModal("批量导入题库",field("content","JSON 数组或导出文件内容",{type:"textarea",wide:true,rows:12}),async v=>{
    const parsed=JSON.parse(v.content),items=Array.isArray(parsed)?parsed:parsed.items||parsed.cases;
    if(!Array.isArray(items))throw new Error("需要题目数组");
    const result=await api(scoped(`${base}/cases/import`),{method:"POST",body:{dataset:state.cache.bankFilter?.dataset||"curated",items:items.map(i=>({...caseContent(i),id:i.case_key||i.id||""}))}});
    await ui.saved(`新增 ${result.inserted} 条，跳过 ${result.skipped} 条`);
  });},
  "export-bank"(){return fetchDownload(scoped(`${base}/cases/export?dataset=${state.cache.bankFilter?.dataset||"curated"}`),"question-bank.json");},
  "edit-case"(id){
    const item=state.cache.bank.items.find(i=>i.id===id);
    if(!can("admin","operator")){modal("题目详情",json(item));return;}
    formModal(`编辑题目 · v${item.revision}`,field("content","题目 JSON",{type:"textarea",wide:true,rows:14,value:JSON.stringify(caseContent(item),null,2)}),async v=>{
      await api(`${base}/cases/${id}`,{method:"PUT",body:{expected_revision:item.revision,content:JSON.parse(v.content)}});await ui.saved("已保存新版本");
    });
  },
  async "case-history"(id){const data=await api(`${base}/cases/${id}/history`);state.cache.caseHistory=data.items;state.cache.historyCase=id;modal("题目版本历史",data.items.map(i=>`<div class="timeline"><strong>v${i.revision} · ${date(i.created_at)}</strong>${json(i.content)}${can("admin","operator")?button("恢复此内容为新版本","restore-case",i.id):""}</div>`).join(""));},
  async "restore-case"(id){const version=state.cache.caseHistory.find(i=>i.id===id),item=state.cache.bank.items.find(i=>i.id===state.cache.historyCase);await api(`${base}/cases/${item.id}`,{method:"PUT",body:{expected_revision:item.revision,content:version.content}});await ui.saved("已恢复为新版本");},
  async "archive-case"(id){const row=state.cache.bank.items.find(i=>i.id===id);await api(`${base}/cases/${id}/archived`,{method:"PUT",body:{enabled:!row.archived}});await ui.refresh();},
  "select-bank-page"(){const inputs=[...document.querySelectorAll('[name="case-selection"]')],enable=inputs.some(i=>!i.checked);for(const input of inputs){input.checked=enable;input.dispatchEvent(new Event("change",{bubbles:true}));}},
  "bank-prev"(){state.cache.bankOffset=Math.max(0,(state.cache.bankOffset||0)-30);return ui.refresh();},
  "bank-next"(){if((state.cache.bankOffset||0)+30<state.cache.bank.total){state.cache.bankOffset=(state.cache.bankOffset||0)+30;return ui.refresh();}},
  async "evaluate-bank"(){
    const ids=state.cache.bankSelection||[];
    const items=await apps();appRequired(items);
    formModal(ids.length?`评测选中 ${ids.length} 条`:"评测整个题库",selectedApp(items)+field("mode","评测方式",{wide:true,options:[{value:"text",label:"文本审核回归"},{value:"generation_compare",label:"批量裸模型 / 护栏攻防对比"}]})+field("target","审核对象",{wide:true,options:[{value:"auto",label:"按题库标注对象（推荐）"},{value:"input",label:"仅输入审核"},{value:"output",label:"仅已有回复审核"}],help:"输入标签不能给回复评分。输出评测使用 response_expected_unsafe；未标注只展示检测结果。"})+field("sample_count","样本量上限（可选）",{type:"number",min:1,max:5000,required:false,help:"留空评测全库；生成对比每任务最多 50 条。"})+field("policy_version","候选版本（可选）",{type:"number",min:1,required:false}),async v=>{
      const r=await api(scoped(`${base}/banks/evaluate`),{method:"POST",body:{application_id:v.application_id,dataset:state.cache.bankFilter?.dataset||"curated",case_ids:ids,mode:v.mode,target:v.target,sample_count:v.sample_count?Number(v.sample_count):null,policy_version:v.policy_version?Number(v.policy_version):null,idempotency_key:uuid()}});
      await ui.saved(`后台任务已提交：${r.id.slice(0,12)}`);ui.navigate("evaluations");
    },"提交评测","全库评测可能耗时较长，支持取消和恢复，结果与生产指标隔离。");
  },
  "load-preset"(){const form=document.getElementById("tuning-form");form.elements.config.value=JSON.stringify(state.cache.presets.items.find(p=>p.id===form.elements.preset.value).config,null,2);},
  "default-draft"(){document.getElementById("tuning-form").elements.config.value=JSON.stringify(state.cache.presets.defaults,null,2);},
  async "preview-prompt"(){showResult(await api(`${base}/prompt-preview`,{method:"POST",body:labBody()}));},
  async "run-ab"(){notify("正在依次运行 Baseline 与 Candidate…");showResult(await api(`${base}/ab-test`,{method:"POST",body:labBody()}));},
  async "save-tuning"(){
    const body=labBody(),app=state.cache.labApps.find(i=>i.id===body.application_id);if(!app)throw new Error("请选择应用");
    await api(`/api/admin/policies/${app.policy_id}/versions`,{method:"POST",body:body.config});notify("已保存策略草稿，请到安全策略中评测后发布");
  },
  async "lab-history"(){const r=await api(scoped(`${base}/runs`));modal("实验记录",r.items.length?table(["类型","时间","操作"],r.items.map(i=>`<tr><td>${esc(i.kind)}</td><td>${date(i.created_at)}</td><td>${button("查看","lab-detail",i.id)}</td></tr>`)):empty("暂无实验","运行实验后会保存结果。"));},
  async "lab-detail"(id){modal("实验详情",tokenResult((await api(`${base}/runs/${id}`)).result));},
  async "historical-report"(){modal("历史报告（非当前指标）",json(await api(`${base}/history/benchmark`)));},
  async "report-detail"(id){
    const r=await api(`${base}/reports/${id}`);state.cache.activeReport=r;
    showReport();
  },
  "report-filter"(){showReport(0,!state.cache.reportFailures);},
  "report-next"(){showReport(state.cache.reportPage+1,state.cache.reportFailures);},
  "report-prev"(){showReport(state.cache.reportPage-1,state.cache.reportFailures);},
  "report-back"(){showReport(state.cache.reportPage,state.cache.reportFailures);},
  "report-item"(id){const item=state.cache.activeReport.results.find(x=>x.id===id);modal("逐题审核证据",button("返回报告","report-back")+json(item));},
  "compare-reports"(){const jobs=state.cache.reportJobs;if(jobs.length<2)throw new Error("至少需要两份报告");formModal("比较两次评测",field("baseline","Baseline",{options:opts(jobs),wide:true})+field("candidate","Candidate",{options:opts(jobs),wide:true}),async v=>{const [a,b]=await Promise.all([api(`${base}/reports/${v.baseline}`),api(`${base}/reports/${v.candidate}`)]);modal("评测结果对比",`<p class="notice">${a.dataset_hash===b.dataset_hash?"数据集快照一致":"数据集快照不同，指标不可直接归因于策略变更"}</p>${table(["指标","Baseline","Candidate"],Object.keys(a.metrics).map(k=>`<tr><td>${esc(k)}</td><td>${esc(a.metrics[k]??"—")}</td><td>${esc(b.metrics[k]??"—")}</td></tr>`))}`);});},
  "print-report"(){window.print();},
  "report-json":id=>fetchDownload(`${base}/reports/${id}/export?format=json`,"evaluation.json"),
  "report-csv":id=>fetchDownload(`${base}/reports/${id}/export?format=csv`,"evaluation.csv"),
  "report-md":id=>fetchDownload(`${base}/reports/${id}/export?format=md`,"evaluation.md"),
  "export-audit-json":()=>fetchDownload(auditExport("json"),"audit.json"),
  "export-audit-csv":()=>fetchDownload(auditExport("csv"),"audit.csv"),
  async "promote-detection"(id){
    const row=await api(`/api/admin/detections/${id}`);
    formModal("沉淀为项目样本",field("content","确认内容与人工标签",{type:"textarea",wide:true,rows:12,value:JSON.stringify({...sample,prompt:row.prompt_preview,response:row.response_preview,expected_unsafe:row.decision==="block",sub_code:row.result.tc260?.sub_code||"BENIGN"},null,2)}),async v=>{
      await api(`${base}/detections/${id}/promote`,{method:"POST",body:JSON.parse(v.content)});await ui.saved("已加入自有样本题库");
    },"保存样本","审计只保存脱敏摘要；请补全需要测试的文本并核对标签。机器判定不是人工标准答案。");
  },
  "review-detection"(id){formModal("复核检测结果",field("state","结论",{options:[{value:"false_positive",label:"误报 / 更正"},{value:"resolved",label:"确认并处理"},{value:"investigating",label:"进一步调查"}]})+field("note","复核说明",{wide:true,type:"textarea"}),async v=>{await api(`${base}/detections/${id}/review`,{method:"POST",body:v});await ui.saved("已追加复核；机器原判保留");});},
  async "archive-audit"(){
    const ids=(state.cache.detectionItems||[]).map(i=>i.id);if(!ids.length)throw new Error("当前页没有记录");
    const archived=state.cache.detectionFilter?.archived!=="true";
    await api(scoped(`${base}/audit/archive`),{method:"POST",body:{ids,archived}});notify(archived?"当前页已归档，账本保留":"当前页已恢复");await ui.refresh();
  },
  "portal-cancel"(){requestController?.abort();},
  "portal-format"(){const f=document.getElementById("portal-form");f.elements.body.value=JSON.stringify(JSON.parse(f.elements.body.value),null,2);},
  "portal-schema"(){const path=document.getElementById("portal-form").elements.endpoint.value;modal("接口契约",json(state.cache.apiSchema.paths[path]||{}));},
  "portal-fields"(){
    const f=document.getElementById("portal-form"),body=JSON.parse(f.elements.body.value);
    formModal("可视化参数编辑",Object.entries(body).map(([k,v])=>field(k,k,{type:typeof v==="object"?"textarea":typeof v==="number"?"number":"text",wide:true,value:typeof v==="object"?JSON.stringify(v):String(v),required:false})).join(""),async values=>{
      for(const k of Object.keys(body)){const v=values[k];body[k]=typeof body[k]==="object"?JSON.parse(v):typeof body[k]==="number"?Number(v):typeof body[k]==="boolean"?v==="true":v;}
      f.elements.body.value=JSON.stringify(body,null,2);document.getElementById("dialog").close();
    },"应用到请求");
  },
  "generate-sdk"(){const f=document.getElementById("portal-form");document.getElementById("sdk-code").textContent=sdk(document.getElementById("sdk-language").value,f.elements.endpoint.value,endpointExamples[f.elements.endpoint.value]===null?null:JSON.parse(f.elements.body.value));},
  async "copy-sdk"(){await copyText(document.getElementById("sdk-code").textContent);notify("接入代码已复制");}
};
function auditExport(format){
  const f=state.cache.detectionFilter||{},p=new URLSearchParams({format});
  for(const key of ["application_id","key_id","source","decision"])if(f[key])p.set(key,f[key]);
  return scoped(`${base}/audit/export?${p}`);
}
function labBody(){
  const f=new FormData(document.getElementById("tuning-form"));
  if(!f.get("application_id"))throw new Error("请先创建并选择应用");
  return {application_id:f.get("application_id"),prompt:f.get("prompt"),response:f.get("response")||null,config:JSON.parse(f.get("config"))};
}
document.addEventListener("change",event=>{
  if(event.target.name==="case-selection"){const selected=new Set(state.cache.bankSelection||[]);if(event.target.checked)selected.add(event.target.value);else selected.delete(event.target.value);state.cache.bankSelection=[...selected];const b=document.querySelector('[data-action="evaluate-bank"]');if(b)b.textContent=`评测已选 ${selected.size} / 全库`;}

  if(event.target.name==="endpoint"&&event.target.closest("#portal-form")){
    document.getElementById("portal-form").elements.body.value=JSON.stringify(endpointExamples[event.target.value]||{},null,2);
  }
});
document.addEventListener("submit",async event=>{
  if(!["bank-filter","inspector-form","portal-form","tuning-form"].includes(event.target.id))return;
  event.preventDefault();const values=Object.fromEntries(new FormData(event.target));
  const submit=event.target.querySelector('[type="submit"]');if(submit)submit.disabled=true;
  try{
    if(event.target.id==="bank-filter"){if(values.dataset!==(state.cache.bankFilter?.dataset||"curated"))state.cache.bankSelection=[];state.cache.bankFilter=Object.fromEntries(Object.entries(values).filter(([,v])=>v!==""));state.cache.bankOffset=0;await ui.refresh();}
    if(event.target.id==="inspector-form"){
      notify("实验执行中…");
      let result;
      if(values.mode==="detect"){
        result=await api(`/api/admin/applications/${values.application_id}/test`,{method:"POST",body:{prompt:values.prompt,response:values.response||null,messages:values.messages?JSON.parse(values.messages):[]}});
      }else if(values.mode==="deobfuscate"){
        result=await api(scoped(`${base}/deobfuscate`),{method:"POST",body:{text:values.prompt}});
      }else result=await api(`${base}/${values.mode}`,{method:"POST",body:{application_id:values.application_id,prompt:values.prompt,response:values.response||null}});
      showResult(result);
    }
    if(event.target.id==="portal-form"){
      requestController=new AbortController();const out=document.getElementById("portal-response");out.textContent="请求中…";
      const isGet=endpointExamples[values.endpoint]===null,body=isGet?undefined:JSON.stringify(JSON.parse(values.body));
      const response=await fetch(values.endpoint,{method:isGet?"GET":"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+values.token},body,signal:requestController.signal});
      out.textContent=`HTTP ${response.status}\nRequest ID: ${response.headers.get("X-Request-Id")||"—"}\n`;
      const reader=response.body.getReader(),decoder=new TextDecoder();
      while(true){const part=await reader.read();if(part.done)break;out.textContent+=decoder.decode(part.value,{stream:true});}
    }
  }catch(error){notify(error.name==="AbortError"?"请求已取消":error.message,true);}
  finally{if(submit)submit.disabled=false;}
});
