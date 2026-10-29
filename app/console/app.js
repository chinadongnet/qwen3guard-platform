import {api,state,scoped,esc,date,notify,can,uuid,copyText} from "./api.js?v=3.2.5";
import {pages,shell,loginView,renderPage} from "./views.js?v=3.2.5";
import {button,badge,empty,panel,table,json,modal,field,formModal} from "./components.js?v=3.2.5";
import {workbenchActions,initWorkbench} from "./workbench.js?v=3.2.5";

const root=document.getElementById("root"),dialog=document.getElementById("dialog");
const close=()=>{dialog.close();dialog.innerHTML="";};
let renderGeneration=0;

async function loadProjects(){
  state.projects=(await api("/api/admin/projects")).items;
  if(!state.projects.some(p=>p.id===state.project))state.project=state.projects[0]?.id||null;
  if(state.project)localStorage.setItem("qg_project",state.project);
}
async function refresh(){
  const generation=++renderGeneration;
  root.innerHTML=shell();document.getElementById("page-content").innerHTML='<div class="loading"><span class="spinner"></span>正在读取工作空间…</div>';
  try{
    const html=await renderPage();
    if(generation!==renderGeneration)return;
    document.getElementById("page-content").innerHTML=html;
    document.title=`${pages.find(p=>p[0]===state.page)?.[1]||"运营总览"} · QwenGuard`;
  }catch(error){
    if(error.status===401){showLogin();return;}
    document.getElementById("page-content").innerHTML=`<div class="error-page"><h2>暂时无法加载</h2><p class="muted">${esc(error.message)}</p><br>${button("重新加载","refresh")}</div>`;
  }
}
function showLogin(){
  state.user=null;state.csrf="";state.cache={};root.innerHTML=loginView();
  document.getElementById("login-form").addEventListener("submit",async event=>{
    event.preventDefault();const submit=event.target.querySelector("button");submit.disabled=true;
    try{
      const data=await api("/api/admin/auth/login",{method:"POST",body:Object.fromEntries(new FormData(event.target))});
      state.user=data.user;state.csrf=data.csrf_token;await loadProjects();await refresh();
    }catch(error){
      document.getElementById("login-error").textContent=error.message;document.getElementById("login-error").classList.remove("hidden");
    }finally{submit.disabled=false;}
  });
}
function navigate(page){
  state.page=pages.some(p=>p[0]===page)?page:"overview";
  history.pushState({},"",`/${state.page==="overview"?"dashboard":state.page}`);refresh();
}
async function saved(message="已保存"){
  close();notify(message);await refresh();
}
function showSecret(title,value,note){
  modal(title,`<div class="notice warning">${esc(note)}</div><pre class="secret" id="one-time-secret">${esc(value)}</pre><div class="dialog-foot">${button("复制","copy-secret","","primary")}${button("已保存，关闭","close-dialog")}</div>`);
}
function policyFields(cfg={}){
  return field("risk_threshold","风险阈值",{type:"number",min:.05,max:.99,step:.01,value:cfg.risk_threshold??.5})+
    field("pii_action","个人信息处理",{value:cfg.pii_action||"block",options:[{value:"block",label:"阻断"},{value:"mask",label:"脱敏"},{value:"audit",label:"仅审计"}]})+
    field("timeout_seconds","单次检测超时（秒）",{type:"number",value:cfg.timeout_seconds||30,min:1,max:120})+
    field("failure_action","检测失败处置",{value:cfg.failure_action||"block",options:[{value:"block",label:"阻断"},{value:"review",label:"人工复核"}]})+
    field("stream_window_chars","流式审核窗口（字符）",{type:"number",value:cfg.stream_window_chars||48,min:16,max:256})+
    field("controversial_as_unsafe","争议内容",{value:cfg.controversial_as_unsafe===false?"false":"true",options:[{value:"true",label:"按风险处理"},{value:"false",label:"由其他规则决定"}]})+
    field("custom_block_keywords","附加拦截词",{type:"textarea",wide:true,required:false,value:(cfg.custom_block_keywords||[]).join("\n"),help:"每行一个，最多 100 个；保存后需发布才会影响业务。"});
}
function policyConfig(values,base={}){
  return {...base,risk_threshold:Number(values.risk_threshold),pii_action:values.pii_action,
    timeout_seconds:Number(values.timeout_seconds),failure_action:values.failure_action,
    stream_window_chars:Number(values.stream_window_chars),controversial_as_unsafe:values.controversial_as_unsafe==="true",
    custom_block_keywords:values.custom_block_keywords.split("\n").map(v=>v.trim()).filter(Boolean)};
}

const actions={
  ...workbenchActions,
  navigate,refresh,"close-dialog":close,
  async logout(){await api("/api/admin/auth/logout",{method:"POST"});showLogin();},
  "change-password"(){
    formModal("修改登录密码",
      field("current_password","当前密码",{type:"password",wide:true,autocomplete:"current-password",maxLength:256})+
      field("new_password","新密码",{type:"password",wide:true,autocomplete:"new-password",minLength:8,maxLength:256,help:"8～256 个字符；密码中的空格会被保留。"})+
      field("confirm_password","确认新密码",{type:"password",wide:true,autocomplete:"new-password",minLength:8,maxLength:256}),async values=>{
        if(values.new_password!==values.confirm_password)throw new Error("两次输入的新密码不一致");
        await api("/api/admin/auth/password",{method:"POST",body:values});
        close();document.getElementById("dialog").innerHTML="";showLogin();
        notify("密码已修改，请使用新密码重新登录");
      },"修改并重新登录","修改当前账户的登录密码。保存后，该账户所有设备上的现有会话都会失效。");
  },
  "new-project"(){
    formModal("创建项目",field("name","项目名称",{wide:true}),async values=>{
      const project=await api("/api/admin/projects",{method:"POST",body:values});
      state.project=project.id;await loadProjects();await saved("项目已创建，请先创建并发布安全策略");
      navigate("policies");
    },"创建项目");
  },
  async "new-application"(){
    const policies=(await api(scoped("/api/admin/policies"))).items.filter(p=>p.published_version>0);
    if(!policies.length){notify("请先创建并发布安全策略");navigate("policies");return;}
    formModal("创建业务应用",
      field("name","应用名称",{wide:true})+field("environment","运行环境",{options:[{value:"sandbox",label:"沙盒"},{value:"production",label:"生产"}]})+
      field("policy_id","绑定策略",{options:policies.map(p=>({value:p.id,label:`${p.name} · v${p.published_version}`}))}),async values=>{
        await api(scoped("/api/admin/applications"),{method:"POST",body:values});await saved("应用已创建，下一步创建凭证");
      },"创建应用");
  },
  async keys(id){
    const data=await api(`/api/admin/applications/${id}/keys`);
    state.cache.keys=data.items;
    modal("应用凭证",`<div class="notice">列表不显示完整密钥。轮换将创建新密钥，旧密钥最多保留 24 小时过渡期。</div><div class="actions">${button("＋ 创建凭证","new-key",id,"primary")}</div><br>`+
      (data.items.length?table(["名称 / 前缀","额度 / 有效期","状态","操作"],data.items.map(k=>`<tr><td>${esc(k.name)}<div class="subline mono">${esc(k.prefix)}…</div></td><td>${k.rpm} 条/分钟<div class="subline">${date(k.expires_at)}</div></td><td>${badge(k.revoked?"已撤销":k.expires_at*1000<Date.now()?"已过期":k.enabled?"可用":"已暂停")}</td><td>${!k.revoked?button("额度 / 启停","key-settings",k.id,"small")+button("轮换","rotate-key",k.id,"small")+button("撤销","revoke-key",k.id,"small danger"):""}</td></tr>`)):empty("暂无凭证","创建一个仅属于此应用的 API Key。")));
  },
  "key-settings"(id){const k=state.cache.keys.find(i=>i.id===id);formModal("凭证额度与启停",field("rpm","每分钟检测条目",{type:"number",min:1,max:10000,value:k.rpm})+field("enabled","状态",{value:String(k.enabled),options:[{value:"true",label:"启用"},{value:"false",label:"暂停"}]}),async v=>{await api(`/api/admin/keys/${id}/settings`,{method:"PUT",body:{enabled:v.enabled==="true",rpm:Number(v.rpm)}});await saved("凭证设置已更新");});},
  async "toggle-application"(id){const app=state.cache.applications.find(i=>i.id===id);await api(`/api/admin/applications/${id}/enabled`,{method:"PUT",body:{enabled:!app.enabled}});await saved("应用状态已更新");},
  async "edit-application"(id){const app=state.cache.applications.find(i=>i.id===id),policies=(await api(scoped("/api/admin/policies"))).items.filter(p=>p.published_version>0);formModal("修改应用设置",field("name","名称",{value:app.name,wide:true})+field("environment","环境",{value:app.environment,options:[{value:"production",label:"生产"},{value:"sandbox",label:"沙盒"}]})+field("policy_id","策略",{value:app.policy_id,options:policies.map(p=>({value:p.id,label:p.name}))}),async v=>{await api(`/api/admin/applications/${id}/settings`,{method:"PUT",body:v});await saved("应用设置已更新，历史记录保持原环境与策略");});},
  "new-key"(id){
    formModal("创建 API Key",field("name","凭证名称",{wide:true,value:"默认业务凭证"})+field("rpm","每分钟检测条目",{type:"number",value:600,min:1,max:10000})+
      field("expires_days","有效期（天）",{type:"number",value:90,min:1,max:365})+
      field("scopes","权限范围",{wide:true,options:[
        {value:"detect,chat,audit:read,policy:manage",label:"全功能凭证（内容审核 + 策略配置 API + 受控对话 + 审计）"},
        {value:"detect,chat,audit:read",label:"内容审核 + 受控对话 + 本应用审计"},
        {value:"detect,audit:read",label:"内容审核 + 本应用审计"},
        {value:"detect",label:"仅内容审核"}
      ]}),async values=>{
        const result=await api(`/api/admin/applications/${id}/keys`,{method:"POST",body:{...values,rpm:Number(values.rpm),expires_days:Number(values.expires_days),scopes:values.scopes.split(",")}});
        await refresh();
        showSecret("请保存你的 API Key",result.token,"完整密钥只在本次显示。关闭后无法再次查看，请存入业务服务的密钥管理器。");
      },"创建凭证");
  },
  async "quick-new-key"(){
    const apps=state.project?(await api(scoped("/api/admin/applications"))).items:[];
    const appField=apps.length?field("application_id","绑定业务应用",{wide:true,options:apps.map(a=>({value:a.id,label:`${a.name} (${a.environment})`}))}):"";
    formModal("一键创建 API Key",appField+field("name","凭证名称",{wide:true,value:"平台与检测 API Key"})+field("rpm","每分钟检测条目",{type:"number",value:600,min:1,max:10000})+
      field("expires_days","有效期（天）",{type:"number",value:90,min:1,max:365})+
      field("scopes","权限范围",{wide:true,options:[
        {value:"detect,chat,audit:read,policy:manage",label:"全功能凭证（内容审核 + 策略配置 API + 受控对话 + 审计）"},
        {value:"detect,chat,audit:read",label:"内容审核 + 受控对话 + 本应用审计"},
        {value:"detect,audit:read",label:"内容审核 + 本应用审计"},
        {value:"detect",label:"仅内容审核"}
      ]}),async values=>{
        const result=await api("/api/admin/keys",{method:"POST",body:{
          name:values.name,project_id:state.project||null,application_id:values.application_id||null,
          rpm:Number(values.rpm),expires_days:Number(values.expires_days),scopes:values.scopes.split(",")
        }});
        await loadProjects();await refresh();
        showSecret("请保存你的 API Key",result.token,"完整密钥只在本次显示。支持直接调用 /v1/policies* 配置策略及 /v1/guard/* 进行内容检测。");
      },"立即生成 API Key","若当前项目尚未创建策略或应用，系统将自动初始化默认已发布策略与默认应用。");
  },
  async "rotate-key"(id){
    const result=await api(`/api/admin/keys/${id}/rotate`,{method:"POST"});
    showSecret("密钥已轮换",result.token,"旧密钥最多保留 24 小时，请完成业务切换后撤销旧密钥。");
  },
  "revoke-key"(id){
    formModal("撤销凭证","",async()=>{await api(`/api/admin/keys/${id}/revoke`,{method:"POST"});await saved("凭证已撤销");},"确认撤销","撤销后，此密钥的新请求将立即被拒绝。");
  },
  async "copy-secret"(){await copyText(document.getElementById("one-time-secret").textContent);notify("已复制，请妥善保存");},
  "test-application"(id){
    formModal("验证应用接入",field("prompt","待检测文本",{type:"textarea",wide:true,value:"请介绍如何整理会议纪要。"})+
      field("response","模型回复（可选）",{type:"textarea",wide:true,required:false}),async values=>{
        const result=await api(`/api/admin/applications/${id}/test`,{method:"POST",body:{prompt:values.prompt,response:values.response||null}});
        modal("检测结果",`<div class="actions">${badge(result.decision)}${badge(result.execution_status)}<code>${esc(result.request_id)}</code></div>${json(result)}<p class="help">这次调用已写入沙盒来源审计，不计入生产指标。</p>`);
      },"开始检测","验证会调用已部署模型并写入真实检测记录。");
  },
  "new-policy"(){
    formModal("创建安全策略",field("name","策略名称",{wide:true})+policyFields(),async values=>{
      await api(scoped("/api/admin/policies"),{method:"POST",body:{name:values.name,config:policyConfig(values)}});await saved("策略草稿已创建，请确认后发布");
    },"保存草稿");
  },
  "new-version"(id){
    const policy=state.cache.policies.find(p=>p.id===id),cfg=policy.versions[0].config;
    formModal("新建策略版本",policyFields(cfg),async values=>{
      await api(`/api/admin/policies/${id}/versions`,{method:"POST",body:policyConfig(values,cfg)});await saved("新版本已保存，尚未影响生产");
    },"保存草稿");
  },
  "policy-detail"(id){
    const policy=state.cache.policies.find(p=>p.id===id);
    const published=policy.versions.find(v=>v.version===policy.published_version);
    modal(policy.name,policy.versions.map(v=>{
      const changes=published?Object.keys(v.config).filter(k=>JSON.stringify(v.config[k])!==JSON.stringify(published.config[k])):[];
      return `<h3>v${v.version} ${v.version===policy.published_version?"· 当前生效":"· 历史 / 草稿"}</h3><p class="help">${date(v.created_at)} · 与当前版本差异：${esc(changes.join("、")||"无")}</p>${json(v.config)}`;
    }).join(""));
  },
  "publish-policy"(id){
    const policy=state.cache.policies.find(p=>p.id===id);
    formModal("发布 / 回滚策略",field("version","目标版本",{wide:true,options:policy.versions.map(v=>({value:String(v.version),label:`v${v.version}${v.version===policy.published_version?"（当前）":""}`}))}),async values=>{
      await api(`/api/admin/policies/${id}/publish`,{method:"POST",body:{version:Number(values.version),expected_current:policy.published_version}});await saved("策略版本已发布");
    },"确认发布","此策略绑定的应用将在下次请求使用目标版本。在途请求保持原版本，历史审计不变。");
  },
  async detection(id){modal("检测详情",`<div class="actions">${can("admin","operator","auditor")?button("查看原文（留痕）","original-detection",id):""}${can("admin","operator")?button("人工复核","review-detection",id)+button("沉淀到题库","promote-detection",id):""}</div>`+json(await api(`/api/admin/detections/${id}`)));},
  "reset-filter"(){state.cache.detectionFilter={};refresh();},
  "next-detections"(){state.cache.detectionFilter={...state.cache.detectionFilter,before:state.cache.nextCursor};refresh();},
  "new-endpoint"(){
    formModal("注册模型 API",field("name","端点名称",{wide:true})+field("url","Chat Completions 完整地址",{wide:true,help:"例如 https://model.example.com/v1/chat/completions"})+
      field("model","模型标识",{wide:true})+field("credential","上游 API Key（可选）",{type:"password",wide:true,required:false}),async values=>{
        await api(scoped("/api/admin/endpoints"),{method:"POST",body:values});await saved("模型端点已注册");
      },"注册端点");
  },
  async "test-endpoint"(id){notify("正在执行连接测试…");const result=await api(`/api/admin/endpoints/${id}/test`,{method:"POST"});modal("连接测试结果",json(result));},
  async "new-evaluation"(){
    const [apps,targets]=await Promise.all([api(scoped("/api/admin/applications")),api(scoped("/api/admin/endpoints"))]);
    if(!apps.items.length){notify("请先创建应用");navigate("applications");return;}
    formModal("创建评测任务",field("name","任务名称",{wide:true})+
      field("application_id","使用应用策略",{options:apps.items.map(a=>({value:a.id,label:a.name}))})+
      field("endpoint_id","评测对象",{required:false,options:[{value:"",label:"直接文本审核回归"},...targets.items.map(e=>({value:e.id,label:e.name}))]})+
      field("policy_version","候选策略版本（可选）",{type:"number",required:false,min:1,wide:true,help:"留空使用当前已发布版本；填写草稿版本可完成发布前回归门禁。"})+
      field("items","JSON 样本数组",{type:"textarea",rows:8,wide:true,value:JSON.stringify([{prompt:"请介绍办公室节约用电的方法。",expected_unsafe:false}],null,2),help:"最多 500 条。prompt 必填，response、expected_unsafe 可选；提交时自动生成数据集哈希。"}),async values=>{
        let items;try{items=JSON.parse(values.items);}catch{throw new Error("样本必须是有效的 JSON 数组");}
        await api(scoped("/api/admin/evaluations"),{method:"POST",body:{name:values.name,application_id:values.application_id,endpoint_id:values.endpoint_id||null,policy_version:values.policy_version?Number(values.policy_version):null,items,idempotency_key:uuid()}});
        await saved("评测任务已进入队列");
      },"提交评测","任务使用提交时的策略版本；不会修改生产策略。对外部端点的调用可能产生供应商费用。");
  },
  async "evaluation-detail"(id){
    const data=await api(`/api/admin/evaluations/${id}`);
    modal("评测报告",`<div class="actions">${badge(data.state)}<strong>${esc(data.name)}</strong></div><p class="help">数据集 ${esc(data.dataset_hash)} · 自动评审，非独立认证</p>${json(data.metrics)}${json(data.results)}`);
  },
  async "cancel-evaluation"(id){await api(`/api/admin/evaluations/${id}/cancel`,{method:"POST"});await saved("已请求取消");},
  async "resume-evaluation"(id){await api(`/api/admin/evaluations/${id}/resume`,{method:"POST"});await saved("任务将从未完成项继续");},
  "incident-detail"(id){const item=state.cache.incidents.find(i=>i.id===id);modal("事件处理记录",item.reviews.length?item.reviews.map(r=>`<div class="timeline">${badge(r.state)}<p>${esc(r.note)}</p><span class="help">${date(r.created_at)} · ${esc(r.actor_id.slice(0,12))}</span></div>`).join(""):empty("尚未复核","原始机器判定保持不变，处理记录会追加保存。"));},
  "review-incident"(id){
    formModal("复核风险事件",field("state","处理状态",{options:[{value:"investigating",label:"处理中"},{value:"resolved",label:"已解决"},{value:"false_positive",label:"确认误报"},{value:"open",label:"重新打开"}]})+
      field("assignee","负责人",{required:false})+field("note","处理说明",{wide:true,type:"textarea"}),async values=>{
        await api(`/api/admin/incidents/${id}/reviews`,{method:"POST",body:values});await saved("复核记录已追加");
      },"保存复核");
  },
  "new-hook"(){
    formModal("新增通知渠道",field("url","Webhook 地址",{wide:true}),async values=>{
      const result=await api(scoped("/api/admin/webhooks"),{method:"POST",body:values});
      showSecret("保存 Webhook 签名密钥",result.signing_secret,"接收端需验证 X-QG-Signature，并按 delivery_id 去重。密钥仅本次显示。");
    },"创建渠道");
  },
  async "disable-hook"(id){await api(`/api/admin/webhooks/${id}/disable`,{method:"POST"});await saved("通知渠道已停用");},
  "new-user"(){
    formModal("创建成员账户",field("username","用户名",{wide:true})+field("password","初始密码",{type:"password",wide:true,help:"至少 8 个字符。创建后需加入项目才拥有项目权限。"}),async values=>{
      await api("/api/admin/users",{method:"POST",body:values});await saved("账户已创建，请将成员加入项目");
    },"创建账户");
  },
  async members(){
    const members=await api(`/api/admin/projects/${state.project}/members`);
    modal("项目成员",`<div class="actions">${button("添加 / 调整成员","set-member","","primary")}</div><br>`+
      (members.items.length?table(["用户名","角色"],members.items.map(m=>`<tr><td>${esc(m.username)}</td><td>${esc(m.role)}</td></tr>`)):empty("暂无项目成员","平台管理员具有项目管理权限；可为其他成员分配项目角色。")));
  },
  "set-member"(){
    formModal("设置项目成员",field("user_id","用户 ID",{wide:true,help:"从管理员账户列表获取，按项目分配角色。"})+
      field("role","项目角色",{wide:true,options:[{value:"developer",label:"开发接入"},{value:"operator",label:"安全运营"},{value:"auditor",label:"只读审计"},{value:"admin",label:"项目管理员"}]}),async values=>{
        await api(`/api/admin/projects/${state.project}/members`,{method:"PUT",body:values});await saved("项目权限已更新");
      },"保存权限");
    if(state.user.is_admin)api("/api/admin/users").then(data=>{
      const input=dialog.querySelector('[name="user_id"]');if(!input)return;
      const select=document.createElement("select");select.name="user_id";select.required=true;
      for(const user of data.items){const option=document.createElement("option");option.value=user.id;option.textContent=user.username;select.append(option);}
      input.replaceWith(select);
    }).catch(error=>notify(error.message,true));
  }
};

document.addEventListener("click",async event=>{
  const target=event.target.closest("[data-action]");if(!target)return;
  const action=actions[target.dataset.action];if(!action)return;
  target.disabled=true;try{await action(target.dataset.id);}catch(error){notify(error.message,true);if(error.status===401)showLogin();}finally{target.disabled=false;}
});
document.addEventListener("change",event=>{
  if(event.target.id==="project-select"){state.project=event.target.value;localStorage.setItem("qg_project",state.project);state.cache={};refresh();}
  if(event.target.id==="environment-select"){state.environment=event.target.value;refresh();}
  if(event.target.id==="hours-select"){state.hours=Number(event.target.value);refresh();}
});
document.addEventListener("submit",event=>{
  if(event.target.id==="detection-filter"){event.preventDefault();state.cache.detectionFilter=Object.fromEntries(new FormData(event.target));refresh();}
});
window.addEventListener("popstate",()=>{state.page=pageFromPath();refresh();});
function pageFromPath(){
  const path=location.pathname.slice(1).split("/")[0];
  const aliases={gateway:"applications",audit:"detections"};
  if(path==="audit"){
    const key=new URLSearchParams(location.search).get("key");
    if(key)state.cache.detectionFilter={key_id:key};
  }
  return aliases[path]||(pages.some(p=>p[0]===path)?path:"overview");
}
async function start(){
  state.page=pageFromPath();
  try{const data=await api("/api/admin/auth/me");state.user=data.user;state.csrf=data.csrf_token;await loadProjects();await refresh();}
  catch(error){if(error.status===401)showLogin();else root.innerHTML=`<div class="boot"><h2>服务暂不可用</h2><p>${esc(error.message)}</p>${button("重试","refresh")}</div>`;}
}
initWorkbench({refresh,navigate,saved});
start();
