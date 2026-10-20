import {esc,date,number} from "./api.js?v=3.2.1";
export const button=(label,action,id="",kind="")=>`<button type="button" class="${esc(kind)}" data-action="${esc(action)}" data-id="${esc(id)}">${esc(label)}</button>`;
export const badge=(value)=>{
  const labels={allow:"放行",block:"阻断",mask:"脱敏",review:"待复核",completed:"已完成",error:"执行失败",timeout:"超时",safe:"安全",unsafe:"风险",indeterminate:"未确定",production:"生产",sandbox:"沙盒",queued:"排队中",running:"执行中",cancelled:"已取消",interrupted:"已中断",failed:"失败",open:"待处理",investigating:"处理中",resolved:"已解决",false_positive:"误报",delivered:"已送达",pending:"待投递",high:"高",medium:"中",low:"低",legacy_unknown:"历史未核验"};
  const cls=["allow","safe","completed","resolved","delivered"].includes(value)?"good":["block","unsafe","error","failed"].includes(value)?"bad":["timeout","review","open","interrupted"].includes(value)?"warn":"info";
  return `<span class="badge ${cls}">${esc(labels[value]||value)}</span>`;
};
export const empty=(title,description,action="")=>`<div class="empty"><div class="empty-symbol">◇</div><h3>${esc(title)}</h3><p>${esc(description)}</p>${action}</div>`;
export const panel=(title,body,action="")=>`<section class="panel"><div class="panel-head"><h2>${esc(title)}</h2>${action}</div>${body}</section>`;
export const table=(columns,rows)=>`<div class="table-scroll"><table><thead><tr>${columns.map(c=>`<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
export const metric=(label,value,note)=>`<div class="metric"><div class="metric-label">${esc(label)}</div><div class="metric-value">${esc(value)}</div><div class="metric-note">${esc(note)}</div></div>`;
export const heading=(title,description,actions="")=>`<div class="page-head"><div><div class="eyebrow">QWENGUARD / WORKSPACE</div><h1>${esc(title)}</h1><p>${esc(description)}</p></div><div class="actions">${actions}</div></div>`;
export const json=value=>`<pre>${esc(JSON.stringify(value,null,2))}</pre>`;
export function modal(title,body){
  const dialog=document.getElementById("dialog");
  dialog.innerHTML=`<div class="dialog-head"><h2>${esc(title)}</h2><button class="dialog-close" data-action="close-dialog" aria-label="关闭">×</button></div><div class="dialog-body">${body}</div>`;
  if(!dialog.open)dialog.showModal();
  return dialog;
}
export function field(name,label,options={}){
  let control;
  const attr=`id="field-${esc(name)}" name="${esc(name)}" ${options.required===false?"":"required"}`;
  if(options.options)control=`<select ${attr}>${options.options.map(v=>`<option value="${esc(v.value)}" ${v.value===options.value?"selected":""}>${esc(v.label)}</option>`).join("")}</select>`;
  else if(options.type==="textarea")control=`<textarea ${attr} rows="${options.rows||4}">${esc(options.value||"")}</textarea>`;
  else control=`<input ${attr} type="${esc(options.type||"text")}" value="${esc(options.value||"")}" ${options.min!==undefined?`min="${options.min}"`:""} ${options.max!==undefined?`max="${options.max}"`:""} ${options.step?`step="${options.step}"`:""} ${options.minLength!==undefined?`minlength="${options.minLength}"`:""} ${options.maxLength!==undefined?`maxlength="${options.maxLength}"`:""} autocomplete="${esc(options.autocomplete||"off")}">`;
  return `<div class="field${options.wide?" wide":""}"><label for="field-${esc(name)}">${esc(label)}</label>${control}${options.help?`<div class="help">${esc(options.help)}</div>`:""}</div>`;
}
export function formModal(title,fields,onSubmit,submit="保存",intro=""){
  const dialog=modal(title,`${intro?`<div class="notice">${esc(intro)}</div>`:""}<form id="modal-form"><div class="form-grid">${fields}</div><div class="error-text hidden" id="modal-error"></div><div class="dialog-foot">${button("取消","close-dialog")}<button class="primary" type="submit">${esc(submit)}</button></div></form>`);
  document.getElementById("modal-form").addEventListener("submit",async event=>{
    event.preventDefault();const submitButton=event.target.querySelector('[type="submit"]');submitButton.disabled=true;
    try{
      const values=Object.fromEntries(new FormData(event.target).entries());
      await onSubmit(values);
    }catch(error){
      const box=dialog.querySelector("#modal-error");if(box){box.textContent=error.message;box.classList.remove("hidden");}
    }finally{submitButton.disabled=false;}
  });
}
export function detectionTable(items){
  if(!items.length)return empty("还没有检测记录","完成应用接入后，每次审核的决策、策略版本和耗时都会记录在这里。");
  return table(["请求 / 时间","应用","内容摘要","决策","执行状态","耗时",""],items.map(item=>`<tr>
    <td><code>${esc(item.request_id.slice(0,14))}…</code><div class="subline">${date(item.created_at)}</div></td>
    <td><code>${esc(item.application_id.slice(0,8))}</code><div class="subline">${esc(item.source)}</div></td>
    <td><span class="clip">${esc(item.prompt_preview)}</span></td><td>${badge(item.decision)}</td><td>${badge(item.execution_status)}</td>
    <td>${number(item.latency_ms)} ms</td><td>${button("详情","detection",item.id,"small")}</td></tr>`));
}
