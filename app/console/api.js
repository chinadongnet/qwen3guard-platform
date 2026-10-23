export const state = {user:null,csrf:"",projects:[],project:localStorage.getItem("qg_project"),page:"overview",environment:"production",hours:24,cache:{}};
export function uuid(){
  if(typeof globalThis.crypto?.randomUUID==="function")return globalThis.crypto.randomUUID();
  const bytes=new Uint8Array(16);
  if(typeof globalThis.crypto?.getRandomValues==="function")globalThis.crypto.getRandomValues(bytes);
  else for(let i=0;i<16;i++)bytes[i]=Math.floor(Math.random()*256);
  bytes[6]=(bytes[6]&0x0f)|0x40;
  bytes[8]=(bytes[8]&0x3f)|0x80;
  const hex=[...bytes].map(b=>b.toString(16).padStart(2,"0")).join("");
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}
if(typeof globalThis.crypto==="object"&&globalThis.crypto&&typeof globalThis.crypto.randomUUID!=="function"){
  try{globalThis.crypto.randomUUID=uuid;}catch{}
}
export async function copyText(text){
  if(navigator.clipboard?.writeText){
    try{await navigator.clipboard.writeText(text);return;}catch{}
  }
  const ta=document.createElement("textarea");
  ta.value=String(text??"");
  ta.setAttribute("readonly","");
  ta.style.position="fixed";
  ta.style.opacity="0";
  document.body.append(ta);
  ta.select();
  document.execCommand("copy");
  ta.remove();
}
export async function api(path,options={}){
  const headers={"Content-Type":"application/json",...options.headers};
  if(state.csrf)headers["X-CSRF-Token"]=state.csrf;
  const response=await fetch(path,{...options,headers,credentials:"same-origin",body:options.body===undefined?undefined:JSON.stringify(options.body)});
  const data=await response.json();
  if(!response.ok){
    const error=new Error(data.error?.message||data.detail?.message||`请求失败 (${response.status})`);
    error.status=response.status;error.data=data;throw error;
  }
  return data;
}
export const scoped=(path)=>`${path}${path.includes("?")?"&":"?"}project_id=${encodeURIComponent(state.project)}`;
export const esc=value=>String(value??"").replace(/[&<>"']/g,ch=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
export const date=value=>value?new Date(value*1000).toLocaleString("zh-CN",{hour12:false}):"—";
export const number=value=>value===null||value===undefined?"—":Number(value).toLocaleString("zh-CN",{maximumFractionDigits:1});
export function can(...roles){return state.user?.is_admin||roles.includes(state.projects.find(p=>p.id===state.project)?.role);}
export function notify(message,error=false){
  const element=document.createElement("div");element.className=`toast${error?" error":""}`;element.textContent=message;
  document.getElementById("notifications").append(element);setTimeout(()=>element.remove(),6000);
}
