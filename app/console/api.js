export const state = {user:null,csrf:"",projects:[],project:localStorage.getItem("qg_project"),page:"overview",environment:"production",hours:24,cache:{}};
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
