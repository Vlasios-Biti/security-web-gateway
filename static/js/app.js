"use strict";

function css(name){return getComputedStyle(document.documentElement).getPropertyValue(name).trim()}
function fitCanvas(canvas){const r=canvas.getBoundingClientRect(),dpr=window.devicePixelRatio||1;canvas.width=Math.max(1,Math.floor(r.width*dpr));canvas.height=Math.max(1,Math.floor(r.height*dpr));const c=canvas.getContext("2d");c.setTransform(dpr,0,0,dpr,0,0);return {ctx:c,w:r.width,h:r.height}}

function drawTraffic(canvas,points){
 if(!canvas||!points.length)return false;
 const total=points.reduce((n,p)=>n+Number(p.allowed||0)+Number(p.denied||0),0);
 if(total<=0)return false;
 const {ctx,w,h}=fitCanvas(canvas),pad={l:44,r:16,t:18,b:28};
 ctx.clearRect(0,0,w,h);
 const max=Math.max(1,...points.flatMap(p=>[Number(p.allowed||0),Number(p.denied||0)]));
 ctx.font="11px system-ui";ctx.strokeStyle="#263653";ctx.fillStyle="#71829a";ctx.lineWidth=1;
 for(let i=0;i<=4;i++){const y=pad.t+(h-pad.t-pad.b)*i/4;ctx.beginPath();ctx.moveTo(pad.l,y);ctx.lineTo(w-pad.r,y);ctx.stroke();const val=Math.round(max*(1-i/4));ctx.fillText(String(val),8,y+4)}
 const x=i=>pad.l+(w-pad.l-pad.r)*(points.length===1?0:i/(points.length-1));
 const y=v=>h-pad.b-(h-pad.t-pad.b)*(Number(v||0)/max);
 function series(key,color,fill){
   ctx.beginPath();points.forEach((p,i)=>{const xx=x(i),yy=y(p[key]);i?ctx.lineTo(xx,yy):ctx.moveTo(xx,yy)});
   ctx.strokeStyle=color;ctx.lineWidth=2.4;ctx.stroke();
   const last=points.length-1;ctx.lineTo(x(last),h-pad.b);ctx.lineTo(x(0),h-pad.b);ctx.closePath();
   const g=ctx.createLinearGradient(0,pad.t,0,h-pad.b);g.addColorStop(0,fill);g.addColorStop(1,"rgba(0,0,0,0)");ctx.fillStyle=g;ctx.fill();
 }
 series("allowed",css("--green"),"rgba(69,214,155,.16)");
 series("denied",css("--red"),"rgba(255,112,124,.12)");
 ctx.fillStyle="#71829a";const step=Math.max(1,Math.ceil(points.length/7));points.forEach((p,i)=>{if(i%step===0||i===points.length-1)ctx.fillText(p.label,x(i)-13,h-8)});
 return true;
}

function drawDonut(canvas,allowed,denied){if(!canvas)return;const {ctx,w,h}=fitCanvas(canvas),total=Math.max(allowed+denied,1),cx=w/2,cy=h/2,r=Math.min(w,h)*.36,lw=Math.min(w,h)*.12;ctx.clearRect(0,0,w,h);ctx.lineWidth=lw;ctx.strokeStyle="#263653";ctx.beginPath();ctx.arc(cx,cy,r,0,Math.PI*2);ctx.stroke();let a=-Math.PI/2;const aa=Math.PI*2*(allowed/total);ctx.strokeStyle=css("--green");ctx.beginPath();ctx.arc(cx,cy,r,a,a+aa);ctx.stroke();a+=aa;ctx.strokeStyle=css("--red");ctx.beginPath();ctx.arc(cx,cy,r,a,a+Math.PI*2*(denied/total));ctx.stroke()}

function drawNetworkBars(canvas,rows){
 if(!canvas||!rows||!rows.length)return false;
 const total=rows.reduce((n,r)=>n+Number(r.allowed||0)+Number(r.denied||0),0);
 if(total<=0)return false;
 const {ctx,w,h}=fitCanvas(canvas),pad={l:150,r:24,t:18,b:18};ctx.clearRect(0,0,w,h);
 const mx=Math.max(1,...rows.map(r=>Number(r.allowed||0)+Number(r.denied||0))),rh=(h-pad.t-pad.b)/rows.length;
 rows.slice(0,8).forEach((r,i)=>{const yy=pad.t+i*rh+rh*.22,bh=Math.max(7,rh*.46),a=Number(r.allowed||0),d=Number(r.denied||0),aw=(w-pad.l-pad.r)*(a/mx),dw=(w-pad.l-pad.r)*(d/mx);ctx.font="11px system-ui";ctx.fillStyle="#9aabc0";const label=(r.vlan_id?"VLAN "+r.vlan_id+" · ":"")+r.name;ctx.fillText(label.slice(0,23),7,yy+bh*.8);ctx.fillStyle="#45d69b";ctx.fillRect(pad.l,yy,aw,bh);ctx.fillStyle="#ff707c";ctx.fillRect(pad.l+aw,yy,dw,bh);ctx.fillStyle="#71829a";ctx.fillText(String(a+d),Math.min(w-pad.r-30,pad.l+aw+dw+6),yy+bh*.8)});
 return true;
}

async function refreshCharts(){
 const traffic=document.getElementById("traffic-chart"),network=document.getElementById("network-chart"),donut=document.getElementById("decision-chart");
 if(!traffic&&!network&&!donut)return;
 try{
   const r=await fetch("/api/dashboard/traffic?minutes=60",{credentials:"same-origin",headers:{"Accept":"application/json"}});
   if(!r.ok)throw new Error("HTTP "+r.status);
   const data=await r.json();
   const trafficHas=drawTraffic(traffic,data.timeline||[]);
   const networkHas=drawNetworkBars(network,data.networks||[]);
   if(donut)drawDonut(donut,Number(data.allowed||0),Number(data.denied||0));
   const tl=document.getElementById("traffic-chart-loading");if(tl)tl.style.display=trafficHas?"none":"flex";
   const nl=document.getElementById("network-chart-loading");if(nl)nl.style.display=networkHas?"none":"flex";
   const total=document.getElementById("decision-total");if(total)total.textContent=Number(data.allowed||0)+Number(data.denied||0);
 }catch(e){
   const l=document.getElementById("traffic-chart-loading");if(l){l.style.display="flex";const s=l.querySelector("strong");if(s)s.textContent="Telemetry unavailable"}
 }
}

function setupNavigation(){
 const closeNav=()=>document.body.classList.remove("nav-open");
 document.querySelectorAll("[data-nav-toggle]").forEach(el=>el.addEventListener("click",()=>document.body.classList.toggle("nav-open")));
 document.querySelectorAll(".sidebar a").forEach(a=>a.addEventListener("click",closeNav));
 document.querySelectorAll(".nav-group").forEach(group=>group.addEventListener("toggle",()=>{if(group.open)document.querySelectorAll(".nav-group").forEach(other=>{if(other!==group)other.open=false})}));
}

function setupCommandPalette(){
 const palette=document.querySelector("[data-command-palette]"),input=document.querySelector("[data-command-input]"),results=document.querySelector("[data-command-results]");
 if(!palette||!input||!results)return;
 const links=[...document.querySelectorAll(".sidebar-nav a")].map(a=>({label:a.textContent.trim(),href:a.getAttribute("href"),group:a.closest(".nav-group")?.querySelector("summary span span")?.textContent?.trim()||"Overview"}));
 const render=()=>{
   const q=input.value.trim().toLowerCase();const matches=links.filter(x=>!q||x.label.toLowerCase().includes(q)||x.group.toLowerCase().includes(q)).slice(0,12);
   results.innerHTML=matches.length?matches.map(x=>'<a class="command-result" href="'+x.href+'"><div><strong>'+x.label+'</strong><small>'+x.group+'</small></div><span>→</span></a>').join(""):'<div class="command-empty">No matching pages</div>';
 };
 const open=()=>{palette.hidden=false;render();requestAnimationFrame(()=>input.focus())};
 const close=()=>{palette.hidden=true;input.value=""};
 document.querySelectorAll("[data-command-open]").forEach(x=>x.addEventListener("click",open));
 document.querySelectorAll("[data-command-close]").forEach(x=>x.addEventListener("click",close));
 input.addEventListener("input",render);
 document.addEventListener("keydown",e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==="k"){e.preventDefault();palette.hidden?open():close()}else if(e.key==="Escape"){close();document.body.classList.remove("nav-open")}});
}

document.addEventListener("DOMContentLoaded",()=>{
 document.querySelectorAll("[data-confirm]").forEach(el=>el.addEventListener("submit",e=>{if(!confirm(el.dataset.confirm))e.preventDefault()}));
 document.querySelectorAll("[data-filter-table]").forEach(i=>{const t=document.getElementById(i.dataset.filterTable);if(!t)return;i.addEventListener("input",()=>{const q=i.value.toLowerCase().trim();t.querySelectorAll("tbody tr").forEach(r=>r.style.display=r.textContent.toLowerCase().includes(q)?"":"none")})});
 document.querySelectorAll("[data-reload]").forEach(b=>b.addEventListener("click",()=>location.reload()));
 document.querySelectorAll("[data-page-size-select]").forEach(s=>s.addEventListener("change",()=>{const u=new URL(location.href);u.searchParams.set("page_size",s.value);u.searchParams.set("page","1");location.href=u.toString()}));
 setupNavigation();setupCommandPalette();refreshCharts();if(document.getElementById("traffic-chart"))setInterval(refreshCharts,15000);
});
window.addEventListener("resize",()=>{clearTimeout(window.__pmResize);window.__pmResize=setTimeout(refreshCharts,160)});
