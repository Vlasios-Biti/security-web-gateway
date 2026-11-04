"use strict";

function css(name){return getComputedStyle(document.documentElement).getPropertyValue(name).trim()}
function fitCanvas(canvas){const r=canvas.getBoundingClientRect(),dpr=window.devicePixelRatio||1;canvas.width=Math.max(1,Math.floor(r.width*dpr));canvas.height=Math.max(1,Math.floor(r.height*dpr));const c=canvas.getContext("2d");c.setTransform(dpr,0,0,dpr,0,0);return {ctx:c,w:r.width,h:r.height}}
function drawTraffic(canvas,points){if(!canvas||!points.length)return;const {ctx,w,h}=fitCanvas(canvas),pad={l:42,r:16,t:16,b:28};ctx.clearRect(0,0,w,h);const max=Math.max(1,...points.flatMap(p=>[p.allowed,p.denied]));ctx.font="10px system-ui";ctx.strokeStyle="#263141";ctx.fillStyle="#718096";ctx.lineWidth=1;for(let i=0;i<=4;i++){const y=pad.t+(h-pad.t-pad.b)*i/4;ctx.beginPath();ctx.moveTo(pad.l,y);ctx.lineTo(w-pad.r,y);ctx.stroke();const val=Math.round(max*(1-i/4));ctx.fillText(String(val),5,y+3)}const x=i=>pad.l+(w-pad.l-pad.r)*(points.length===1?0:i/(points.length-1));const y=v=>h-pad.b-(h-pad.t-pad.b)*(v/max);function line(key,color){ctx.beginPath();points.forEach((p,i)=>{const xx=x(i),yy=y(p[key]);i?ctx.lineTo(xx,yy):ctx.moveTo(xx,yy)});ctx.strokeStyle=color;ctx.lineWidth=2;ctx.stroke();points.forEach((p,i)=>{if(i%Math.max(1,Math.floor(points.length/12))===0||i===points.length-1){ctx.fillStyle=color;ctx.beginPath();ctx.arc(x(i),y(p[key]),2.2,0,Math.PI*2);ctx.fill()}})}line("allowed",css("--good"));line("denied",css("--bad"));ctx.fillStyle="#718096";const step=Math.max(1,Math.ceil(points.length/8));points.forEach((p,i)=>{if(i%step===0||i===points.length-1)ctx.fillText(p.label,x(i)-12,h-8)})}
function drawDonut(canvas,allowed,denied){if(!canvas)return;const {ctx,w,h}=fitCanvas(canvas),total=Math.max(allowed+denied,1),cx=w/2,cy=h/2,r=Math.min(w,h)*.36,lw=Math.min(w,h)*.12;ctx.clearRect(0,0,w,h);ctx.lineWidth=lw;ctx.lineCap="butt";ctx.strokeStyle="#263141";ctx.beginPath();ctx.arc(cx,cy,r,0,Math.PI*2);ctx.stroke();let a=-Math.PI/2;const aa=Math.PI*2*(allowed/total);ctx.strokeStyle=css("--good");ctx.beginPath();ctx.arc(cx,cy,r,a,a+aa);ctx.stroke();a+=aa;ctx.strokeStyle=css("--bad");ctx.beginPath();ctx.arc(cx,cy,r,a,a+Math.PI*2*(denied/total));ctx.stroke()}

function drawNetworkBars(canvas,rows){if(!canvas||!rows||!rows.length)return;const {ctx,w,h}=fitCanvas(canvas),pad={l:135,r:22,t:18,b:20};ctx.clearRect(0,0,w,h);const mx=Math.max(1,...rows.map(r=>Number(r.allowed||0)+Number(r.denied||0))),rh=(h-pad.t-pad.b)/rows.length;rows.forEach((r,i)=>{const y=pad.t+i*rh+rh*.2,bh=rh*.52,a=Number(r.allowed||0),d=Number(r.denied||0),aw=(w-pad.l-pad.r)*(a/mx),dw=(w-pad.l-pad.r)*(d/mx);ctx.font="10px system-ui";ctx.fillStyle="#9aa8ba";const label=(r.vlan_id?"VLAN "+r.vlan_id+" · ":"")+r.name;ctx.fillText(label.slice(0,21),7,y+bh*.72);ctx.fillStyle=css("--good");ctx.fillRect(pad.l,y,aw,bh);ctx.fillStyle=css("--bad");ctx.fillRect(pad.l+aw,y,dw,bh);ctx.fillStyle="#8c9aae";ctx.fillText(String(a+d),Math.min(w-pad.r-28,pad.l+aw+dw+5),y+bh*.72)})}

async function refreshCharts(){const traffic=document.getElementById("traffic-chart"),donut=document.getElementById("decision-chart"),network=document.getElementById("network-chart");if(!traffic&&!donut&&!network)return;try{const r=await fetch("/api/dashboard/traffic?minutes=60",{credentials:"same-origin",headers:{"Accept":"application/json"}});if(!r.ok)throw new Error("HTTP "+r.status);const data=await r.json();drawTraffic(traffic,data.timeline||[]);drawDonut(donut,Number(data.allowed||0),Number(data.denied||0));drawNetworkBars(network,data.networks||[]);const total=document.getElementById("decision-total");if(total)total.textContent=Number(data.allowed||0)+Number(data.denied||0);const l=document.getElementById("traffic-chart-loading");if(l)l.style.display="none";const nl=document.getElementById("network-chart-loading");if(nl)nl.style.display="none"}catch(e){const l=document.getElementById("traffic-chart-loading");if(l){l.textContent="Telemetry unavailable";l.style.color=css("--bad")}}}

document.addEventListener("DOMContentLoaded",()=>{
 document.querySelectorAll("[data-confirm]").forEach(el=>el.addEventListener("submit",e=>{if(!confirm(el.dataset.confirm))e.preventDefault()}));
 document.querySelectorAll("[data-filter-table]").forEach(i=>{const t=document.getElementById(i.dataset.filterTable);if(!t)return;i.addEventListener("input",()=>{const q=i.value.toLowerCase().trim();t.querySelectorAll("tbody tr").forEach(r=>r.style.display=r.textContent.toLowerCase().includes(q)?"":"none")})});
 document.querySelectorAll("[data-reload]").forEach(b=>b.addEventListener("click",()=>location.reload()));
 refreshCharts();if(document.getElementById("traffic-chart"))setInterval(refreshCharts,15000);
});
window.addEventListener("resize",()=>{clearTimeout(window.__pmResize);window.__pmResize=setTimeout(refreshCharts,150)});

document.addEventListener("DOMContentLoaded",()=>{
 document.querySelectorAll("[data-page-size-select]").forEach(s=>s.addEventListener("change",()=>{const u=new URL(location.href);u.searchParams.set("page_size",s.value);u.searchParams.set("page","1");location.href=u.toString()}));
});


document.addEventListener("DOMContentLoaded",()=>{
  const toggles=[...document.querySelectorAll("[data-nav-toggle]")];
  const closeNav=()=>document.body.classList.remove("nav-open");
  toggles.forEach(el=>el.addEventListener("click",()=>document.body.classList.toggle("nav-open")));
  document.querySelectorAll(".sidebar a").forEach(a=>a.addEventListener("click",closeNav));
  document.addEventListener("keydown",e=>{if(e.key==="Escape")closeNav()});
});
