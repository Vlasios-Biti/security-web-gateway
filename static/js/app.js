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

function drawSystemPerformance(){
 const canvas=document.getElementById("system-performance-chart");
 const source=document.getElementById("system-performance-data");
 if(!canvas||!source)return;
 let rows=[];try{rows=JSON.parse(source.textContent||"[]")}catch(e){return}
 const empty=document.getElementById("system-performance-empty");
 if(!rows.length){if(empty)empty.style.display="flex";return}
 if(empty)empty.style.display="none";
 const {ctx,w,h}=fitCanvas(canvas),pad={l:36,r:16,t:14,b:26};
 ctx.clearRect(0,0,w,h);
 ctx.strokeStyle="#e9edf3";ctx.lineWidth=1;
 for(let i=0;i<4;i++){const y=pad.t+(h-pad.t-pad.b)*i/3;ctx.beginPath();ctx.moveTo(pad.l,y);ctx.lineTo(w-pad.r,y);ctx.stroke()}
 const xs=rows.slice(-120),pw=w-pad.l-pad.r,ph=h-pad.t-pad.b;
 const latencyMax=Math.max(50,...xs.map(r=>Number(r.proxy_p95_ms||0)));
 const series=[
  {key:"cpu_percent",stroke:"#2563eb",max:100},
  {key:"memory_percent",stroke:"#159a67",max:100},
  {key:"proxy_p95_ms",stroke:"#7c3aed",max:latencyMax}
 ];
 series.forEach(ser=>{
   ctx.strokeStyle=ser.stroke;ctx.lineWidth=2;ctx.beginPath();let started=false;
   xs.forEach((r,i)=>{const raw=r[ser.key];if(raw===null||raw===undefined)return;const x=pad.l+(xs.length<=1?0:i*pw/(xs.length-1));const y=pad.t+ph-(Math.max(0,Math.min(ser.max,Number(raw)))/ser.max)*ph;if(!started){ctx.moveTo(x,y);started=true}else ctx.lineTo(x,y)});
   if(started)ctx.stroke();
 });
 ctx.fillStyle="#7b8798";ctx.font="10px system-ui";ctx.fillText("6h ago",pad.l,h-7);ctx.fillText("now",w-pad.r-20,h-7);
}

function setupCardFilters(){
 document.querySelectorAll("[data-filter-cards]").forEach(input=>{
   const root=document.getElementById(input.dataset.filterCards);if(!root)return;
   input.addEventListener("input",()=>{const q=input.value.trim().toLowerCase();root.querySelectorAll("[data-card-search]").forEach(card=>{card.style.display=!q||card.dataset.cardSearch.toLowerCase().includes(q)?"":"none"})});
 });
}

function setupLiveTrafficRefresh(){
 const marker=document.querySelector("[data-live-traffic-refresh]");if(!marker)return;
 const seconds=Math.max(5,Math.min(60,Number(marker.dataset.liveTrafficRefresh)||10));
 const tick=()=>{
   if(document.hidden){window.setTimeout(tick,seconds*1000);return}
   const tag=(document.activeElement&&document.activeElement.tagName||"").toLowerCase();
   if(["input","select","textarea"].includes(tag)){window.setTimeout(tick,5000);return}
   window.location.reload();
 };
 window.setTimeout(tick,seconds*1000);
}

function setupApplicationActivityPoll(){
 const el=document.querySelector("[data-application-activity]");
 if(!el)return;
 const url=el.dataset.activityUrl;
 if(!url)return;
 let stopped=false,failures=0;
 const poll=async()=>{
   if(stopped)return;
   try{
     const r=await fetch(url,{credentials:"same-origin",headers:{"Accept":"application/json"}});
     if(!r.ok)throw new Error("HTTP "+r.status);
     const data=await r.json();
     failures=0;
     if(data.status==="running"){
       window.setTimeout(poll,1800);
       return;
     }
     stopped=true;
     window.location.reload();
   }catch(e){
     failures+=1;
     if(failures<20)window.setTimeout(poll,Math.min(5000,1800+failures*250));
   }
 };
 window.setTimeout(poll,1200);
}

function setupNotificationStatus(){
 const root=document.querySelector('[data-notification-status]');if(!root)return;
 const tick=async()=>{
  if(!document.hidden)try{
   const response=await fetch(root.dataset.notificationStatus,{credentials:'same-origin',headers:{Accept:'application/json'}});
   if(!response.ok)throw new Error('Status unavailable');
   const data=await response.json(),tbody=root.querySelector('[data-delivery-body]'),last=root.querySelector('[data-last-monitor]');
   if(last)last.textContent=data.last_run;
   if(tbody){
    tbody.replaceChildren();
    for(const entry of data.deliveries){const row=document.createElement('tr');
     for(const value of [entry.created_at,entry.channel,entry.kind,entry.result,entry.event_count,entry.error_code||'—']){const cell=document.createElement('td');cell.textContent=String(value);row.appendChild(cell)}
     tbody.appendChild(row);
    }
    if(!data.deliveries.length){const row=document.createElement('tr'),cell=document.createElement('td');cell.colSpan=6;cell.className='empty';cell.textContent='No notifications sent yet.';row.appendChild(cell);tbody.appendChild(row)}
   }
  }catch(error){/* Keep the last result while the management plane reconnects. */}
  setTimeout(tick,5000);
 };setTimeout(tick,3000);
}

document.addEventListener("DOMContentLoaded",()=>{
 document.querySelectorAll("[data-confirm]").forEach(el=>el.addEventListener("submit",e=>{if(!confirm(el.dataset.confirm))e.preventDefault()}));
 document.querySelectorAll("[data-filter-table]").forEach(i=>{const t=document.getElementById(i.dataset.filterTable);if(!t)return;i.addEventListener("input",()=>{const q=i.value.toLowerCase().trim();t.querySelectorAll("tbody tr").forEach(r=>r.style.display=r.textContent.toLowerCase().includes(q)?"":"none")})});
 document.querySelectorAll("[data-reload]").forEach(b=>b.addEventListener("click",()=>location.reload()));
 document.querySelectorAll("[data-page-size-select]").forEach(s=>s.addEventListener("change",()=>{const u=new URL(location.href);u.searchParams.set("page_size",s.value);u.searchParams.set("page","1");location.href=u.toString()}));
 document.querySelectorAll("[data-select-candidates-all]").forEach(master=>{
   const boxes=[...document.querySelectorAll('input[name="candidate_ids"]:not(:disabled)')];
   const sync=()=>{const n=boxes.filter(x=>x.checked).length;master.checked=boxes.length>0&&n===boxes.length;master.indeterminate=n>0&&n<boxes.length};
   master.addEventListener("change",()=>{boxes.forEach(x=>x.checked=master.checked);sync()});
   boxes.forEach(x=>x.addEventListener("change",sync));sync();
 });
 document.querySelectorAll("[data-dismiss-message]").forEach(button=>button.addEventListener("click",()=>button.closest("[data-success-message]").remove()));
 document.querySelectorAll("[data-channel-toggle]").forEach(input=>input.addEventListener("change",()=>{const details=input.closest(".settings-card").querySelector(".channel-settings");if(details&&input.checked)details.open=true}));
 setupNavigation();setupCommandPalette();setupCardFilters();setupLiveTrafficRefresh();setupApplicationActivityPoll();setupNotificationStatus();refreshCharts();drawSystemPerformance();if(document.getElementById("traffic-chart"))setInterval(refreshCharts,15000);
});
window.addEventListener("resize",()=>{clearTimeout(window.__pmResize);window.__pmResize=setTimeout(()=>{refreshCharts();drawSystemPerformance()},160)});
