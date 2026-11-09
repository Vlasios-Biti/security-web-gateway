"use strict";
let current = null;
async function action(name) {
  const result = await chrome.runtime.sendMessage({action:name});
  if (!result.ok) throw new Error(result.error);
  current = result.state;
  const count = current ? Object.keys(current.destinations).length : 0;
  document.getElementById("status").textContent = current ? `${current.active ? "Recording" : "Stopped"} · ${current.seed_host} · ${count} destinations` : "No capture. Open the application tab first.";
  document.getElementById("start").disabled = !!current?.active;
  document.getElementById("stop").disabled = !current?.active;
  document.getElementById("export").disabled = !count;
}
for (const name of ["start","stop","clear"]) document.getElementById(name).addEventListener("click", () => action(name).catch(showError));
function showError(error) { document.getElementById("status").textContent = error.message; }
document.getElementById("export").addEventListener("click", async () => {
  try {
    await action("stop");
    const payload = {format:"swg-tab-capture-v1",scope:"selected-tab",seed_host:current.seed_host,destinations:Object.values(current.destinations)};
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload,null,2)],{type:"application/json"}));
    const link = document.createElement("a");link.href=url;link.download="swg-tab-capture.json";link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  } catch (error) { showError(error); }
});
action("status").catch(showError);
