"use strict";
importScripts("capture-core.js");
let queue = Promise.resolve();
function serial(work) {
  const result = queue.then(work);
  queue = result.catch(() => {});
  return result;
}
async function readState() { return (await chrome.storage.session.get("capture")).capture || null; }
chrome.webRequest.onBeforeRequest.addListener(details => {
  serial(async () => {
    const before = await readState();
    const after = recordRequest(before, details);
    if (after !== before) await chrome.storage.session.set({capture:after});
  });
}, {urls:["<all_urls>"]});
chrome.tabs.onRemoved.addListener(tabId => {
  serial(async () => {
    const state = await readState();
    if (state && state.tab_id===tabId) await chrome.storage.session.set({capture:{...state,active:false,stopped_reason:"Selected tab closed"}});
  });
});
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id !== chrome.runtime.id || sender.url !== chrome.runtime.getURL('popup.html')) return false;
  serial(async () => {
    let state = await readState();
    if (message.action==="start") {
      const [tab] = await chrome.tabs.query({active:true,currentWindow:true});
      const url = new URL(tab.url);
      if (!["http:","https:"].includes(url.protocol)) throw new Error("Select the application's website tab first.");
      state = {active:true,tab_id:tab.id,seed_host:url.hostname.toLowerCase(),started_at:Date.now(),expires_at:Date.now()+600000,destinations:{}};
    } else if (message.action==="stop" && state) {
      state = {...state,active:false,stopped_reason:"Stopped by user"};
    } else if (message.action==="clear") {
      state = null;
    } else if (message.action!=="status") {
      if (!['stop'].includes(message.action)) throw new Error("Unsupported action");
    }
    if (state && Date.now()>=state.expires_at) state={...state,active:false,stopped_reason:"Time limit reached"};
    await chrome.storage.session.set({capture:state});
    reply({ok:true,state});
  }).catch(error => reply({ok:false,error:error.message}));
  return true;
});
