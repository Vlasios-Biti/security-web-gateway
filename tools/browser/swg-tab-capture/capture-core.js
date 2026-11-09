"use strict";
// Pure request scoping, shared by the extension and regression tests.
function recordRequest(state, details, now = Date.now()) {
  if (!state || !state.active) return state;
  if (now >= state.expires_at) return {...state, active:false, stopped_reason:"Time limit reached"};
  if (details.tabId !== state.tab_id || details.tabId < 0) return state;
  let url;
  try { url = new URL(details.url); } catch { return state; }
  if (!["http:","https:","ws:","wss:"].includes(url.protocol)) return state;
  if (url.port && !((url.protocol === "http:" || url.protocol === "ws:") && url.port === "80") &&
      !((url.protocol === "https:" || url.protocol === "wss:") && url.port === "443")) return state;
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  // Local/private IP literals and browser-internal URLs are outside public-app capture.
  if (!host.includes(".") || /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":")) return state;
  const protocol = ["https:","wss:"].includes(url.protocol) ? "HTTPS" : "HTTP";
  const key = protocol + ":" + host;
  const destinations = {...state.destinations};
  if (!destinations[key] && Object.keys(destinations).length >= 500) {
    return {...state,active:false,stopped_reason:"500 destination limit reached"};
  }
  const prior = destinations[key] || {host,protocol,request_count:0,resource_types:[]};
  const type = details.type === "xmlhttprequest" ? "xhr" : String(details.type || "other");
  destinations[key] = {host,protocol,request_count:Math.min(100000,prior.request_count+1),
    resource_types:[...new Set([...prior.resource_types,type])].slice(0,20)};
  return {...state,destinations};
}
if (typeof module !== "undefined") module.exports = {recordRequest};
