SWG SELECTED TAB CAPTURE — REVIEW BUILD

Chrome/Edge administrator or developer installation:
1. Extract the ZIP to a folder.
2. Open chrome://extensions or edge://extensions, enable Developer mode and
   choose Load unpacked. Select the extracted folder containing manifest.json.
   Follow your organisation's extension policy; this is not a signed store package.
3. Open the application's main domain, click the extension and Start capture.
4. Sign in and exercise the relevant buttons in that same tab. Reload a blocked
   workflow after applying reviewed dependencies if further requests are hidden.
5. Stop and Export for review. In SWG open that application, upload the JSON,
   review destination candidates and approve the intended dependencies.

The extension requests webRequest, tabs, storage and host access because both
the source and unknown destination hosts must be observable. The runtime only
retains hostname/protocol/count/resource-type data for the explicitly selected
tab. It sends nothing to any server. No path/query/header/cookie/body is stored.
Clear removes the session capture; closing the browser clears session storage.

The selected tab's subframes are included. New windows/tabs and requests whose
tabId is -1 (including some background/service-worker traffic) are excluded.
It does not attribute native PC processes or Windows services. It cannot prove
that every third party in the tab is business-essential: ads, analytics and
embedded widgets can be present, so a review is still required. Navigating the
recorded tab to another site includes that activity until capture is stopped.
Public IP-literal and non-standard-port requests are excluded from this build.
Stops after ten minutes, selected-tab close, or 500 destination records.

Chrome API reference:
https://developer.chrome.com/docs/extensions/reference/api/webRequest
