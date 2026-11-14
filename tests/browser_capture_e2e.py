"""Optional Chromium extension test. Requires local port 80 and Playwright Chromium.

No extension is installed in the user's normal browser profile. All test hosts
resolve to a loopback-only synthetic HTTP server in a disposable browser profile.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type','text/html' if self.headers['Host'].startswith('app.') else 'application/json')
        self.send_header('Access-Control-Allow-Origin','*')
        self.end_headers()
        if self.headers['Host'].startswith('app.'):
            self.wfile.write(b'''<button id="action">Do work</button><p id="result"></p><script>
document.querySelector('#action').onclick=async()=>{await fetch('http://api.swg.test/action?token=must-not-be-exported');document.querySelector('#result').textContent='done'};
</script>''')
        else:self.wfile.write(b'{"ok":true}')

    def log_message(self,*args):pass


def main():
    extension=ROOT/'tools/browser/swg-tab-capture'
    server=ThreadingHTTPServer(('127.0.0.1',80),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='swg-extension-test-',ignore_cleanup_errors=True) as td,sync_playwright() as pw:
            context=pw.chromium.launch_persistent_context(td,channel='chromium',headless=True,args=[
                f'--disable-extensions-except={extension}',f'--load-extension={extension}',
                '--host-resolver-rules=MAP *.swg.test 127.0.0.1','--no-proxy-server'])
            try:
                worker=context.service_workers[0] if context.service_workers else context.wait_for_event('serviceworker')
                extension_id=worker.url.split('/')[2]
                page=context.new_page();page.goto('http://app.swg.test/')
                popup=context.new_page();popup.goto(f'chrome-extension://{extension_id}/popup.html')
                page.bring_to_front()
                popup.wait_for_function("document.getElementById('status').textContent !== 'Loading…'")
                popup.evaluate("document.getElementById('start').click()")
                page.wait_for_timeout(500)
                state=worker.evaluate('(async()=> (await chrome.storage.session.get("capture")).capture)()')
                assert state and state['active'] and state['seed_host']=='app.swg.test', (state,popup.locator('#status').inner_text(),worker.evaluate('chrome.tabs.query({active:true,currentWindow:true})'))
                # Native request from the chosen tab, triggered by a button.
                page.click('#action');page.wait_for_selector('#result:text("done")')
                noise=context.new_page();noise.goto('http://noise.swg.test/')
                page.wait_for_timeout(500)
                popup.evaluate("document.getElementById('stop').click()")
                page.wait_for_timeout(300)
                state=worker.evaluate('(async()=> (await chrome.storage.session.get("capture")).capture)()')
                assert 'HTTP:api.swg.test' in state['destinations'],state
                assert not any('noise.swg.test' in key for key in state['destinations']),state
                assert 'must-not-be-exported' not in json.dumps(state),state
                assert not state['active'],state
                print('Real Chromium extension: selected-tab button request captured; other tab excluded; query secret absent; Stop honoured: PASS')
            finally:context.close()
    finally:server.shutdown();server.server_close()


if __name__=='__main__':main()
