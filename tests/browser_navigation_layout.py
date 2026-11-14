#!/usr/bin/env python3
"""Real-browser regression: navigation labels must fit and SNMP must be discoverable."""
import argparse,os,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def render_pages(folder):
    os.environ.update(SWG_DB_PATH=str(folder/'test.db'),SWG_DATA_ROOT=str(folder),SWG_MODE='candidate',SWG_FQDN='localhost',SWG_PROXY_IP='127.0.0.1')
    subprocess.check_call([sys.executable,str(ROOT/'tools/migrate.py'),'--db',os.environ['SWG_DB_PATH'],'--root',str(ROOT)])
    sys.path.insert(0,str(ROOT))
    from app.db import connect
    from app.main import app
    from app.auth import create_session
    from app.config import SESSION_COOKIE
    from starlette.testclient import TestClient
    from starlette.requests import Request
    c=connect();uid=c.execute("INSERT INTO users(username,password_hash,role,enabled) VALUES('layout-admin','unused-test-hash','admin',1)").lastrowid;c.commit();c.close()
    token=create_session(uid,Request({'type':'http','headers':[],'client':('127.0.0.1',1)}))
    with TestClient(app,base_url='https://localhost') as client:
        client.cookies.set(SESSION_COOKIE,token)
        for name,url in [('profiles','/policies/groups'),('notifications','/system/notifications'),('connection','/connection')]:
            response=client.get(url);assert response.status_code==200,(url,response.status_code)
            html=response.text.replace('/static/',(ROOT/'static').as_uri()+'/')
            (folder/(name+'.html')).write_text(html,encoding='utf-8')


def check(folder,executable=None):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        options={'headless':True}
        if executable:options['executable_path']=executable
        browser=p.chromium.launch(**options)
        page=browser.new_page(reduced_motion='reduce')
        for width,zoom in [(1440,1),(1100,1),(980,1),(920,1),(390,1),(1440,1.25),(1100,1.5)]:
            page.set_viewport_size({'width':width,'height':1000})
            page.goto((folder/'profiles.html').resolve().as_uri())
            page.evaluate('(zoom)=>document.body.style.zoom=zoom',zoom)
            if page.locator('.mobile-nav-button').is_visible():page.locator('.mobile-nav-button').click()
            page.wait_for_timeout(50)
            assert page.locator('.sidebar a.nav-primary[href="/system/notifications"]').count()==1,'SNMP must have one direct primary entry'
            assert page.locator('.profile-head>.badge').evaluate_all('nodes=>nodes.every(e=>e.clientHeight<=40)'), 'Profile status badges must not stretch with the description'
            labels=page.locator('.sidebar a.nav-primary>span:not(.nav-count)').evaluate_all("""elements=>elements.map(e=>({text:e.textContent.trim(),height:e.clientHeight,line:parseFloat(getComputedStyle(e).lineHeight),width:e.clientWidth,scroll:e.scrollWidth}))""")
            for label in labels:
                assert label['height']<=label['line']+2,('Wrapped navigation label',width,zoom,label)
                assert label['scroll']<=label['width']+1,('Clipped navigation label',width,zoom,label)
        page.set_viewport_size({'width':390,'height':900})
        page.goto((folder/'notifications.html').resolve().as_uri())
        page.get_by_role('link',name='SNMP',exact=True).click()
        position=page.locator('#snmp h3').bounding_box()
        assert position and 0<=position['y']<900,'SNMP jump link must bring configuration into view'
        for name in ('connection','notifications'):
            for width in (1440,920,390):
                page.set_viewport_size({'width':width,'height':1000})
                page.goto((folder/(name+'.html')).resolve().as_uri())
                page.locator('main details').evaluate_all('nodes=>nodes.forEach(e=>e.open=true)')
                assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),('Form overflow',name,width)
        page.goto((folder/'connection.html').resolve().as_uri())
        assert page.locator('#pac-address').input_value().endswith('/proxy.pac')
        page.get_by_role('button',name='Copy address',exact=True).click()
        page.wait_for_function("document.querySelector('[data-copy-target=\"pac-address\"]').textContent !== 'Copy address'")
        assert page.locator('[data-copy-target="pac-address"]').inner_text() in ('Copied','Selected — press Ctrl+C')
        browser.close()
    print('Navigation fit at five widths and 125/150% zoom; direct SNMP entry and section jump: PASS')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--html-dir',type=Path);parser.add_argument('--executable');args=parser.parse_args()
    if args.html_dir:check(args.html_dir,args.executable)
    else:
        with tempfile.TemporaryDirectory(prefix='swg-layout-') as td:
            folder=Path(td);render_pages(folder);check(folder,args.executable)
