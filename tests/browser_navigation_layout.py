#!/usr/bin/env python3
"""Real-browser regression: navigation labels must fit and SNMP must be discoverable."""
import argparse,os,re,subprocess,sys,tempfile,time
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
    from app.services.access_model import create_application,create_policy_group
    c=connect();uid=c.execute("INSERT INTO users(username,password_hash,role,enabled) VALUES('layout-admin','unused-test-hash','admin',1)").lastrowid;c.execute("INSERT INTO telemetry_events(epoch,event_time,client_ip,decision,event_hash,destination_host,destination_port) VALUES(?,CURRENT_TIMESTAMP,'10.20.0.10','ALLOW','layout-fixture','www.google.com',443)",(time.time(),));c.commit();c.close()
    aid=create_application('Example workflow','Test','','portal.example.test','manual','',False,'layout-admin')
    c=connect();nid=c.execute("INSERT INTO networks(name,cidr,vlan_id,proxy_enabled,enabled,pending,created_by) VALUES('Office','10.20.0.0/24',131,1,1,0,'layout-admin')").lastrowid;c.commit();c.close()
    create_policy_group('Office access','',[aid],[],[nid],'layout-admin')
    c=connect();c.execute("INSERT INTO application_dependency_candidates(application_id,destination,confidence,confidence_score,request_count,client_count) VALUES(?,'api.portal.example.test','high',90,12,2)",(aid,));c.commit();c.close()
    token=create_session(uid,Request({'type':'http','headers':[],'client':('127.0.0.1',1)}))
    with TestClient(app,base_url='https://localhost') as client:
        client.cookies.set(SESSION_COOKIE,token)
        for name,url in [('access-add','/applications/allow'),('application-add','/applications/discover'),('application-edit',f'/applications/{aid}/edit'),('dependency-review','/intelligence/dependency-candidates'),('profiles','/policies/groups'),('notifications','/system/notifications'),('connection','/connection'),('simulator','/intelligence/simulator'),('traffic-clients','/traffic/clients'),('pc-detail','/traffic/clients/10.20.0.10')]:
            response=client.get(url);assert response.status_code==200,(url,response.status_code)
            html=response.text.replace('/static/',(ROOT/'static').as_uri()+'/')
            (folder/(name+'.html')).write_text(html,encoding='utf-8')
        response=client.post('/intelligence/simulator',data={'client_ip':'10.20.0.10','destination':'http://printer'})
        assert response.status_code==200
        (folder/'simulator-result.html').write_text(response.text.replace('/static/',(ROOT/'static').as_uri()+'/'),encoding='utf-8')


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
        for name in ('access-add','application-add','application-edit','dependency-review','connection','notifications','simulator','simulator-result','traffic-clients','pc-detail'):
            for width in (1440,920,390):
                page.set_viewport_size({'width':width,'height':1000})
                page.goto((folder/(name+'.html')).resolve().as_uri())
                page.locator('main details').evaluate_all('nodes=>nodes.forEach(e=>e.open=true)')
                assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),('Form overflow',name,width)
                if name in ('access-add','application-add','application-edit'):
                    assert page.locator('[data-access-method]').count()==0,'Applications must have one profile-based access path'
                    assert page.locator('input[name=network_ids]').count()==0,'No duplicate direct VLAN assignment'
                    assert page.locator('.application-profile-picker').count()>=1
                if name=='dependency-review':
                    controls=page.locator('.candidate-filters input,.candidate-filters select').evaluate_all('nodes=>nodes.map(e=>({width:e.getBoundingClientRect().width,left:e.getBoundingClientRect().left,right:e.getBoundingClientRect().right}))')
                    assert len(controls)==4
                    assert all(e['width']>=100 and e['left']>=0 and e['right']<=width for e in controls),('Candidate filter fit',width,controls)
                if name=='connection':
                    form_width=page.locator('#blocked-page form').bounding_box()['width']
                    for field in ('message','contact','logo'):
                        control=page.locator('#blocked-page [name="'+field+'"]').bounding_box()
                        assert control['width']>=form_width*.9,('Branding field must fill its own row',field,width,control)
                if name=='traffic-clients':
                    assert page.locator('#clients-table tbody code').count()>0
                    assert page.locator('#clients-table tbody code').evaluate_all('nodes=>nodes.every(e=>e.getBoundingClientRect().height<30)'), 'PC IPs must stay on one line, including on phones'
        page.goto((folder/'traffic-clients.html').resolve().as_uri())
        page.locator('select[name=range]').select_option('7d')
        page.wait_for_url(re.compile(r'[?&]range=7d(?:&|$)'))
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
