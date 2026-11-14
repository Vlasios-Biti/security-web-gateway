#!/usr/bin/env python3
"""Endpoint-by-role matrix, read-only GETs, authentication and failure handling."""
import csv,io,json,os,re,threading,unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
import smoke_v3125 as prior


class DetailedFunctionalAudit(prior.ClientActivityWorkflows):
    def test_all_declared_routes_by_role_and_csrf_without_policy_mutation(self):
        from tools.function_inventory import inventory
        from app.services.access_model import create_policy_group
        from app.services.rules import create_rule
        from app.services.deployment import state_snapshot
        aid=self._app();gid=create_policy_group('Audit profile','',[aid],[],[1],'admin')
        rid=create_rule('ip','203.0.113.19','HTTPS',[1],'admin','Audit fixture')['id']
        c=self.connect()
        drid=c.execute("SELECT id FROM rules WHERE rule_type='domain' LIMIT 1").fetchone()[0]
        category=c.execute("INSERT INTO categories(name,slug,system_managed) VALUES('Audit system','audit-system',1)").lastrowid
        srid=c.execute("INSERT INTO rules(rule_type,destination,protocol,category_id,management_type,status,fingerprint,created_by) VALUES('domain','protected.example.com','HTTPS',?,'system','active','audit-system-fixture','admin')",(category,)).lastrowid
        run=c.execute("INSERT INTO discovery_runs(application_id,method,status,started_by) VALUES(?,'har_import','ready','admin')",(aid,)).lastrowid
        c.execute("INSERT INTO users(username,password_hash,role,enabled) VALUES('auditor','unused-test-hash','auditor',1)");c.commit();c.close()
        self.event('10.20.0.10','portal.example.com','matrix')
        mapping={'application_id':aid,'group_id':gid,'network_id':1,'run_id':run,'rule_id':rid,'user_id':1,'event_id':1,'client_ip':'10.20.0.10','deployment_id':999,'candidate_id':999,'batch_id':999,'session_id':999,'service_key':'windows-update','channel':'slack','action':'backup'}
        record=[];before=state_snapshot()
        for role in ('admin','operator','viewer','auditor'):
            client,_=self.client_for(role)
            with client,patch('app.services.deployment.helper_request') as helper,patch('app.services.notifications.send_channel') as outbound:
                for route in inventory()['routes']:
                    if route['method']=='POST' and route['path'] in ('/login','/intelligence/simulator'):continue
                    ids={**mapping,'rule_id':srid if '/system/' in route['path'] else (drid if '/domains/' in route['path'] else rid)}
                    path=re.sub(r'{(\w+)}',lambda match:str(ids[match[1]]),route['path'])
                    if route['method']=='GET':
                        response=client.get(path,follow_redirects=False)
                        admin_only=path.startswith(('/connection','/security','/system/notifications','/system/storage','/system/backups')) or route['path'] in ('/policies/networks/add','/policies/networks/{network_id}/copy','/policies/networks/{network_id}/edit','/rules/system/add','/rules/system/{rule_id}/edit')
                        manager_only=route['path'] in ('/applications/allow','/applications/add','/applications/discover','/applications/discovery/{run_id}','/applications/capture/extension.zip','/applications/{application_id}/edit','/policies/groups/add','/policies/groups/{group_id}/copy','/policies/groups/{group_id}/edit','/rules/domains/add','/rules/domains/{rule_id}/edit','/rules/ips/add','/rules/ips/{rule_id}/edit','/bulk/import')
                        expected=403 if (admin_only and role!='admin') or (manager_only and role not in ('admin','operator')) else (303 if route['path'] in ('/login','/rules/domains','/rules/ips') else 200)
                        self.assertEqual(response.status_code,expected,(role,path,response.status_code,response.text[:150]))
                    else:
                        numbers={'auto_monitor':0,'auto_approve':0,'window_minutes':10,'smtp_port':587,'snmp_port':162,'snmp_agent_port':1161,'confirmation_samples':2,'recovery_samples':2,'repeat_minutes':60,'slack_repeat_minutes':-1,'disk_percent':85,'memory_percent':90,'certificate_days':30,'telemetry_lag_seconds':120,'cpu_percent':90,'backup_age_hours':72,'retention_days':30,'days':30,'raw_days':14,'max_gb':8,'target_gb':6,'min_free_gb':10,'raw_max_gb':4,'enabled':1}
                        booleans={'fail_open','internal_direct','email_enabled','slack_enabled','snmp_enabled','snmp_agent_enabled','clear_smtp_password','clear_slack_webhook','clear_snmp_community','slack_recovery','slack_mention_critical_only','slack_options_present','combined_setup','unlock','proxy_enabled'}
                        data={key:str(numbers.get(key,False if key in booleans else 'audit')) for key in route['fields']}
                        data.update({key:value for key,value in {'csrf_token':'invalid-csrf','network_ids':'1','policy_group_ids':str(gid),'application_ids':str(aid),'rule_ids':str(rid),'candidate_ids':'1','port':'443'}.items() if key in route['fields']})
                        files={key:('audit.json',b'{}','application/json') for key in route['files']}
                        response=client.post(path,data=data,files=files or None,follow_redirects=False)
                        if route['path']=='/traffic/settings/retention':
                            self.assertEqual(response.status_code,303)
                            self.assertIn('error=',response.headers['location'])
                        else:self.assertEqual(response.status_code,403,(role,path,response.status_code,response.text[:150]))
                    record.append({'role':role,'method':route['method'],'path':route['path'],'status':response.status_code})
                helper.assert_not_called();outbound.assert_not_called()
        self.assertEqual(before,state_snapshot(),'Read-only pages and rejected mutations must not change policy')
        from starlette.testclient import TestClient
        from app.main import app
        with TestClient(app,base_url='https://localhost') as client:
            for route in inventory()['routes']:
                if route['path']=='/login' and route['method']=='POST':continue
                path=re.sub(r'{(\w+)}',lambda match:str(mapping[match[1]]),route['path'])
                response=client.request(route['method'],path,follow_redirects=False)
                self.assertEqual(response.status_code,200 if path=='/login' else 303,(path,response.status_code))
                record.append({'role':'anonymous','method':route['method'],'path':route['path'],'status':response.status_code})
        if os.getenv('SWG_FUNCTION_AUDIT_REPORT'):Path(os.environ['SWG_FUNCTION_AUDIT_REPORT']).write_text(json.dumps(record,indent=2),encoding='utf-8')
        print('Endpoint role/CSRF/anonymous checks:',len(record))

    def test_activity_get_is_read_only_and_auditors_can_view_it(self):
        from app.services.deployment import generate_config
        from app.config import LIVE_MANAGED_CONF
        c=self.connect();c.execute('UPDATE networks SET pending=1');c.commit();c.close()
        LIVE_MANAGED_CONF.parent.mkdir(parents=True,exist_ok=True);LIVE_MANAGED_CONF.write_text(generate_config())
        client,_=self.client_for('viewer')
        with client:
            response=client.get('/changes/review');self.assertEqual(response.status_code,200)
            self.assertNotIn('>Approve &amp; apply<',response.text)
        c=self.connect();self.assertEqual(c.execute('SELECT pending FROM networks WHERE id=1').fetchone()[0],1);c.close()

    def test_invalid_traffic_queries_fail_as_client_errors(self):
        client,_=self.client_for('viewer')
        with client:
            for path in ('/traffic/explorer','/traffic/export.csv','/traffic/export.xlsx','/traffic/clients/10.20.0.10'):
                for query in ('port=bad','port=65536','network_id=-1','application_id=9999999999999999999999999','client_ip=bad','date_from=invalid','date_from=2026-11-14T12:00&date_to=2026-11-13T12:00'):
                    response=client.get(path+'?'+query);self.assertEqual(response.status_code,400,(path,query,response.status_code))

    def test_login_logout_cookie_flags_and_malformed_hash_fail_closed(self):
        from app import auth
        from app.main import app
        from app.config import SESSION_COOKIE
        from starlette.testclient import TestClient
        c=self.connect();c.execute("INSERT INTO users(username,password_hash,role,enabled) VALUES('login-user',?,'viewer',1)",(auth.PH.hash('Strong-test-password-123'),));c.commit();c.close()
        with TestClient(app,base_url='https://localhost') as client:
            self.assertEqual(client.post('/login',data={'username':'admin','password':'wrong'}).status_code,401)
            self.assertEqual(client.post('/login',data={'username':'login-user','password':'wrong'}).status_code,401)
            result=client.post('/login',data={'username':'login-user','password':'Strong-test-password-123'},follow_redirects=False)
            self.assertEqual(result.status_code,303)
            cookie=result.headers['set-cookie'].lower();self.assertIn('httponly',cookie);self.assertIn('secure',cookie);self.assertIn('samesite=strict',cookie)
            self.assertTrue(client.cookies.get(SESSION_COOKIE));c=self.connect();csrf=c.execute("SELECT s.csrf_token FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.username='login-user'").fetchone()[0];c.close()
            self.assertEqual(client.post('/logout',data={'csrf_token':'wrong'}).status_code,403)
            self.assertEqual(client.post('/logout',data={'csrf_token':csrf},follow_redirects=False).status_code,303)
            self.assertEqual(client.get('/policies/groups',follow_redirects=False).status_code,303)

    def test_login_lockout_admin_unlock_and_password_reset_revoke_sessions(self):
        from app import auth
        from app.main import app
        from starlette.testclient import TestClient
        c=self.connect();uid=c.execute("INSERT INTO users(username,password_hash,role,enabled) VALUES('lock-user',?,'viewer',1)",(auth.PH.hash('Strong-test-password-123'),)).lastrowid;c.commit();c.close()
        with TestClient(app,base_url='https://localhost') as client:
            for _ in range(5):self.assertEqual(client.post('/login',data={'username':'lock-user','password':'wrong'}).status_code,401)
            self.assertEqual(client.post('/login',data={'username':'lock-user','password':'Strong-test-password-123'}).status_code,401)
            admin,csrf=self.client_for('admin')
            with admin:
                result=admin.post('/security/users/'+str(uid)+'/edit',data={'csrf_token':csrf,'role':'viewer','enabled':'true','unlock':'true'},follow_redirects=False)
                self.assertEqual(result.status_code,303)
                self.assertEqual(client.post('/login',data={'username':'lock-user','password':'Strong-test-password-123'},follow_redirects=False).status_code,303)
                self.assertEqual(client.get('/policies/groups').status_code,200)
                self.assertEqual(admin.post('/security/users/'+str(uid)+'/edit',data={'csrf_token':csrf,'role':'viewer','enabled':'true','new_password':'Changed-test-password-456'},follow_redirects=False).status_code,303)
                self.assertEqual(client.get('/policies/groups',follow_redirects=False).status_code,303)

    def test_domain_rule_edits_do_not_wait_for_external_dns(self):
        from app.services.rules import create_rule,update_rule
        from app.services.deployment import generate_config
        with patch('socket.getaddrinfo',side_effect=AssertionError('Policy edits must not depend on DNS')):
            result=create_rule('domain','offline.example.com','HTTPS',[1],'admin','Offline fixture')
            update_rule(result['id'],'another-offline.example.com','HTTPS',[1],'admin','Update offline fixture')
            self.assertIn('another-offline.example.com',generate_config())

    def test_concurrent_admin_edits_cannot_remove_all_administrators(self):
        from app.routers.users import edit_user
        from starlette.requests import Request
        c=self.connect();second=c.execute("INSERT INTO users(username,password_hash,role,enabled) VALUES('second-admin','unused-test-hash','admin',1)").lastrowid;c.commit();c.close()
        barrier=threading.Barrier(2);original=self.connect
        def connected():
            c=original();barrier.wait(timeout=5);return c
        def change(actor,target):
            from app.main import app
            request=Request({'type':'http','headers':[],'client':('127.0.0.1',1),'app':app,'server':('localhost',443),'scheme':'https','path':'/security/users','method':'POST','query_string':b''})
            request.state.user={'id':actor,'username':'admin' if actor==1 else 'second-admin','role':'admin','csrf_token':'fixture-csrf'}
            return edit_user(target,request,role='viewer',enabled=True,new_password='',unlock=False,csrf_token='fixture-csrf').status_code
        with patch('app.routers.users.connect',side_effect=connected),ThreadPoolExecutor(max_workers=2) as pool:
            futures=[pool.submit(change,1,second),pool.submit(change,second,1)];statuses=[future.result(timeout=15) for future in futures]
        self.assertEqual(sorted(statuses),[303,400]);c=self.connect();self.assertEqual(c.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND enabled=1").fetchone()[0],1);c.close()

    def test_archived_profile_cannot_be_reactivated_by_status_toggle(self):
        from app.services.access_model import create_policy_group,delete_policy_group,set_policy_group_status
        gid=create_policy_group('Archived fixture','',[],[],[],'admin');delete_policy_group(gid,'admin')
        with self.assertRaises(ValueError):set_policy_group_status(gid,'active','admin')

    def test_xlsx_control_characters_remain_valid_xml(self):
        import zipfile,xml.etree.ElementTree as ET
        from app.services.traffic import export_xlsx
        with patch('app.services.traffic._export_rows',return_value=[{'network_name':'Office\x00\x01 & safe','bytes':123}]):
            with zipfile.ZipFile(io.BytesIO(export_xlsx({}))) as archive:
                xml=archive.read('xl/worksheets/sheet1.xml');ET.fromstring(xml);self.assertNotIn(b'\x00',xml)

    def test_new_har_import_rejects_oversize_before_creating_application(self):
        client,csrf=self.client_for('admin');c=self.connect();before=c.execute('SELECT COUNT(*) FROM applications').fetchone()[0];c.close()
        with client,patch('app.routers.applications.DISCOVERY_MAX_HAR_BYTES',16):
            response=client.post('/applications/discover/har',data={'name':'Oversize fixture','csrf_token':csrf},files={'har_file':('large.har',b'x'*17,'application/json')},follow_redirects=False)
        self.assertEqual(response.status_code,303);self.assertIn('too+large',response.headers['location'])
        c=self.connect();self.assertEqual(c.execute('SELECT COUNT(*) FROM applications').fetchone()[0],before);c.close()

    def test_activity_failed_attempt_is_not_a_successful_baseline(self):
        c=self.connect();c.execute("INSERT INTO deployments(version,status,created_by,config_content,config_sha256,state_json) VALUES('failed-fixture','failed','admin','','fixture','{}')");c.commit();c.close()
        client,_=self.client_for('viewer')
        with client:response=client.get('/changes/review')
        self.assertEqual(response.status_code,200)
        self.assertIn('Last successful baseline</span><b>None</b>',response.text)
        self.assertNotIn('>Available<',response.text)


if __name__=='__main__':
    h=prior.prior.prior.prior.prior.prior.health
    with h.tempfile.TemporaryDirectory(prefix='swg-v3126-') as td:
        h.os.environ.update(SWG_DB_PATH=str(h.Path(td)/'initial.db'),SWG_DATA_ROOT=td,SWG_LIVE_MANAGED_CONF=str(h.Path(td)/'live.conf'),SWG_MODE='production',SWG_PROXY_IP='127.0.0.1',SWG_FQDN='localhost')
        h.subprocess.check_call([h.sys.executable,str(h.ROOT/'tools/migrate.py'),'--db',h.os.environ['SWG_DB_PATH'],'--root',str(h.ROOT)])
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(DetailedFunctionalAudit))
        if not result.wasSuccessful():h.sys.exit(1)
