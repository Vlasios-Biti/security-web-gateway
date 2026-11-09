#!/usr/bin/env python3
"""Connection publishing, route permissions and bounded learning regressions."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class Workflows(unittest.TestCase):
    def setUp(self):
        import app.db as db
        self.tmp = tempfile.TemporaryDirectory(prefix="swg-case-")
        self.path = Path(self.tmp.name) / "test.db"
        subprocess.check_call([sys.executable, str(ROOT / "tools/migrate.py"), "--db", str(self.path), "--root", str(ROOT)], stdout=subprocess.DEVNULL)
        db.DB_PATH = self.path
        self.connect = db.connect
        c = self.connect()
        try:
            for role in ("admin", "operator", "viewer"):
                c.execute("INSERT INTO users(username,password_hash,role,enabled) VALUES(?,?,?,1)", (role, "unused-test-hash", role))
            c.execute("INSERT INTO networks(name,cidr,proxy_enabled,enabled,pending,created_by) VALUES('Test','10.20.0.0/24',1,1,0,'admin')")
            c.commit()
        finally:
            c.close()

    def tearDown(self):
        self.tmp.cleanup()

    def test_pac_validation_and_package(self):
        from app.services.pac_policy import validate_policy, render_pac
        from app.services.connectivity import windows_package
        policy = validate_policy({"fail_open": True, "internal_direct": True, "bypass": ["*.EXAMPLE.com", "192.0.2.23/24", "portal.example.com", "*.example.com"]})
        self.assertEqual(policy["bypass"], ["*.example.com", "192.0.2.0/24", "portal.example.com"])
        self.assertIn("PROXY 127.0.0.1:3128; DIRECT", render_pac(policy, "127.0.0.1", 3128))
        policy["fail_open"] = False
        self.assertNotIn("; DIRECT", render_pac(policy, "127.0.0.1", 3128))
        for entry in ('https://example.com', 'example.com\";alert(1)', '*.com', '192.0.2.1:443', '2001:db8::/32'):
            with self.assertRaises(ValueError):
                validate_policy({"fail_open": True, "internal_direct": True, "bypass": [entry]})
        with zipfile.ZipFile(io.BytesIO(windows_package())) as archive:
            self.assertIn('payload/Proxy-Control-Endpoint.ps1', archive.namelist())
            self.assertIn('http://127.0.0.1:8081/proxy.pac', archive.read('Install-Managed-Proxy.ps1').decode())
            self.assertIn('START-HERE.txt', archive.namelist())

    def test_failed_publish_keeps_previous_settings(self):
        from app.services.connectivity import connection_policy, save_connection_policy
        old = {"fail_open": True, "internal_direct": True, "bypass": ["old.example.com"]}
        with patch('app.services.deployment.helper_request', return_value={"ok": True}):
            save_connection_policy(old, 'admin')
        with patch('app.services.deployment.helper_request', return_value={"ok": False, "message": "disk full"}):
            with self.assertRaisesRegex(ValueError, 'disk full'):
                save_connection_policy({**old, "bypass": ["new.example.com"]}, 'admin')
        self.assertEqual(connection_policy(), old)

    def test_generated_pac_routing(self):
        from app.services.pac_policy import render_pac
        policy = {"fail_open": True, "internal_direct": True, "bypass": ['portal.example.com', '*.example.org', '198.51.100.0/24']}
        payload = {"open": render_pac(policy, '192.0.2.10', 3128), "closed": render_pac({**policy, 'fail_open': False}, '192.0.2.10', 3128)}
        import shutil
        node = shutil.which('node')
        if node:
            subprocess.run([node, str(ROOT/'tests/pac_contract.cjs')], input=json.dumps(payload), text=True, check=True)
        else:
            self.skipTest('Node is required to execute the PAC routing contract')

    def test_privileged_pac_atomic_publish(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('helper_test', ROOT/'privileged/security-web-gateway-deploy-helper.py')
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        helper.PAC = Path(self.tmp.name)/'proxy.pac'
        helper.PAC.write_text('previous PAC')
        helper.ENV_FILE = Path(self.tmp.name)/'production.env'
        helper.ENV_FILE.write_text('SWG_PROXY_IP=192.0.2.10\nSWG_PROXY_PORT=3128\n')
        helper.LOCK = Path(self.tmp.name)/'lock'
        helper.BACKUPS = Path(self.tmp.name)/'backups'
        helper.PAC_RENDERER = ROOT/'app/services/pac_policy.py'
        policy = {'fail_open': True, 'internal_direct': True, 'bypass': ['*.example.com']}
        result = helper.publish_pac(policy)
        self.assertTrue(result['ok'])
        self.assertEqual(Path(result['backup']).read_text(), 'previous PAC')
        published = helper.PAC.read_text()
        self.assertIn('PROXY 192.0.2.10:3128; DIRECT', published)
        with self.assertRaises(ValueError):
            helper.publish_pac({**policy, 'bypass': ['evil"; alert(1)']})
        self.assertEqual(helper.PAC.read_text(), published)

    def test_route_auth_csrf_and_rendering(self):
        from starlette.testclient import TestClient
        from app.main import app
        from app.auth import create_session
        from app.config import SESSION_COOKIE
        from starlette.requests import Request
        app.state.mode = 'production'
        with TestClient(app, base_url='https://localhost') as client:
            self.assertEqual(client.get('/connection', follow_redirects=False).status_code, 303)
            for role in ('operator', 'viewer', 'admin'):
                c = self.connect()
                user = c.execute('SELECT id FROM users WHERE username=?', (role,)).fetchone()
                c.close()
                request = Request({'type': 'http', 'headers': [], 'client': ('127.0.0.1', 1234)})
                token = create_session(user['id'], request)
                client.cookies.set(SESSION_COOKIE, token)
                expected = 200 if role == 'admin' else 403
                self.assertEqual(client.get('/connection').status_code, expected)
                self.assertEqual(client.get('/connection/windows.zip').status_code, expected)
                self.assertEqual(client.post('/connection', data={'csrf_token': 'wrong'}).status_code, 403)
                self.assertEqual(client.post('/connection/services/windows-update',data={'csrf_token':'wrong','enabled':'true'}).status_code,403)
            response = client.get('/connection')
            self.assertIn('One policy. Every device.', response.text)
            self.assertNotIn('Search traffic</a>', response.text)
            c = self.connect()
            csrf = c.execute('SELECT csrf_token FROM sessions ORDER BY id DESC LIMIT 1').fetchone()['csrf_token']
            c.close()
            with patch('app.services.deployment.helper_request', return_value={'ok': True}):
                result = client.post('/connection', data={'csrf_token': csrf, 'fail_open': 'true', 'bypass': '*.example.com\n192.0.2.0/24'}, follow_redirects=False)
            self.assertEqual(result.status_code, 303)

    def _app(self):
        from app.services.access_model import create_application, create_application_dependency
        aid = create_application('Learning App', 'Test', '', 'portal.example.com', 'observed', 'https://portal.example.com', False, 'admin')
        create_application_dependency(aid, 'domain', 'portal.example.com', 'HTTPS', 'admin')
        return aid

    def _event(self, epoch, host, decision='DENY', apps='', client='10.20.0.10'):
        c = self.connect()
        try:
            c.execute("INSERT INTO telemetry_events(epoch,event_time,client_ip,decision,destination_host,destination_port,application_ids,event_hash) VALUES(?,'2026-11-09T12:00:00Z',?,?,?,443,?,?)", (epoch, client, decision, host, apps, f'{host}-{epoch}-{client}'))
            c.commit()
        finally:
            c.close()

    def test_browser_auto_approval_respects_selection(self):
        import app.services.discovery as discovery
        aid = self._app()
        run_id = discovery.create_run(aid, 'https://portal.example.com', 'browser_auto', 'admin', auto_approve=True)
        items = [
            {'endpoint_type':'domain','destination':'portal.example.com','protocol':'HTTPS','selected':True,'recommendation':'allow'},
            {'endpoint_type':'domain','destination':'cdn.vendor.example','protocol':'HTTPS','selected':True,'recommendation':'review'},
            {'endpoint_type':'domain','destination':'analytics.vendor.example','protocol':'HTTPS','selected':False,'recommendation':'ignore'},
        ]
        with patch.object(discovery, 'discover_browser', return_value=(items, 'test-version', 'https://portal.example.com')):
            discovery.process_browser_queue()
        c = self.connect()
        try:
            hosts = {r['destination'] for r in c.execute('SELECT r.destination FROM rules r JOIN application_rules ar ON ar.rule_id=r.id WHERE ar.application_id=?', (aid,))}
        finally:
            c.close()
        self.assertIn('cdn.vendor.example', hosts)
        self.assertNotIn('analytics.vendor.example', hosts)

    def test_policy_rollback_stops_learning_and_preserves_history(self):
        from app.services.deployment import deploy, rollback_to
        from app.services.learning import start_session, latest_session
        from app.services.access_model import create_application_dependency
        aid = self._app()
        with patch('app.services.deployment.helper_request', return_value={'ok': True, 'message':'test apply'}):
            deploy('admin', None, 'baseline')
            c = self.connect()
            baseline = c.execute('SELECT MAX(id) FROM deployments').fetchone()[0]
            c.close()
            c = self.connect()
            sid = c.execute("INSERT INTO application_learning_sessions(application_id,client_ip,started_by,started_epoch,expires_epoch) VALUES(?,'10.20.0.10','admin',?,?)", (aid,time.time(),time.time()+600)).lastrowid
            c.commit()
            c.close()
            rid = create_application_dependency(aid, 'domain', 'new.vendor.example', 'HTTPS', 'admin')
            c = self.connect()
            c.execute('INSERT INTO application_learning_destinations VALUES(?,?,?,?,?)', (sid,'new.vendor.example','HTTPS',123,rid))
            c.commit()
            c.close()
            self.assertTrue(rollback_to(baseline, 'admin', None)['ok'])
        self.assertEqual(latest_session(aid)['status'], 'stopped')
        c = self.connect()
        try:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM application_learning_destinations WHERE session_id=?', (sid,)).fetchone()[0], 1)
            self.assertFalse(list(c.execute('PRAGMA foreign_key_check')))
        finally:
            c.close()

    def test_ip_correlation_can_never_publish(self):
        from app.services.learning import start_session, process_learning_sessions
        aid=self._app()
        with self.assertRaisesRegex(ValueError,'disabled'):
            start_session(aid,'10.20.0.10','admin')
        c=self.connect()
        c.execute("INSERT INTO application_learning_sessions(application_id,client_ip,started_by,started_epoch,expires_epoch) VALUES(?,'10.20.0.10','admin',?,?)",(aid,time.time(),time.time()+600))
        c.commit();c.close()
        self._event(time.time(),'portal.example.com','ALLOW',str(aid))
        self._event(time.time(),'unrelated-pc-traffic.example')
        with patch('app.services.apply.apply_saved_change') as publish,patch('app.services.access_model.create_application_dependency') as add:
            result=process_learning_sessions()
            self.assertEqual(result[0]['status'],'stopped')
            publish.assert_not_called();add.assert_not_called()

    def test_tab_capture_is_review_only_and_discards_secrets(self):
        from app.services.tab_capture import create_capture_run,parse_capture
        from app.services.discovery import get_run
        aid=self._app()
        payload={'format':'swg-tab-capture-v1','scope':'selected-tab','seed_host':'portal.example.com','cookies':'private-secret',
            'destinations':[{'host':'api.vendor.example','protocol':'HTTPS','request_count':3,'resource_types':['xhr'],'url':'https://api.vendor.example/path?token=private-secret'},
            {'host':'google-analytics.com','protocol':'HTTPS','request_count':1,'resource_types':['script']}]}
        raw=json.dumps(payload).encode()
        with patch('app.services.apply.apply_saved_change') as publish:
            rid=create_capture_run(aid,raw,'admin')
            publish.assert_not_called()
        run=get_run(rid)
        self.assertEqual(run['status'],'ready')
        self.assertEqual(run['auto_apply'],0)
        self.assertNotIn('private-secret',json.dumps(run))
        self.assertEqual([x['destination'] for x in run['candidates'] if x['selected']],['api.vendor.example'])
        with self.assertRaisesRegex(ValueError,'another domain'):
            parse_capture(raw,'different.example.com')
        with self.assertRaises(ValueError):
            parse_capture(json.dumps({**payload,'seed_host':42}).encode(),'portal.example.com')

    def test_pc_services_are_optional_scoped_and_share_rules_safely(self):
        from app.services.pc_services import save_service,service_profiles
        from app.services.deployment import generate_config
        self.assertFalse(any(x['enabled'] for x in service_profiles()))
        c=self.connect()
        gid=c.execute("INSERT INTO policy_groups(name,status,created_by) VALUES('Update PCs','active','admin')").lastrowid
        c.execute('INSERT INTO policy_group_networks(group_id,network_id) VALUES(?,1)',(gid,));c.commit();c.close()
        with self.assertRaises(ValueError):save_service('windows-update',True,[],'admin')
        with self.assertRaises(ValueError):save_service('windows-update',True,[gid],'operator')
        update_id=save_service('windows-update',True,[gid],'admin')
        defender_id=save_service('defender-updates',True,[gid],'admin')
        self.assertNotIn('dstdomain .microsoft.com\n',generate_config())
        self.assertIn('.windowsupdate.com',generate_config())
        save_service('windows-update',False,[gid],'admin')
        self.assertIn('.windowsupdate.com',generate_config())
        c=self.connect()
        try:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM rules WHERE destination='*.windowsupdate.com' AND status='active'").fetchone()[0],1)
            self.assertEqual(c.execute('SELECT status FROM applications WHERE id=?',(update_id,)).fetchone()[0],'disabled')
            self.assertEqual(c.execute('SELECT status FROM applications WHERE id=?',(defender_id,)).fetchone()[0],'active')
        finally:c.close()
        save_service('defender-updates',False,[gid],'admin')
        self.assertNotIn('.windowsupdate.com',generate_config())

    def test_service_protocol_conflict_is_transactional(self):
        from app.services.pc_services import save_service
        from app.services.access_model import create_application_dependency
        aid=self._app()
        create_application_dependency(aid,'domain','*.windowsupdate.com','HTTPS','admin')
        c=self.connect()
        gid=c.execute("INSERT INTO policy_groups(name,status,created_by) VALUES('Conflict test','active','admin')").lastrowid
        c.commit();c.close()
        with self.assertRaisesRegex(ValueError,'conflict'):
            save_service('windows-update',True,[gid],'admin')
        c=self.connect()
        try:
            self.assertFalse(c.execute("SELECT id FROM applications WHERE source_ref='pc-service:windows-update'").fetchone())
            self.assertEqual(c.execute("SELECT protocol FROM rules WHERE destination='*.windowsupdate.com'").fetchone()[0],'HTTPS')
        finally:c.close()

    def test_selected_tab_recorder_contract(self):
        import shutil
        node=shutil.which('node')
        if not node:self.skipTest('Node is required for the selected-tab contract')
        subprocess.run([node,str(ROOT/'tests/tab_capture_contract.cjs')],check=True)

    def test_custom_source_reference_cannot_impersonate_pc_service(self):
        from app.services.access_model import create_application
        from app.services.pc_services import service_profiles
        create_application('Ordinary app','Test','','example.com','manual','pc-service:windows-update',False,'operator')
        self.assertFalse(any(item['enabled'] for item in service_profiles()))


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='swg-v3100-') as td:
        os.environ.update(SWG_DB_PATH=str(Path(td)/'initial.db'), SWG_DATA_ROOT=td, SWG_LIVE_MANAGED_CONF=str(Path(td)/'managed.conf'), SWG_MODE='production', SWG_PROXY_IP='127.0.0.1', SWG_FQDN='localhost')
        subprocess.check_call([sys.executable, str(ROOT/'tools/migrate.py'), '--db', os.environ['SWG_DB_PATH'], '--root', str(ROOT)])
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Workflows))
        if not result.wasSuccessful():
            sys.exit(1)
