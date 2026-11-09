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

    def test_learning_is_scoped_and_stops(self):
        from app.services.learning import start_session, process_learning_sessions, latest_session, stop_session
        aid = self._app()
        with patch('app.services.apply.save_apply_state', return_value={'dirty': False}):
            sid = start_session(aid, '10.20.0.10', 'admin')
            with self.assertRaises(ValueError):
                start_session(aid, '10.20.0.10', 'admin')
            with self.assertRaises(ValueError):
                start_session(aid, '10.20.0.11', 'operator')
        now = time.time()
        self._event(now, 'portal.example.com', 'ALLOW', str(aid))
        self._event(now + .001, 'api.vendor.example')
        self._event(now + .002, 'www.google-analytics.com')
        self._event(now + .003, 'other-device.example', client='10.20.0.99')
        self._event(now + .004, 'private.example')
        def public(host, port):
            if host == 'private.example':
                raise ValueError('private')
            return ['93.184.215.14']
        time.sleep(.01)
        with patch('app.services.apply.save_apply_state', return_value={'dirty': False}), patch('app.services.apply.apply_saved_change', return_value={'ok': True, 'applied': True}), patch('app.services.discovery._public_addresses', side_effect=public):
            result = process_learning_sessions()
            self.assertEqual(result, [{'session': sid, 'learned': 1}])
            self.assertEqual(process_learning_sessions(), [{'session': sid, 'learned': 0}])
        self.assertEqual(latest_session(aid)['learned_count'], 1)
        stop_session(aid, 'admin')
        self.assertEqual(latest_session(aid)['status'], 'stopped')
        self.assertEqual(process_learning_sessions(), [])

    def test_learning_refuses_pending_and_expired(self):
        from app.services.learning import start_session, process_learning_sessions, latest_session
        aid = self._app()
        with patch('app.services.apply.save_apply_state', return_value={'dirty': True}):
            with self.assertRaisesRegex(ValueError, 'pending'):
                start_session(aid, '10.20.0.10', 'admin')
        with patch('app.services.apply.save_apply_state', return_value={'dirty': False}):
            sid = start_session(aid, '10.20.0.10', 'admin')
        with patch('app.services.apply.save_apply_state', return_value={'dirty': True}):
            process_learning_sessions()
        self.assertEqual(latest_session(aid)['status'], 'failed')
        c = self.connect()
        c.execute("UPDATE application_learning_sessions SET status='active',expires_epoch=? WHERE id=?", (time.time()-1, sid))
        c.commit()
        c.close()
        self.assertEqual(process_learning_sessions(), [])
        self.assertEqual(latest_session(aid)['status'], 'completed')

    def test_learning_batches_through_real_save_apply(self):
        from app.services.learning import start_session, process_learning_sessions
        from app.services.deployment import generate_config, CANDIDATE_ROOT, LIVE_MANAGED_CONF
        from app.services.apply import save_apply_state
        aid = self._app()
        c = self.connect()
        c.execute('INSERT INTO application_networks(application_id,network_id) VALUES(?,1)', (aid,))
        c.commit()
        c.close()
        LIVE_MANAGED_CONF.write_text(generate_config())
        sid = start_session(aid, '10.20.0.10', 'admin')
        now = time.time()
        self._event(now, 'portal.example.com', 'ALLOW', str(aid))
        self._event(now+.001, 'api.vendor.example')
        self._event(now+.002, 'assets.vendor.example')
        time.sleep(.01)
        def helper(action, **payload):
            self.assertEqual(action, 'deploy')
            content = (CANDIDATE_ROOT/payload['candidate_id']/'security-web-gateway.conf').read_text()
            LIVE_MANAGED_CONF.write_text(content)
            return {'ok': True, 'message': 'Test transport applied candidate'}
        with patch('app.services.discovery._public_addresses', return_value=['93.184.215.14']), patch('app.services.deployment.helper_request', side_effect=helper) as transport:
            result = process_learning_sessions()
        self.assertEqual(result, [{'session':sid, 'learned':2}])
        self.assertEqual(transport.call_count, 1)
        self.assertFalse(save_apply_state()['dirty'])
        self.assertIn('api.vendor.example', LIVE_MANAGED_CONF.read_text())
        self.assertIn('assets.vendor.example', LIVE_MANAGED_CONF.read_text())

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
            with patch('app.services.apply.save_apply_state', return_value={'dirty': False}):
                sid = start_session(aid, '10.20.0.10', 'admin')
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


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='swg-v3100-') as td:
        os.environ.update(SWG_DB_PATH=str(Path(td)/'initial.db'), SWG_DATA_ROOT=td, SWG_LIVE_MANAGED_CONF=str(Path(td)/'managed.conf'), SWG_MODE='production', SWG_PROXY_IP='127.0.0.1', SWG_FQDN='localhost')
        subprocess.check_call([sys.executable, str(ROOT/'tools/migrate.py'), '--db', os.environ['SWG_DB_PATH'], '--root', str(ROOT)])
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Workflows))
        if not result.wasSuccessful():
            sys.exit(1)
