#!/usr/bin/env python3
"""Simple network onboarding, safe copies and optional audit notes."""
import unittest
from unittest.mock import patch
import smoke_v3110 as health

class SimpleWorkflows(health.HealthWorkflows):
    def client_for(self, role):
        from starlette.testclient import TestClient
        from starlette.requests import Request
        from app.main import app
        from app.auth import create_session
        from app.config import SESSION_COOKIE
        c=self.connect();uid=c.execute("SELECT id FROM users WHERE username=?",(role,)).fetchone()[0];c.close()
        token=create_session(uid,Request({'type':'http','headers':[],'client':('127.0.0.1',1)}))
        c=self.connect();csrf=c.execute("SELECT csrf_token FROM sessions WHERE user_id=? ORDER BY id DESC LIMIT 1",(uid,)).fetchone()[0];c.close()
        client=TestClient(app,base_url='https://localhost');client.cookies.set(SESSION_COOKIE,token)
        return client,csrf

    def test_network_needs_only_name_and_subnet_and_preserves_failed_input(self):
        client,csrf=self.client_for('admin')
        with client,patch('app.routers.policies.apply_saved_change',return_value={'ok':True,'applied':True}):
            response=client.post('/policies/networks/add',data={'name':'Finance','cidr':'10.31.0.0/24','csrf_token':csrf},follow_redirects=False)
            self.assertEqual(response.status_code,303)
            c=self.connect();row=c.execute("SELECT * FROM networks WHERE name='Finance'").fetchone();self.assertTrue(row['proxy_enabled']);self.assertEqual(row['reason'],'Created network');c.close()
            bad=client.post('/policies/networks/add',data={'name':'Keep this input','cidr':'bad-value','vlan_id':'131','csrf_token':csrf})
            self.assertEqual(bad.status_code,400);self.assertIn('Keep this input',bad.text);self.assertIn('bad-value',bad.text)
            self.assertEqual(client.post('/policies/networks/add',data={'name':'Blocked','cidr':'10.32.0.0/24','csrf_token':'wrong'}).status_code,403)

    def test_copy_keeps_access_and_requires_new_identity_without_changing_source(self):
        from app.services.rules import create_rule
        from app.services.access_model import create_policy_group
        gid=create_policy_group('Source profile','',[],[],[1],'admin')
        rid=create_rule('domain','copy.example','HTTPS',[1],'admin','Initial rule')['id']
        client,csrf=self.client_for('admin')
        with client,patch('app.routers.policies.apply_saved_change',return_value={'ok':True,'applied':True}):
            c=self.connect();before=c.execute('SELECT COUNT(*) FROM networks').fetchone()[0];c.close()
            preview=client.get('/policies/networks/1/copy')
            self.assertEqual(preview.status_code,200);self.assertIn('Create copy',preview.text);self.assertIn('name="cidr" value=""',preview.text)
            c=self.connect();self.assertEqual(c.execute('SELECT COUNT(*) FROM networks').fetchone()[0],before);c.close()
            data={'name':'Second office','cidr':'10.42.0.0/24','vlan_id':'142','clone_from_network_id':'1','policy_group_ids':str(gid),'csrf_token':csrf}
            self.assertEqual(client.post('/policies/networks/add',data=data,follow_redirects=False).status_code,303)
            c=self.connect();new=c.execute("SELECT id FROM networks WHERE name='Second office'").fetchone()[0]
            self.assertEqual(c.execute('SELECT cidr FROM networks WHERE id=1').fetchone()[0],'10.20.0.0/24')
            self.assertTrue(c.execute('SELECT 1 FROM rule_networks WHERE rule_id=? AND network_id=?',(rid,new)).fetchone())
            self.assertTrue(c.execute('SELECT 1 FROM policy_group_networks WHERE group_id=? AND network_id=?',(gid,new)).fetchone());c.close()
            # Explicitly deselecting profiles on the copy must be respected.
            data.update(name='Without profiles',cidr='10.43.0.0/24',vlan_id='143');data.pop('policy_group_ids')
            self.assertEqual(client.post('/policies/networks/add',data=data,follow_redirects=False).status_code,303)
            c=self.connect();new=c.execute("SELECT id FROM networks WHERE name='Without profiles'").fetchone()[0];self.assertFalse(c.execute('SELECT 1 FROM policy_group_networks WHERE network_id=?',(new,)).fetchone());c.close()
        for role in ('viewer','operator'):
            client,_=self.client_for(role)
            with client:self.assertEqual(client.get('/policies/networks/1/copy').status_code,403)

    def test_domain_and_ip_can_save_without_manual_justification(self):
        client,csrf=self.client_for('admin')
        with client,patch('app.routers.domains.apply_saved_change',return_value={'ok':True,'applied':True}),patch('app.routers.ips.apply_saved_change',return_value={'ok':True,'applied':True}):
            for route,dest in [('domains','simple.example'),('ips','203.0.113.51')]:
                response=client.post('/rules/'+route+'/add',data={'destination':dest,'protocol':'HTTPS','network_ids':'1','csrf_token':csrf},follow_redirects=False)
                self.assertEqual(response.status_code,303,response.text)
        c=self.connect();self.assertTrue(c.execute("SELECT reason FROM rules WHERE destination='simple.example'").fetchone()[0]);c.close()

if __name__=='__main__':
    with health.tempfile.TemporaryDirectory(prefix='swg-v3111-') as td:
        health.os.environ.update(SWG_DB_PATH=str(health.Path(td)/'initial.db'),SWG_DATA_ROOT=td,SWG_LIVE_MANAGED_CONF=str(health.Path(td)/'live.conf'),SWG_MODE='production',SWG_PROXY_IP='127.0.0.1',SWG_FQDN='localhost')
        health.subprocess.check_call([health.sys.executable,str(health.ROOT/'tools/migrate.py'),'--db',health.os.environ['SWG_DB_PATH'],'--root',str(health.ROOT)])
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(SimpleWorkflows))
        if not result.wasSuccessful():health.sys.exit(1)
