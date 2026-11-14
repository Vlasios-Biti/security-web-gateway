#!/usr/bin/env python3
"""Domain corrections, current PC labels and scoped monitoring API regressions."""
import hashlib,json,os,sqlite3,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import smoke_v31210 as prior


class IntegrationsAndCorrections(prior.ApplicationProfiles):
    def target(self,protected=False):
        from app.services.access_model import create_application
        return create_application('Target application','Test','','target.example.test','manual','',False,'admin',system_managed=protected)

    def test_domain_move_is_atomic_preserves_shared_rules_and_restricts_protected_targets(self):
        from app.services.access_model import get_application,create_application,create_application_dependency
        from app.services.dependency_assignment import move_dependency
        source=self._app();target=self.target(True)
        rid=get_application(source)['dependencies'][0]['id']
        with self.assertRaises(ValueError):move_dependency(source,rid,target,'operator')
        self.assertTrue(get_application(source)['dependencies']);self.assertFalse(get_application(target)['dependencies'])
        move_dependency(source,rid,target,'admin')
        self.assertFalse(get_application(source)['dependencies']);self.assertEqual(get_application(target)['dependencies'][0]['id'],rid)
        c=self.connect();self.assertIsNotNone(c.execute('SELECT 1 FROM rules WHERE id=?',(rid,)).fetchone());self.assertEqual(c.execute('SELECT target_application_id FROM dependency_corrections').fetchone()[0],target);c.close()
        with self.assertRaises(ValueError):move_dependency(source,rid,target,'admin')

    def test_candidate_move_merges_without_granting_access_and_remembers_future_correlation(self):
        from app.services.dependency_assignment import move_candidate,catalog,suggestions
        from app.services.deployment import state_snapshot
        from app.services.traffic import refresh_dependency_candidates
        source=self._app();target=self.target();cid=self.candidate(source,'api.target.example.test');other=self.candidate(target,'api.target.example.test')
        before=state_snapshot();move_candidate(cid,target,'admin');self.assertEqual(state_snapshot(),before)
        c=self.connect();self.assertEqual(c.execute('SELECT status FROM application_dependency_candidates WHERE id=?',(cid,)).fetchone()[0],'ignored')
        self.assertEqual(suggestions('api.target.example.test',source,catalog(c))[0]['id'],target);c.close()
        now=time.time();self.event('10.20.0.10','portal.example.com','prev',now-2);self.event('10.20.0.10','api.target.example.test','new',now,'DENY')
        c=self.connect();c.execute("UPDATE telemetry_events SET application_ids=? WHERE event_hash='pc-fixture-prev'",(','+str(source)+',',));c.commit();c.close()
        refresh_dependency_candidates()
        c=self.connect();self.assertEqual(c.execute('SELECT confidence FROM application_dependency_candidates WHERE id=?',(other,)).fetchone()[0],'low')
        self.assertEqual(c.execute("SELECT COUNT(*) FROM application_dependency_candidates WHERE application_id=? AND status='pending'",(source,)).fetchone()[0],0);c.close()

    def test_move_routes_require_role_csrf_and_publish_once(self):
        from app.services.access_model import get_application
        source=self._app();target=self.target();rid=get_application(source)['dependencies'][0]['id'];client,csrf=self.client_for('admin')
        path=f'/applications/{source}/dependency/{rid}/move'
        with client,patch('app.routers.applications.apply_saved_change',return_value={'ok':True,'applied':True}) as apply:
            self.assertEqual(client.get(path).status_code,200)
            self.assertEqual(client.post(path,data={'target_application_id':target,'csrf_token':'bad'},follow_redirects=False).status_code,403)
            response=client.post(path,data={'target_application_id':target,'csrf_token':csrf},follow_redirects=False)
            self.assertEqual(response.status_code,303);apply.assert_called_once()
        self.assertFalse(get_application(source)['dependencies'])

    def test_pc_labels_are_searchable_override_current_dns_and_can_be_cleared(self):
        from app.services.client_identity import save_label
        from app.services.traffic import client_inventory,client_detail
        self.event('10.20.0.10','portal.example.test','pc')
        c=self.connect();c.execute('INSERT INTO dashboard_cache(key,payload_json,expires_at) VALUES(?,?,?)',('client-ptr:10.20.0.10',json.dumps({'hostname':'pc-office.example.test'}),time.time()+600));c.commit();c.close()
        save_label('10.20.0.10','Reception <PC>','admin')
        row=client_inventory(search='reception')['rows'][0];self.assertEqual(row['display_name'],'Reception <PC>');self.assertEqual(row['hostname'],'pc-office.example.test');self.assertEqual(row['identity_source'],'manual')
        self.assertEqual(client_detail('10.20.0.10')['meta']['label'],'Reception <PC>')
        client,csrf=self.client_for('admin')
        with client:
            response=client.get('/traffic/clients/10.20.0.10');self.assertIn('Reception &lt;PC&gt;',response.text);self.assertNotIn('Reception <PC>',response.text)
            self.assertEqual(client.post('/traffic/clients/10.20.0.10/label',data={'name':'','csrf_token':csrf},follow_redirects=False).status_code,303)
        self.assertEqual(client_inventory()['rows'][0]['display_name'],'pc-office.example.test')
        with self.assertRaises(ValueError):save_label('not-ip','Name','admin')

    def test_api_tokens_are_hashed_scoped_expiring_revocable_and_cookie_independent(self):
        from app.services.integrations import create_token,revoke_token
        raw=create_token('Monitor',['clients:read'],30,'admin');self.event('10.20.0.10','portal.example.test','api')
        c=self.connect();token=c.execute('SELECT * FROM api_tokens').fetchone();self.assertEqual(token['token_hash'],hashlib.sha256(raw.encode()).hexdigest());self.assertNotIn(raw,str(dict(token)));c.close()
        client,_=self.client_for('admin');headers={'Authorization':'Bearer '+raw}
        with client:
            self.assertEqual(client.get('/api/v1/clients').status_code,401)
            self.assertEqual(client.get('http://localhost/api/v1/clients',headers=headers).status_code,400)
            response=client.get('/api/v1/clients',headers=headers);self.assertEqual(response.status_code,200);self.assertEqual(response.json()['rows'][0]['ip'],'10.20.0.10')
            self.assertEqual(client.get('/api/v1/clients/10.20.0.10/traffic',headers=headers).status_code,403)
            self.assertEqual(client.post('/api/v1/clients',headers=headers,json={}).status_code,405)
            self.assertEqual(client.get('/api/v1/clients?period=bad',headers=headers).status_code,400)
            self.assertEqual(client.get('/api/v1/clients?token='+raw).status_code,401)
            revoke_token(token['id'],'admin');self.assertEqual(client.get('/api/v1/clients',headers=headers).status_code,401)

    def test_api_traffic_stays_on_path_ip_and_rate_limit_and_owner_revocation_apply(self):
        from app.services.integrations import create_token
        raw=create_token('Traffic',['traffic:read'],1,'admin');self.event('10.20.0.10','one.example.test','a');self.event('10.20.0.20','two.example.test','b')
        client,_=self.client_for('admin');headers={'Authorization':'Bearer '+raw}
        with client:
            response=client.get('/api/v1/clients/10.20.0.10/traffic?client_ip=10.20.0.20',headers=headers)
            self.assertEqual(response.status_code,200);self.assertEqual(response.json()['meta']['ip'],'10.20.0.10');self.assertNotIn('two.example.test',response.text)
            c=self.connect();c.execute('UPDATE api_tokens SET window_start=?,request_count=120',(int(time.time())//60,));c.commit();c.close()
            self.assertEqual(client.get('/api/v1/clients/10.20.0.10/traffic',headers=headers).status_code,429)
            c=self.connect();c.execute('UPDATE api_tokens SET request_count=0');c.execute("UPDATE users SET role='viewer' WHERE username='admin'");c.commit();c.close()
            self.assertEqual(client.get('/api/v1/clients/10.20.0.10/traffic',headers=headers).status_code,401)

    def test_api_gui_shows_secret_once_and_expired_tokens_are_refused(self):
        from app.services.integrations import create_token
        client,csrf=self.client_for('admin')
        with client:
            response=client.post('/system/integrations',data={'name':'Monitor','days':7,'scopes':'clients:read','csrf_token':csrf})
            self.assertEqual(response.status_code,200);raw=response.context['new_token'];self.assertTrue(raw.startswith('swg_'))
            self.assertNotIn(raw,client.get('/system/integrations').text)
            c=self.connect();c.execute("UPDATE api_tokens SET expires_at='2000-01-01'");c.commit();c.close()
            self.assertEqual(client.get('/api/v1/clients',headers={'Authorization':'Bearer '+raw}).status_code,401)
        with self.assertRaises(ValueError):create_token('Bad',['policies:write'],30,'admin')

    def test_recovery_message_clearly_marks_old_condition_without_repeating_stale_failure(self):
        from app.services.notifications import incident_line
        event={'active':0,'severity':'warning','title':'Configuration backup needs attention','detail':'No recent successful backup is recorded.'}
        line=incident_line(event);self.assertIn('Condition cleared',line);self.assertIn('Previous alert:',line);self.assertNotIn('No recent successful',line)
        self.assertIn('No recent successful',incident_line({**event,'active':1}))

    def test_portable_restore_revokes_imported_tokens_and_keeps_target_pc_labels(self):
        from tools.prepare_restored_policy import prepare_restored_policy
        from app.services.integrations import create_token
        from app.services.client_identity import save_label
        create_token('Source token',['clients:read'],30,'admin');save_label('10.20.0.10','Target PC','admin')
        staged=Path(self.tmp.name)/'import.db';backup=Path(self.tmp.name)/'before.db'
        with sqlite3.connect(self.path) as source,sqlite3.connect(staged) as destination:source.backup(destination)
        with sqlite3.connect(staged) as c:c.execute("UPDATE client_labels SET name='Imported PC'")
        prepare_restored_policy(self.path,backup,staged)
        with sqlite3.connect(staged) as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM api_tokens').fetchone()[0],0)
            self.assertEqual(c.execute('SELECT name FROM client_labels').fetchone()[0],'Target PC')


if __name__=='__main__':
    root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix='swg-v31211-') as td:
        os.environ.update(SWG_DB_PATH=td+'/initial.db',SWG_DATA_ROOT=td,SWG_LIVE_MANAGED_CONF=td+'/live.conf',SWG_MODE='production',SWG_PROXY_IP='127.0.0.1',SWG_FQDN='localhost')
        subprocess.run([sys.executable,str(root/'tools/migrate.py'),'--db',os.environ['SWG_DB_PATH'],'--root',str(root)],check=True)
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(IntegrationsAndCorrections))
        if not result.wasSuccessful():sys.exit(1)
