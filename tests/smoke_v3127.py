#!/usr/bin/env python3
"""Defensive regressions for recovery, protected resources and portable state."""
import io,json,os,sqlite3,subprocess,sys,threading,time,unittest,zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import smoke_v3126 as prior


class SecurityCorrections(prior.DetailedFunctionalAudit):
    def request(self,user=None):
        from starlette.requests import Request
        from app.main import app
        r=Request({'type':'http','headers':[],'client':('127.0.0.1',1),'server':('localhost',443),'scheme':'https','path':'/login','method':'POST','query_string':b'','app':app})
        r.state.user=user;return r

    def test_password_reset_wins_against_inflight_login(self):
        from app import auth
        from app.routers import users,auth_routes
        old='Dummy old password 482!';new='Dummy replacement 731!';hasher=auth.PH
        c=self.connect();c.execute("UPDATE users SET password_hash=? WHERE username='operator'",(hasher.hash(old),));uid=c.execute("SELECT id FROM users WHERE username='operator'").fetchone()[0];c.commit();c.close()
        ready=threading.Event();resume=threading.Event()
        def verify(hash,password):
            result=hasher.verify(hash,password);ready.set()
            if not resume.wait(5):raise RuntimeError('fixture timeout')
            return result
        with ThreadPoolExecutor(max_workers=1) as pool,patch.object(auth,'PH',SimpleNamespace(verify=verify,check_needs_rehash=hasher.check_needs_rehash,hash=hasher.hash)):
            future=pool.submit(auth_routes.login_submit,self.request(),username='operator',password=old)
            self.assertTrue(ready.wait(5))
            try:
                response=users.edit_user(uid,self.request({'id':1,'username':'admin','role':'admin','csrf_token':'dummy'}),role='operator',enabled=True,new_password=new,unlock=False,csrf_token='dummy')
                self.assertEqual(response.status_code,303)
            finally:resume.set()
            self.assertEqual(future.result(timeout=5).status_code,401)
        c=self.connect();stored=c.execute('SELECT password_hash FROM users WHERE id=?',(uid,)).fetchone()[0];count=c.execute('SELECT COUNT(*) FROM sessions WHERE user_id=? AND revoked_at IS NULL',(uid,)).fetchone()[0];c.close()
        self.assertTrue(hasher.verify(stored,new));self.assertEqual(count,0)
        with self.assertRaises(Exception):hasher.verify(stored,old)

    def test_reset_between_verification_and_session_insert_refuses_stale_proof(self):
        from app import auth
        c=self.connect();old=auth.PH.hash('Dummy original password');c.execute("UPDATE users SET password_hash=? WHERE username='operator'",(old,));uid=c.execute("SELECT id FROM users WHERE username='operator'").fetchone()[0];c.commit();c.close()
        user=auth.authenticate('operator','Dummy original password',self.request());self.assertIsNotNone(user)
        c=self.connect();c.execute('UPDATE users SET password_hash=? WHERE id=?',(auth.PH.hash('Dummy replaced password'),uid));c.commit();c.close()
        self.assertIsNone(auth.create_session(uid,self.request(),verified_password_hash=user['password_hash']))

    def protected_app(self,name='Protected fixture'):
        from app.services.access_model import create_application
        return create_application(name,'Dummy','','example.test','manual','',False,'admin',system_managed=True)

    def test_operator_discovery_cannot_reassign_protected_application(self):
        from app.services.access_model import get_application
        aid=self.protected_app();c=self.connect();c.execute('INSERT INTO application_networks VALUES(?,1)',(aid,));c.commit();c.close()
        before=get_application(aid);client,csrf=self.client_for('operator')
        with client,patch('app.routers.applications.create_run') as start:
            response=client.post('/applications/discover/custom',data={'name':'Protected fixture','method':'browser_auto','source_ref':'https://example.test/','auto_approve':1,'access_mode':'none','csrf_token':csrf},follow_redirects=False)
            self.assertEqual(response.status_code,403)
            response=client.post('/applications/discover/har',data={'name':'Protected fixture','access_mode':'none','csrf_token':csrf},files={'har_file':('fixture.har',b'{"log":{"entries":[]}}','application/json')},follow_redirects=False)
            self.assertEqual(response.status_code,403);start.assert_not_called()
        after=get_application(aid);self.assertEqual(after['network_ids'],before['network_ids']);self.assertEqual(after['pending'],before['pending'])

    def test_queued_discovery_rechecks_current_actor_and_resource(self):
        from app.services import discovery
        aid=self._app();rid=discovery.create_run(aid,'https://example.test/','browser_auto','operator',auto_approve=True)
        c=self.connect();c.execute("UPDATE users SET role='viewer' WHERE username='operator'");c.commit();c.close()
        with patch.object(discovery,'discover_browser') as browser:result=discovery.process_browser_queue(1);browser.assert_not_called()
        self.assertEqual(result[0]['status'],'failed');self.assertEqual(discovery.get_run(rid)['status'],'failed')
        aid=self.protected_app();rid=discovery.create_run(aid,'https://example.test/','browser_auto','operator',auto_approve=True)
        c=self.connect();c.execute("UPDATE users SET role='operator' WHERE username='operator'");c.commit();c.close()
        with patch.object(discovery,'discover_browser') as browser:result=discovery.process_browser_queue(1);browser.assert_not_called()
        self.assertEqual(result[0]['status'],'failed')

    def test_add_access_uses_real_sqlite_queue_without_form_objects(self):
        client,csrf=self.client_for('admin')
        with client,patch('app.services.discovery.discover_browser') as browser:
            response=client.post('/applications/allow',data={'destination':'portal.example.test','access_mode':'networks','network_ids':1,'csrf_token':csrf},follow_redirects=False)
            self.assertEqual(response.status_code,303);self.assertNotIn('error=',response.headers['location']);browser.assert_not_called()
        c=self.connect();row=c.execute("SELECT client_ip,window_minutes,status,method FROM discovery_runs ORDER BY id DESC LIMIT 1").fetchone();c.close()
        self.assertEqual(dict(row),{'client_ip':None,'window_minutes':10,'status':'running','method':'browser_auto'})

    def test_official_source_is_queued_without_network_under_edit_lock(self):
        client,csrf=self.client_for('admin')
        from app.services import discovery
        with client,patch.object(discovery,'safe_fetch') as fetch:
            response=client.post('/applications/discover/custom',data={'name':'Feed fixture','method':'official_url','seed_domain':'feed.example.test','source_ref':'https://feed.example.test/','csrf_token':csrf},follow_redirects=False)
            self.assertEqual(response.status_code,303);fetch.assert_not_called()
        c=self.connect();row=c.execute('SELECT id,status FROM discovery_runs ORDER BY id DESC LIMIT 1').fetchone();c.close();self.assertEqual(row['status'],'running')
        with patch.object(discovery,'safe_fetch',return_value=(b'api.example.test','text/plain','https://feed.example.test/')):
            result=discovery.process_browser_queue(1)
        self.assertEqual(result[0]['status'],'ready')

    def test_untrusted_hostnames_are_normalized_before_approval(self):
        from app.services import discovery
        from app.services.deployment import generate_config
        har={'log':{'entries':[{'request':{'url':'https://bad_host.example/'}},{'request':{'url':'https://API.Example.TEST/'}}]}}
        items,_,_=discovery.discover_har(json.dumps(har).encode())
        self.assertEqual([x['destination'] for x in items],['api.example.test'])
        aid=self._app();rid=discovery.create_har_run(aid,'portal.example.com',json.dumps(har).encode(),'admin')
        c=self.connect();cid=c.execute('SELECT id FROM discovery_candidates WHERE run_id=?',(rid,)).fetchone()[0];c.execute("UPDATE discovery_candidates SET destination='bad_host.example' WHERE id=?",(cid,));before=c.execute('SELECT COUNT(*) FROM rules').fetchone()[0];c.commit();c.close()
        with self.assertRaises(ValueError):discovery.approve_run(rid,[cid],'admin')
        c=self.connect();self.assertEqual(c.execute('SELECT COUNT(*) FROM rules').fetchone()[0],before);c.close();generate_config()

    def test_official_hostname_extraction_rejects_long_tokens_without_suffix_grants(self):
        from app.services import discovery
        raw=('a.'*2000+'1 api.example.test *.cdn.example.test 192.0.2.5').encode()
        with patch.object(discovery,'safe_fetch',return_value=(raw,'text/plain','https://feed.example.test/')):items,_,_=discovery.discover_official_url('https://feed.example.test/')
        domains={x['destination'] for x in items if x['endpoint_type']=='domain'}
        self.assertEqual(domains,{'api.example.test','*.cdn.example.test'})

    def test_http_response_deadline_closes_incomplete_dummy_response(self):
        from app.services import discovery
        released=threading.Event()
        class DummyResponse:
            status=200
            def read(self,size):
                if not released.wait(2):raise RuntimeError('deadline did not close fixture')
                return b''
            def getheader(self,name):return 'text/plain'
        class DummyConnection:
            def __init__(self,*a,**kw):self.sock=SimpleNamespace(shutdown=lambda how:released.set())
            def request(self,*a,**kw):pass
            def getresponse(self):return DummyResponse()
            def close(self):released.set()
        with patch.object(discovery,'_public_addresses',return_value=['8.8.8.8']),patch.object(discovery,'_PinnedHTTPSConnection',DummyConnection):
            with self.assertRaisesRegex(ValueError,'time limit'):discovery._fetch_once('https://fixture.example.test/',deadline=time.monotonic()+.1)
        self.assertTrue(released.is_set())

    def test_dependency_review_waits_for_policy_writer_and_protects_system_app(self):
        from app.services.policy_lock import policy_edit_lock
        from app.services.access_model import get_application
        aid=self.protected_app();c=self.connect();cid=c.execute("INSERT INTO application_dependency_candidates(application_id,destination,protocol,confidence_score,status) VALUES(?,'api.example.test','HTTPS',90,'pending')",(aid,)).lastrowid;c.commit();c.close()
        client,csrf=self.client_for('operator')
        with client,ThreadPoolExecutor(max_workers=1) as pool:
            self.assertEqual(client.post(f'/intelligence/dependency-candidates/{cid}/review',data={'action':'approve','csrf_token':csrf}).status_code,403)
            with policy_edit_lock():
                # Submit while lock is held; worker must not enter the handler.
                future=pool.submit(client.post,f'/intelligence/dependency-candidates/{cid}/review',data={'action':'ignore','csrf_token':csrf})
                time.sleep(.1);self.assertFalse(future.done())
            self.assertEqual(future.result(timeout=5).status_code,403)

    def test_export_is_private_during_write_and_replaces_output_link(self):
        from tools.export_policy_archive import export_archive
        import tarfile,stat
        base=Path(self.tmp.name);stage=base/'stage';stage.mkdir();shared=base/'shared';shared.mkdir()
        for name in ('swg.db','metadata.txt','SHA256SUMS.txt'):(stage/name).write_text('dummy-'+name)
        protected=base/'unrelated';protected.write_text('unchanged');output=shared/'state.tar.gz';output.symlink_to(protected)
        original=tarfile.TarFile.add;modes=[]
        def add(archive,*args,**kw):modes.append(stat.S_IMODE(os.fstat(archive.fileobj.fileno()).st_mode));return original(archive,*args,**kw)
        oldmask=os.umask(0o022)
        try:
            with patch.object(tarfile.TarFile,'add',add):export_archive(stage,output)
        finally:os.umask(oldmask)
        self.assertEqual(modes,[0o600]*3);self.assertFalse(output.is_symlink());self.assertEqual(output.stat().st_mode&0o777,0o600);self.assertEqual(protected.read_text(),'unchanged')
        with tarfile.open(output) as archive:self.assertEqual(set(archive.getnames()),{'swg.db','metadata.txt','SHA256SUMS.txt'})

    def test_operator_cannot_change_protected_profile_membership_indirectly(self):
        from app.services.access_model import create_policy_group,update_application,get_application
        from app.services.access_choice import save_discovery_access
        from app.services.rules import create_rule
        aid=self._app();gid=create_policy_group('Protected profile','',[],[],[1],'admin')
        c=self.connect();c.execute('UPDATE policy_groups SET system_managed=1 WHERE id=?',(gid,));c.commit();c.close()
        with self.assertRaises(ValueError):save_discovery_access(aid,'profiles',[],[gid],'operator')
        with self.assertRaises(ValueError):create_rule('domain','new.example.test','HTTPS',[],'operator','Dummy fixture',policy_group_ids=[gid])
        app=get_application(aid)
        with self.assertRaises(ValueError):update_application(aid,app['name'],'Dummy','','portal.example.com','manual','',False,[],'operator',[gid])
        c=self.connect();self.assertEqual(c.execute('SELECT COUNT(*) FROM policy_group_applications WHERE group_id=?',(gid,)).fetchone()[0],0);c.close()

    def test_upgrade_cutover_backup_preserves_last_moment_credentials(self):
        import shutil
        script=(Path(__file__).resolve().parents[1]/'deploy/upgrade.sh').read_text()
        marker='python3 - "$PDB" "$BACKUP/cutover.db" <<\'PY\'\n'
        self.assertGreater(script.index(marker),script.index('Writer still active:'))
        snapshot=script.split(marker,1)[1].split('\nPY',1)[0]
        clear=script.split('python3 - "$PDB" <<\'PY\'\n',1)[1].split('\nPY',1)[0]
        c=self.connect();c.execute("INSERT INTO sessions(user_id,token_hash,csrf_token,created_at,expires_at,last_seen_at) VALUES(1,'dummy-session','dummy','2026-11-14T00:00:00+00:00','2099-01-01T00:00:00+00:00','2026-11-14T00:00:00+00:00')");c.commit();c.close()
        # Changes after the historical early backup must survive a failed upgrade.
        early=Path(self.tmp.name)/'early.db';shutil.copyfile(self.path,early)
        c=self.connect();c.execute("UPDATE users SET password_hash='dummy-reset-before-cutover' WHERE id=1");c.execute("UPDATE sessions SET revoked_at='2026-11-14T12:00:00+00:00'");c.commit();c.close()
        cutover=Path(self.tmp.name)/'cutover.db';subprocess.run([sys.executable,'-c',snapshot,str(self.path),str(cutover)],check=True)
        rolled=Path(self.tmp.name)/'rolled.db';shutil.copyfile(cutover,rolled);subprocess.run([sys.executable,'-c',clear,str(rolled)],check=True)
        with sqlite3.connect(rolled) as c:
            self.assertEqual(c.execute('SELECT password_hash FROM users WHERE id=1').fetchone()[0],'dummy-reset-before-cutover')
            self.assertEqual(c.execute('SELECT COUNT(*) FROM sessions').fetchone()[0],0)

    def test_restore_keeps_target_pac_in_generated_windows_and_edge_downloads(self):
        from tools.prepare_restored_policy import prepare_restored_policy
        from app.services.connectivity import windows_package
        from app.services.endpoint_config import pac_address
        import app.db as db
        root=Path(__file__).resolve().parents[1];staged=Path(self.tmp.name)/'source.db'
        subprocess.run([sys.executable,str(root/'tools/migrate.py'),'--db',str(staged),'--root',str(root)],check=True,stdout=subprocess.DEVNULL)
        c=self.connect();c.execute("INSERT INTO settings(key,value) VALUES('pac_endpoint',?)",(json.dumps({'scheme':'https','host':'target.example.test'}),));c.commit();c.close()
        with sqlite3.connect(staged) as c:
            c.execute("INSERT INTO settings(key,value) VALUES('pac_endpoint',?)",(json.dumps({'scheme':'http','host':'source.example.test'}),))
            c.execute("INSERT INTO users(username,password_hash,role) VALUES('admin','unused-fixture-hash','admin')")
        prepare_restored_policy(self.path,Path(self.tmp.name)/'backup.db',staged)
        with patch.object(db,'DB_PATH',staged):
            self.assertEqual(pac_address(),'https://target.example.test/proxy.pac')
            with zipfile.ZipFile(io.BytesIO(windows_package())) as archive:self.assertIn(pac_address(),archive.read('Install-Managed-Proxy.ps1').decode())
            client,_=self.client_for('admin')
            with client:self.assertEqual(client.get('/connection/edge-policy.json').json()['ProxyPacUrl'],pac_address())
        # An absent target endpoint must also remove the imported source endpoint.
        c=self.connect();c.execute("DELETE FROM settings WHERE key='pac_endpoint'");c.commit();c.close()
        prepare_restored_policy(self.path,Path(self.tmp.name)/'backup2.db',staged)
        with patch.object(db,'DB_PATH',staged):self.assertNotIn('source.example.test',pac_address())

    def test_queue_migration_preserves_browser_jobs_and_excludes_sync_producers(self):
        import shutil
        root=Path(__file__).resolve().parents[1];legacy=Path(self.tmp.name)/'legacy';(legacy/'migrations').mkdir(parents=True)
        for path in (root/'migrations').glob('*.sql'):
            if path.name[:3]<'018':shutil.copyfile(path,legacy/'migrations'/path.name)
        old_db=legacy/'old.db';subprocess.run([sys.executable,str(root/'tools/migrate.py'),'--db',str(old_db),'--root',str(legacy)],check=True,stdout=subprocess.DEVNULL)
        with sqlite3.connect(old_db) as c:
            c.execute("INSERT INTO discovery_runs(method,status,started_by) VALUES('browser_auto','running','admin')")
            c.execute("INSERT INTO discovery_runs(method,status,started_by) VALUES('official_url','running','system-sync')")
        subprocess.run([sys.executable,str(root/'tools/migrate.py'),'--db',str(old_db),'--root',str(root)],check=True,stdout=subprocess.DEVNULL)
        with sqlite3.connect(old_db) as c:self.assertEqual(c.execute('SELECT method,queued FROM discovery_runs ORDER BY id').fetchall(),[('browser_auto',1),('official_url',0)])
        from app.services import discovery
        c=self.connect();c.execute("INSERT INTO discovery_runs(method,status,started_by,queued) VALUES('official_url','running','system-sync',0)");c.commit();c.close()
        with patch.object(discovery,'_execute_run') as execute:self.assertEqual(discovery.process_browser_queue(1),[]);execute.assert_not_called()


if __name__=='__main__':
    import tempfile
    with tempfile.TemporaryDirectory(prefix='swg-v3127-') as td:
        os.environ.update(SWG_DB_PATH=td+'/initial.db',SWG_DATA_ROOT=td,SWG_LIVE_MANAGED_CONF=td+'/live.conf',SWG_MODE='production',SWG_PROXY_IP='127.0.0.1',SWG_FQDN='localhost')
        root=Path(__file__).resolve().parents[1]
        subprocess.run([sys.executable,str(root/'tools/migrate.py'),'--db',os.environ['SWG_DB_PATH'],'--root',str(root)],check=True)
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(SecurityCorrections))
        if not result.wasSuccessful():sys.exit(1)
