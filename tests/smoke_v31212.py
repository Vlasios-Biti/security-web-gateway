#!/usr/bin/env python3
"""New applications stay visible before scan or traffic candidates exist."""
import os,subprocess,sys,tempfile,unittest
from pathlib import Path
import smoke_v31211 as prior
from unittest.mock import patch


class CandidateVisibility(prior.IntegrationsAndCorrections):
    def test_panel_certificate_is_identified_and_warning_state_is_not_green(self):
        client,_=self.client_for('admin')
        with client:
            health=client.get('/system/health').context['health']
            health={**health,'certificate':{'ok':True,'state':'warning','days_remaining':19.7,'expires_at':'2026-12-01T00:00:00+00:00'}}
            with patch('app.routers.system.cached_system_health',return_value=health):response=client.get('/system/health')
            self.assertIn('Panel HTTPS certificate',response.text)
            self.assertRegex(response.text,r'Panel HTTPS certificate</a></span><b class="status-pill warning">19.7 days')
            self.assertIn('does not enable inspection',client.get('/connection').text)

    def test_new_application_with_no_candidates_is_visible_immediately(self):
        from app.services.access_model import create_application
        aid=create_application('Newly added portal','Test','','new.example.test','manual','',False,'admin')
        client,_=self.client_for('admin')
        with client:
            response=client.get('/intelligence/dependency-candidates')
            self.assertEqual(response.status_code,200)
            self.assertIn(aid,[a['id'] for a in response.context['applications']])
            selected=client.get('/intelligence/dependency-candidates',params={'application_id':aid})
            self.assertEqual(selected.context['total'],0);self.assertIn('No run recorded',selected.text)
            self.assertIn(f'/applications/{aid}',selected.text);self.assertIn('listed here immediately',selected.text)
            self.assertIn('Traffic-based suggestions from blocked requests',selected.text)

    def test_selected_application_shows_discovery_without_inventing_traffic_candidates(self):
        aid=self._app();c=self.connect()
        run=c.execute("INSERT INTO discovery_runs(application_id,method,status,started_by) VALUES(?,'browser_auto','running','admin')",(aid,)).lastrowid;c.commit();c.close()
        client,_=self.client_for('admin')
        with client:
            response=client.get('/intelligence/dependency-candidates',params={'application_id':aid})
            self.assertEqual(response.context['total'],0);self.assertEqual(response.context['selected_application']['dependency_count'],1)
            self.assertIn('Queued / running',response.text)
            c=self.connect();c.execute("UPDATE discovery_runs SET status='approved' WHERE id=?",(run,));c.commit();c.close()
            response=client.get('/intelligence/dependency-candidates',params={'application_id':aid})
            self.assertIn('Completed',response.text);self.assertEqual(response.context['total'],0)


if __name__=='__main__':
    root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix='swg-v31212-') as td:
        os.environ.update(SWG_DB_PATH=td+'/initial.db',SWG_DATA_ROOT=td,SWG_LIVE_MANAGED_CONF=td+'/live.conf',SWG_MODE='production',SWG_PROXY_IP='127.0.0.1',SWG_FQDN='localhost')
        subprocess.run([sys.executable,str(root/'tools/migrate.py'),'--db',os.environ['SWG_DB_PATH'],'--root',str(root)],check=True)
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CandidateVisibility))
        if not result.wasSuccessful():sys.exit(1)
