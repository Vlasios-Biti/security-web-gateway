#!/usr/bin/env python3
"""System review regressions: policy/PAC diagnosis and consistent health alerts."""
import json
import shutil
import subprocess
import unittest
from unittest.mock import patch
import smoke_v3123 as prior


class ReviewedWorkflows(prior.EndpointAlertWorkflows):
    def test_simulator_honors_squid_ports_methods_and_literal_ips(self):
        from app.services.rules import create_rule
        from app.services.policy_explain import explain_policy
        create_rule('domain','portal.example.com','BOTH',[1],'admin','Test access')
        create_rule('ip','203.0.113.15','HTTPS',[1],'admin','Test IP')
        for port,method,decision in ((443,'CONNECT','ALLOW'),(80,'GET','ALLOW'),(8443,'CONNECT','DENY'),(80,'CONNECT','DENY'),(443,'GET','DENY')):
            result=explain_policy('10.20.0.10','portal.example.com',port,method)
            self.assertEqual(result['decision'],decision,(port,method,result))
        self.assertEqual(explain_policy('10.20.0.10','203.0.113.15')['decision'],'ALLOW')
        self.assertEqual(explain_policy('127.0.0.1','portal.example.com')['decision'],'ALLOW')
        result=explain_policy('10.20.0.10','https://portal.example.com/path?q=test')
        self.assertEqual(result['decision'],'ALLOW');self.assertEqual(result['destination'],'portal.example.com')
        self.assertEqual(explain_policy('10.20.0.10','http://portal.example.com')['method'],'GET')
        for destination in ('https://user:secret@portal.example.com','file:///etc/passwd','*.example.com',''):
            with self.assertRaises(ValueError):explain_policy('10.20.0.10',destination)

    def test_simulator_legacy_overlapping_networks_use_all_allow_scopes(self):
        from app.services.rules import create_rule
        from app.services.policy_explain import explain_policy
        create_rule('domain','portal.example.com','HTTPS',[1],'admin','Test access')
        c=self.connect();c.execute("INSERT INTO networks(name,cidr,proxy_enabled,enabled,pending,created_by) VALUES('Legacy narrower scope','10.20.0.0/25',1,1,0,'admin')");c.commit();c.close()
        result=explain_policy('10.20.0.10','portal.example.com')
        self.assertEqual(result['decision'],'ALLOW');self.assertEqual(len(result['networks']),2)
        self.assertEqual(result['network']['name'],'Legacy narrower scope')
        self.assertTrue(result['pending_changes']);self.assertEqual(result['basis'],'saved_policy')

    def test_pac_diagnosis_matches_actual_generated_javascript(self):
        from app.services.pac_policy import explain_routing,render_pac
        cfg={'fail_open':True,'internal_direct':True,'bypass':['*.direct.example.com','exact.example.com','203.0.113.0/24']}
        cases=[('printer','','DIRECT'),('192.168.1.1','','DIRECT'),('direct.example.com','','DIRECT'),('a.direct.example.com','','DIRECT'),('exact.example.com','','DIRECT'),('203.0.113.7','','DIRECT'),('external.example.com','203.0.113.8','DIRECT'),('external.example.com','198.51.100.3','PROXY')]
        for host,ip,expected in cases:self.assertEqual(explain_routing(cfg,host,ip)['route'],expected,(host,ip))
        self.assertEqual(explain_routing(cfg,'unresolved.example.com')['route'],'DNS_REQUIRED')
        self.assertEqual(explain_routing({**cfg,'bypass':[]},'public.example.com')['route'],'PROXY')
        if shutil.which('node'):
            root=prior.prior.prior.prior.health.ROOT
            subprocess.run(['node',str(root/'tests/routing_preview_contract.cjs')],input=json.dumps({'pac':render_pac(cfg,'127.0.0.1',3128),'cases':cases}),text=True,check=True)

    def test_simulator_retains_inputs_and_labels_saved_vs_direct_policy(self):
        client,csrf=self.client_for('admin')
        with client:
            page=client.post('/intelligence/simulator',data={'client_ip':'10.20.0.10','destination':'http://printer'})
            self.assertEqual(page.status_code,200);self.assertIn('PAC route: DIRECT',page.text);self.assertIn('saved policy',page.text);self.assertIn('value="10.20.0.10"',page.text)
            bad=client.post('/intelligence/simulator',data={'client_ip':'wrong-ip','destination':'portal.example.com'})
            self.assertEqual(bad.status_code,400);self.assertIn('value="wrong-ip"',bad.text);self.assertIn('value="portal.example.com"',bad.text)

    def test_health_gui_uses_notification_thresholds_without_enabling_delivery(self):
        import app.services.system as system
        health=system.cached_system_health()
        health.update(squid_status='active',nginx_status='active',app_status='active',port_ok=True,cache_stale=False,dns=[],workers={},ntp={'ok':True,'state':'synchronized'},certificate={'state':'healthy','ok':True,'days_remaining':100,'expires_at':'future'},disk={**health['disk'],'percent':90,'free_gb':20},memory={**health['memory'],'percent':90})
        cfg=self.config(enabled=False,disk_percent=95,memory_percent=95,backup_age_hours=0)
        client,_=self.client_for('admin')
        with client,patch('app.routers.system.cached_system_health',return_value=health),patch('app.routers.system.latest_performance',return_value=None),patch('app.routers.system.drift_status',return_value={'state':'clean'}),patch('app.routers.system.notification_settings',return_value=cfg):
            page=client.get('/system/health');self.assertEqual(page.status_code,200)
            self.assertNotIn('Disk utilization is high',page.text);self.assertNotIn('Memory utilization is high',page.text)
            cfg['disk_percent']=85;cfg['memory_percent']=85
            page=client.get('/system/health');self.assertIn('Disk utilization is high',page.text);self.assertIn('Memory utilization is high',page.text)

    def test_client_names_resolve_only_in_bounded_background_worker(self):
        import app.services.traffic as traffic
        import time
        c=self.connect()
        for index in range(1,10):
            c.execute("INSERT INTO telemetry_events(epoch,event_time,client_ip,decision,event_hash) VALUES(?,CURRENT_TIMESTAMP,?,'ALLOW',?)",(time.time(),'10.20.0.'+str(index),'ptr-fixture-'+str(index)))
        c.commit();c.close()
        with patch('socket.gethostbyaddr',side_effect=AssertionError('DNS must not run during GUI reads')):
            self.assertTrue(all(not row['hostname'] for row in traffic.clients()))
            with patch.object(traffic.subprocess,'run',return_value=subprocess.CompletedProcess([],0,stdout='10.20.0.1 workstation.office.internal\n')) as query:
                result=traffic.refresh_client_hostnames(1000)
                self.assertEqual(result['checked'],8);self.assertEqual(query.call_count,8)
                self.assertEqual(query.call_args.kwargs['timeout'],.5)
            self.assertEqual(sum(bool(row['hostname']) for row in traffic.clients()),8)
            with patch.object(traffic.subprocess,'run',side_effect=subprocess.TimeoutExpired('getent',.5)) as query:
                self.assertEqual(traffic.refresh_client_hostnames()['checked'],1)
                self.assertEqual(traffic.refresh_client_hostnames()['checked'],0)
                self.assertEqual(query.call_count,1)

    def test_dashboard_health_api_uses_cached_sample(self):
        from app.services.system import cached_system_health
        health=cached_system_health();client,_=self.client_for('viewer')
        with client,patch('app.routers.api.cached_system_health',return_value=health) as sample:
            response=client.get('/api/dashboard/health')
            self.assertEqual(response.status_code,200);sample.assert_called_once()
            self.assertEqual(response.json()['cache_stale'],health['cache_stale'])
            self.assertEqual(response.json()['squid'],health['squid_status'])

    def test_csv_exports_escape_formula_text_and_xlsx_remains_text(self):
        import csv,io,zipfile
        from app.security import csv_cell
        from app.services.traffic import export_csv,export_xlsx
        from app.routers.bulk import _export
        for text in ('=1+1',' +SUM(1,2)','@test','-formula','\t=1','＝1+1'):
            self.assertTrue(csv_cell(text).startswith("'"),text)
        self.assertEqual(csv_cell(123),123);self.assertEqual(csv_cell('portal.example.com'),'portal.example.com')
        with patch('app.services.traffic._export_rows',return_value=[{'network_name':'=1+1','bytes':123}]):
            rows=list(csv.reader(io.StringIO(export_csv({}).decode('utf-8-sig'))))
            self.assertEqual(rows[1][2],"'=1+1")
            with zipfile.ZipFile(io.BytesIO(export_xlsx({}))) as archive:
                xml=archive.read('xl/worksheets/sheet1.xml').decode()
                self.assertIn('=1+1',xml);self.assertNotIn('<f>',xml)
        rule={'destination':'portal.example.com','protocol':'HTTPS','scope_mode':'selected','status':'active','reason':'=1+1','policy_groups':[],'networks':[]}
        with patch('app.routers.bulk.list_rules',return_value=[rule]):
            self.assertEqual(list(csv.reader(io.StringIO(_export('domain'))))[1][7],"'=1+1")

    def test_overview_does_not_claim_healthy_with_stale_samples(self):
        from app.services.system import cached_system_health
        health=cached_system_health();health.update(squid_status='active',nginx_status='active',app_status='active',port_ok=True,cache_stale=True)
        client,_=self.client_for('admin')
        with client,patch('app.routers.overview.cached_system_health',return_value=health),patch('app.routers.overview.drift_status',return_value={'state':'clean'}):
            page=client.get('/');self.assertEqual(page.status_code,200)
            self.assertIn('Gateway needs attention',page.text);self.assertIn('Health sample is stale',page.text)

    def test_expiry_alert_category_and_no_empty_admin_menu_for_viewer(self):
        from app.services.notification_config import event_topic
        self.assertEqual(event_topic('expiry'),'policy')
        client,_=self.client_for('viewer')
        with client:
            page=client.get('/policies/groups');self.assertEqual(page.status_code,200)
            self.assertNotIn('<span>System</span>',page.text)
            self.assertEqual(client.get('/system/notifications').status_code,403)


if __name__=='__main__':
    h=prior.prior.prior.prior.health
    with h.tempfile.TemporaryDirectory(prefix='swg-v3124-') as td:
        h.os.environ.update(SWG_DB_PATH=str(h.Path(td)/'initial.db'),SWG_DATA_ROOT=td,SWG_LIVE_MANAGED_CONF=str(h.Path(td)/'live.conf'),SWG_MODE='production',SWG_PROXY_IP='127.0.0.1',SWG_FQDN='localhost')
        h.subprocess.check_call([h.sys.executable,str(h.ROOT/'tools/migrate.py'),'--db',h.os.environ['SWG_DB_PATH'],'--root',str(h.ROOT)])
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ReviewedWorkflows))
        if not result.wasSuccessful():h.sys.exit(1)
