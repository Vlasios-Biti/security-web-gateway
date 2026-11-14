#!/usr/bin/env python3
"""PAC delivery parity, TLS renewal rollback and independent Slack preferences."""
import base64
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import zipfile
import smoke_v3121 as prior


class EndpointAlertWorkflows(prior.CombinedProfileWorkflows):
    def test_pac_address_is_shared_by_gui_package_and_edge(self):
        from app.services.endpoint_config import pac_address, validate_endpoint
        from app.services.connectivity import windows_package
        self.assertEqual(pac_address(),'http://127.0.0.1:8081/proxy.pac')
        for host in ('https://host','x";bad','host/path','host:443','-invalid',''):
            with self.assertRaises(ValueError):validate_endpoint('https',host)
        client,csrf=self.client_for('admin')
        with client:
            denied=client.post('/connection/endpoint',data={'csrf_token':'bad','scheme':'https','host':'gateway.example.com'})
            self.assertEqual(denied.status_code,403)
            response=client.post('/connection/endpoint',data={'csrf_token':csrf,'scheme':'https','host':'gateway.example.com'},follow_redirects=False)
            self.assertEqual(response.status_code,303)
            self.assertIn('https://gateway.example.com/proxy.pac',client.get('/connection').text)
            self.assertEqual(client.get('/connection/edge-policy.json').json()['ProxyPacUrl'],pac_address())
        with zipfile.ZipFile(io.BytesIO(windows_package())) as archive:
            for name in ('Install-Managed-Proxy.ps1','Build-For-This-Gateway.ps1','START-HERE.txt'):
                self.assertIn(pac_address(),archive.read(name).decode())
        client,csrf=self.client_for('operator')
        with client:self.assertEqual(client.post('/connection/endpoint',data={'csrf_token':csrf,'host':'changed.example.com'}).status_code,403)

    def test_slack_filters_are_independent_and_repeat_and_recovery_are_optional(self):
        n=self.notification
        cfg=self.config(confirmation_samples=1,recovery_samples=1,repeat_minutes=1,slack_topics=['services'],slack_minimum_severity='critical',slack_repeat_minutes=0,slack_recovery=False,slack_format='compact')
        found={'disk':{'severity':'critical','title':'Disk high','detail':'Disk detail'},'proxy_listener':{'severity':'critical','title':'Proxy down','detail':'Proxy detail'},'dns':{'severity':'warning','title':'DNS slow','detail':'DNS detail'}}
        n.update_incidents(found,cfg,100)
        with patch.object(n,'send_channel') as send:
            self.assertEqual(n.deliver(cfg,100)['sent'],2)
            slack=[call.args[2] for call in send.call_args_list if call.args[0]=='slack'][0]
            self.assertIn('Proxy down',slack);self.assertNotIn('Proxy detail',slack);self.assertNotIn('Disk high',slack);self.assertNotIn('DNS slow',slack)
            send.reset_mock();self.assertEqual(n.deliver(cfg,161)['sent'],1);self.assertEqual(send.call_args.args[0],'email')
            n.update_incidents({},cfg,200);send.reset_mock();self.assertEqual(n.deliver(cfg,200)['sent'],1);self.assertEqual(send.call_args.args[0],'email')

    def test_slack_empty_categories_severity_mentions_and_validation(self):
        n=self.notification
        cfg=self.config(confirmation_samples=1,slack_topics=[],slack_mentions=['U012ABC','S012ABC'])
        n.update_incidents({'proxy_listener':{'severity':'critical','title':'Proxy down','detail':'Down'}},cfg,100)
        with patch.object(n,'send_channel') as send:
            n.deliver(cfg,100);self.assertEqual(send.call_count,1);self.assertEqual(send.call_args.args[0],'email')
        self.assertNotIn('<!everyone>',n.slack_payload(cfg,'<!everyone>')['text'])
        payload=n.slack_payload(cfg,'ALERT [CRITICAL] Proxy down')
        self.assertEqual(payload['blocks'][0]['text']['text'],'<@U012ABC> <!subteam^S012ABC>')
        for body in ('RECOVERED [CRITICAL] Proxy up','Administrator-requested channel test.','ALERT [WARNING] Disk high'):
            self.assertTrue(all(b['text']['type']=='plain_text' for b in n.slack_payload(cfg,body)['blocks']))
        for changes in ({'slack_topics':['bogus']},{'slack_mentions':['<!everyone>']},{'slack_repeat_minutes':-2},{'slack_format':'html'}):
            with self.assertRaises(ValueError):self.config(**changes)
        cfg=self.config(minimum_severity='critical',slack_minimum_severity='warning')
        self.assertEqual(n.channel_preferences('email',cfg)[0],'critical');self.assertEqual(n.channel_preferences('slack',cfg)[0],'warning')

    def test_slack_form_persists_empty_selection_and_masks_secret(self):
        cfg=self.config();self.notification.PATH.write_text(json.dumps(cfg))
        client,csrf=self.client_for('admin')
        data={**cfg,'csrf_token':csrf,'slack_options_present':'true','slack_topics':['__none__'],'slack_mentions':'U012ABC, S012ABC','slack_destination':'#urgent','recipients':'it@example.com','snmp_managers':'','slack_webhook':''}
        with client,patch('app.services.deployment.helper_request',return_value={'ok':True}) as helper:
            response=client.post('/system/notifications',data=data,follow_redirects=False)
            self.assertNotIn('error=',response.headers['location'])
            value=helper.call_args.kwargs['settings'];self.assertEqual(value['slack_topics'],[]);self.assertEqual(value['slack_mentions'],['U012ABC','S012ABC'])
            page=client.get('/system/notifications');self.assertNotIn('fixture-secret',page.text)

    def test_certificate_endpoint_role_csrf_and_size(self):
        client,csrf=self.client_for('admin')
        with client,patch('app.services.deployment.helper_request') as helper:
            files={'certificate':('chain.pem',b'fake'),'private_key':('key.pem',b'fake')}
            self.assertEqual(client.post('/connection/certificate',data={'csrf_token':'bad'},files=files).status_code,403)
            response=client.post('/connection/certificate',data={'csrf_token':csrf},files={**files,'private_key':('key.pem',b'x'*20001)},follow_redirects=False)
            self.assertIn('error=',response.headers['location']);helper.assert_not_called()
        client,csrf=self.client_for('viewer')
        with client:self.assertEqual(client.post('/connection/certificate',data={'csrf_token':csrf},files=files).status_code,403)

    def test_https_pac_nginx_upgrade_is_idempotent(self):
        from tools.enable_https_pac import patch as patch_nginx
        source=(Path(__file__).resolve().parents[1]/'deploy/templates/nginx.conf.tpl').read_text()
        existing=source[:source.index('    # SWG HTTPS PAC:')]+source[source.index('    location / {'):]
        existing=existing.replace('__BIND_IP__','127.0.0.1')
        updated=patch_nginx(existing)
        self.assertEqual(updated,patch_nginx(updated));self.assertEqual(updated.count('location = /proxy.pac'),2)
        with self.assertRaises(ValueError):patch_nginx('server { listen 8443; }')

    def test_tls_matching_host_and_key_and_reload_rollback(self):
        root=Path(self.tmp.name);spec=importlib.util.spec_from_file_location('tls_fixture',Path(__file__).resolve().parents[1]/'privileged/tls_install.py')
        tls=importlib.util.module_from_spec(spec);spec.loader.exec_module(tls)
        tls.TLS=root/'tls';tls.TLS.mkdir();tls.NGINX=root/'nginx';tls.ENV=root/'production.env'
        cert=tls.TLS/'management.crt';key=tls.TLS/'management.key'
        tls.NGINX.write_text(f'ssl_certificate {cert};\nssl_certificate_key {key};\n');tls.ENV.write_text('SWG_FQDN=localhost\n')
        newcert=root/'new.crt';newkey=root/'new.key'
        subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',str(newkey),'-out',str(newcert)],capture_output=True,check=True)
        payload={'certificate':base64.b64encode(newcert.read_bytes()).decode(),'private_key':base64.b64encode(newkey.read_bytes()).decode(),'hostname':'localhost'}
        cert.write_bytes(b'old-cert');key.write_bytes(b'old-key');key.chmod(0o600)
        original=tls.command
        def simulate(args):
            return original(args) if args[0]=='/usr/bin/openssl' else subprocess.CompletedProcess(args,0)
        with patch.object(tls,'command',side_effect=simulate):self.assertTrue(tls.install(payload)['ok'])
        self.assertEqual(cert.read_bytes(),newcert.read_bytes());self.assertEqual(key.stat().st_mode & 0o777,0o600)
        with patch.object(tls,'command',side_effect=simulate):
            with self.assertRaises(ValueError):tls.install({**payload,'hostname':'wrong.example.com'})
            with self.assertRaises(ValueError):tls.install({**payload,'private_key':base64.b64encode(b'invalid key').decode()})
        cert.write_bytes(b'previous-cert');key.write_bytes(b'previous-key')
        def fail_reload(args):
            if args[:2]==['/usr/bin/systemctl','reload']:return subprocess.CompletedProcess(args,1)
            return simulate(args)
        with patch.object(tls,'command',side_effect=fail_reload):
            with self.assertRaises(ValueError):tls.install(payload)
        self.assertEqual(cert.read_bytes(),b'previous-cert');self.assertEqual(key.read_bytes(),b'previous-key')


if __name__=='__main__':
    h=prior.prior.prior.health
    with h.tempfile.TemporaryDirectory(prefix='swg-v3123-') as td:
        h.os.environ.update(SWG_DB_PATH=str(h.Path(td)/'initial.db'),SWG_DATA_ROOT=td,SWG_LIVE_MANAGED_CONF=str(h.Path(td)/'live.conf'),SWG_MODE='production',SWG_PROXY_IP='127.0.0.1',SWG_FQDN='localhost')
        h.subprocess.check_call([h.sys.executable,str(h.ROOT/'tools/migrate.py'),'--db',h.os.environ['SWG_DB_PATH'],'--root',str(h.ROOT)])
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(EndpointAlertWorkflows))
        if not result.wasSuccessful():h.sys.exit(1)
