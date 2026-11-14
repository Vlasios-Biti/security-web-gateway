#!/usr/bin/env python3
"""Health delivery, secrets, frozen publication, expiry and portable restores."""
import io
import json
import os
from pathlib import Path
import smtplib
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch
from smoke_v3100 import Workflows,ROOT


class HealthWorkflows(Workflows):
    def setUp(self):
        super().setUp()
        import app.services.notifications as notification
        self.notification=notification
        self.path_patch=patch.object(notification,'PATH',Path(self.tmp.name)/'notifications.json');self.path_patch.start()

    def tearDown(self):
        self.path_patch.stop();super().tearDown()

    def config(self,**changes):
        from app.services.notification_config import validate_settings
        return validate_settings({'enabled':True,'email_enabled':True,'slack_enabled':True,'smtp_host':'smtp.example.com','smtp_port':587,
          'smtp_tls':'starttls','smtp_username':'test','smtp_password':'fixture-secret','sender':'gateway@example.com','recipients':['it@example.com'],
          'slack_webhook':'https://hooks.slack.com/services/TTEST/BTEST/fixture-secret',**changes})

    def test_config_masks_and_retains_credentials(self):
        from app.services.notification_config import validate_settings,public_settings
        cfg=self.config();masked=public_settings(cfg)
        self.assertNotIn('fixture-secret',json.dumps(masked))
        next_cfg=validate_settings({**cfg,'smtp_password':'','slack_webhook':''},cfg)
        self.assertEqual(next_cfg['smtp_password'],'fixture-secret')
        self.assertEqual(next_cfg['slack_webhook'],cfg['slack_webhook'])
        for changes in ({'smtp_tls':'none'},{'slack_webhook':'https://evil.example/services/a/b/c'}, {'recipients':['x\r\nBcc:bad@example.com']}, {'confirmation_samples':0}):
            with self.assertRaises(ValueError):self.config(**changes)

    def test_notification_dedup_and_confirmed_recovery(self):
        n=self.notification;cfg=self.config();found={'disk':{'severity':'warning','title':'Disk high','detail':'90% used'}}
        with patch.object(n,'send_channel') as send:
            n.update_incidents(found,cfg,100);self.assertEqual(n.deliver(cfg,100)['sent'],0)
            n.update_incidents(found,cfg,160);self.assertEqual(n.deliver(cfg,160)['sent'],2)
            self.assertEqual(n.deliver(cfg,200)['sent'],0)
            n.update_incidents({},cfg,220);self.assertEqual(n.deliver(cfg,220)['sent'],0)
            n.update_incidents({},cfg,280);self.assertEqual(n.deliver(cfg,280)['sent'],2)
            self.assertEqual(n.deliver(cfg,340)['sent'],0)
            self.assertEqual(send.call_count,4)
            self.assertIn('RECOVERED',send.call_args.args[2])

    def test_delivery_failure_does_not_repeat_successful_channel(self):
        n=self.notification;cfg=self.config(confirmation_samples=1)
        n.update_incidents({'proxy':{'severity':'critical','title':'Proxy down','detail':'Unavailable'}},cfg,100)
        def fail_email(channel,cfg,body):
            if channel=='email':raise smtplib.SMTPAuthenticationError(535,b'fixture-secret')
        with patch.object(n,'send_channel',side_effect=fail_email):self.assertEqual(n.deliver(cfg,100),{'sent':1,'failed':1})
        self.assertNotIn('fixture-secret',json.dumps(n.history()))
        with patch.object(n,'send_channel') as send:
            self.assertEqual(n.deliver(cfg,120)['sent'],0)
            self.assertEqual(n.deliver(cfg,221)['sent'],1)
            self.assertEqual(send.call_args.args[0],'email');self.assertEqual(send.call_count,1)

    def test_disabled_notifications_and_unreported_recovery_do_not_send(self):
        n=self.notification;cfg=self.config(confirmation_samples=1,recovery_samples=1)
        n.update_incidents({'memory':{'severity':'warning','title':'Memory','detail':'High'}},cfg,100)
        with patch.object(n,'send_channel') as send:
            self.assertEqual(n.deliver({**cfg,'enabled':False},100)['sent'],0)
            n.update_incidents({},cfg,160);self.assertEqual(n.deliver(cfg,160)['sent'],0)
            send.assert_not_called()

    def test_queued_tests_are_explicit_and_cancel_on_changed_destination(self):
        n=self.notification;cfg=self.config(enabled=False)
        n.PATH.write_text(json.dumps(cfg))
        with patch.object(n,'send_channel') as send:
            n.queue_test('email','admin')
            with self.assertRaises(ValueError):n.queue_test('email','admin')
            n.process_tests({**cfg,'revision':cfg['revision']+1});send.assert_not_called()
            n.queue_test('slack','admin');n.process_tests(cfg)
            self.assertEqual(send.call_count,1);self.assertEqual(send.call_args.args[0],'slack')

    def test_monitoring_gui_permissions_masking_and_save(self):
        from starlette.testclient import TestClient
        from starlette.requests import Request
        from app.main import app
        from app.auth import create_session
        from app.config import SESSION_COOKIE
        n=self.notification;cfg=self.config();n.PATH.write_text(json.dumps(cfg))
        with TestClient(app,base_url='https://localhost') as client:
            for role in ('viewer','operator','admin'):
                c=self.connect();uid=c.execute('SELECT id FROM users WHERE username=?',(role,)).fetchone()[0];c.close()
                token=create_session(uid,Request({'type':'http','headers':[],'client':('127.0.0.1',1)}));client.cookies.set(SESSION_COOKIE,token)
                response=client.get('/system/notifications')
                self.assertEqual(response.status_code,200 if role=='admin' else 403)
                self.assertNotIn('fixture-secret',response.text)
                self.assertEqual(client.post('/system/notifications/test/email',data={'csrf_token':'wrong'}).status_code,403)
            c=self.connect();csrf=c.execute('SELECT csrf_token FROM sessions ORDER BY id DESC LIMIT 1').fetchone()[0];c.close()
            data={**cfg,'recipients':'it@example.com','csrf_token':csrf,'smtp_password':'','slack_webhook':''}
            with patch('app.services.deployment.helper_request',return_value={'ok':True}) as helper:
                response=client.post('/system/notifications',data=data,follow_redirects=False)
                self.assertEqual(response.status_code,303);self.assertIn('msg=',response.headers['location'])
                self.assertEqual(helper.call_args.args[0],'save_notifications')
            c=self.connect()
            try:self.assertNotIn('fixture-secret',str([dict(x) for x in c.execute("SELECT * FROM audit_events WHERE action='NOTIFICATION_SETTINGS'")]))
            finally:c.close()

    def test_frozen_apply_does_not_clear_concurrent_save(self):
        import app.services.deployment as dep
        from app.services.access_model import create_application_dependency
        aid=self._app();c=self.connect();c.execute('INSERT INTO application_networks VALUES(?,1)',(aid,));c.commit();c.close()
        def transport(action,**payload):
            dep.LIVE_MANAGED_CONF.write_text((dep.CANDIDATE_ROOT/payload['candidate_id']/'security-web-gateway.conf').read_text())
            create_application_dependency(aid,'domain','later.example','HTTPS','operator')
            return {'ok':True}
        with patch.object(dep,'helper_request',side_effect=transport):dep.deploy('admin',None,'concurrency regression')
        c=self.connect()
        try:
            self.assertEqual(c.execute("SELECT pending FROM rules WHERE destination='later.example'").fetchone()[0],1)
            recorded=json.loads(c.execute('SELECT state_json FROM deployments ORDER BY id DESC LIMIT 1').fetchone()[0])
            self.assertNotIn('later.example',{r['destination'] for r in recorded['rules']})
        finally:c.close()
        self.assertNotIn('later.example',dep.LIVE_MANAGED_CONF.read_text())

    def test_deployed_expiry_does_not_publish_pending_rule(self):
        import app.services.deployment as dep
        from app.services.access_model import create_application_dependency
        from app.services.expiry import expire_deployed_policy
        from app.services.policy_explain import explain_policy
        aid=self._app();c=self.connect();c.execute('INSERT INTO application_networks VALUES(?,1)',(aid,));c.commit();c.close()
        def transport(action,**payload):
            dep.LIVE_MANAGED_CONF.write_text((dep.CANDIDATE_ROOT/payload['candidate_id']/'security-web-gateway.conf').read_text());return {'ok':True}
        with patch.object(dep,'helper_request',side_effect=transport):dep.deploy('admin',None,'initial')
        # Emulate a rule whose deadline has passed since the previous publication.
        c=self.connect();row=c.execute('SELECT * FROM deployments ORDER BY id DESC LIMIT 1').fetchone();state=json.loads(row['state_json'])
        target=next(r for r in state['rules'] if r['destination']=='portal.example.com');target['expires_at']='2000-01-01T00:00:00Z'
        c.execute('UPDATE rules SET expires_at=? WHERE id=?',(target['expires_at'],target['id']))
        c.execute('UPDATE deployments SET state_json=? WHERE id=?',(json.dumps(state),row['id']));c.commit();c.close()
        create_application_dependency(aid,'domain','queued.example','HTTPS','operator')
        with patch.object(dep,'helper_request',side_effect=transport):result=expire_deployed_policy()
        self.assertTrue(result['ok']);self.assertEqual(result['expired'],1)
        self.assertNotIn('portal.example.com',dep.LIVE_MANAGED_CONF.read_text());self.assertNotIn('queued.example',dep.LIVE_MANAGED_CONF.read_text())
        self.assertEqual(explain_policy('10.20.0.10','portal.example.com')['decision'],'DENY')
        c=self.connect()
        try:self.assertEqual(c.execute("SELECT pending FROM rules WHERE destination='queued.example'").fetchone()[0],1)
        finally:c.close()

    def test_restore_staging_accepts_legacy_absolute_hash_and_rejects_links(self):
        import hashlib,importlib.util
        spec=importlib.util.spec_from_file_location('restore_prepare',ROOT/'tools/prepare_state_restore.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        archive=Path(self.tmp.name)/'state.tar.gz'
        digest=hashlib.sha256(self.path.read_bytes()).hexdigest()
        with tarfile.open(archive,'w:gz') as output:
            for name,data in [('swg.db',self.path.read_bytes()),('metadata.txt',b'test'),('SHA256SUMS.txt',(digest+'  /deleted/source/swg.db\n').encode())]:
                info=tarfile.TarInfo(name);info.size=len(data);output.addfile(info,io.BytesIO(data))
        module.prepare(archive,Path(self.tmp.name)/'stage')
        bad=Path(self.tmp.name)/'bad.tar.gz'
        with tarfile.open(bad,'w:gz') as output:
            info=tarfile.TarInfo('swg.db');info.type=tarfile.SYMTYPE;info.linkname='/etc/passwd';output.addfile(info)
        with self.assertRaises(ValueError):module.prepare(bad,Path(self.tmp.name)/'bad-stage')

    def test_discovery_proxy_requires_auth_and_blocks_private_targets(self):
        import base64
        from app.services.discovery_proxy import discovery_egress_proxy
        from urllib.parse import urlsplit
        with discovery_egress_proxy() as proxy:
            target=urlsplit(proxy['server'])
            with socket.create_connection((target.hostname,target.port)) as client:
                client.sendall(b'CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n');self.assertIn(b'407',client.recv(2048))
            auth=base64.b64encode((proxy['username']+':'+proxy['password']).encode())
            with socket.create_connection((target.hostname,target.port)) as client:
                client.sendall(b'CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1\r\nProxy-Authorization: Basic '+auth+b'\r\n\r\n');self.assertIn(b'403',client.recv(2048))

    def test_email_uses_verified_tls_before_auth_and_slack_does_not_redirect(self):
        n=self.notification;cfg=self.config()
        from unittest.mock import MagicMock
        client=MagicMock();client.__enter__.return_value=client;client.send_message.return_value={}
        with patch('smtplib.SMTP',return_value=client):n.send_channel('email',cfg,'Health fixture')
        operations=[call[0] for call in client.method_calls]
        self.assertLess(operations.index('starttls'),operations.index('login'))
        self.assertLess(operations.index('login'),operations.index('send_message'))
        self.assertTrue(client.starttls.call_args.kwargs['context'].check_hostname)
        connection=MagicMock();response=connection.getresponse.return_value;response.status=302;response.read.return_value=b'ok'
        with patch('http.client.HTTPSConnection',return_value=connection):
            with self.assertRaisesRegex(RuntimeError,'SLACK_HTTP_302'):n.send_channel('slack',cfg,'Health fixture')
        self.assertEqual(connection.request.call_count,1)
        body=json.loads(connection.request.call_args.kwargs['body']);self.assertEqual(body['blocks'][0]['text']['type'],'plain_text')

    def test_updated_channel_configuration_retries_without_old_backoff(self):
        n=self.notification;cfg=self.config(confirmation_samples=1,slack_enabled=False)
        n.update_incidents({'proxy':{'severity':'critical','title':'Proxy','detail':'Down'}},cfg,100)
        with patch.object(n,'send_channel',side_effect=OSError('fixture-secret')):n.deliver(cfg,100)
        with patch.object(n,'send_channel') as send:
            self.assertEqual(n.deliver(cfg,110)['sent'],0)
            self.assertEqual(n.deliver({**cfg,'revision':cfg['revision']+1},111)['sent'],1)
            self.assertEqual(send.call_count,1)

    def test_resource_thresholds_and_backup_health_are_optional(self):
        n=self.notification;cfg=self.config()
        health={'squid_status':'active','nginx_status':'active','app_status':'active','port_ok':True,'disk':{'percent':20},'memory':{'percent':20},'ntp':{'ok':True}}
        events=n.conditions(health,{'cpu_percent':95}, {'state':'clean'},cfg,False,None)
        self.assertIn('cpu',events);self.assertIn('backup',events)
        events=n.conditions(health,{'cpu_percent':20},{'state':'clean'},{**cfg,'backup_age_hours':0},False,None)
        self.assertFalse(events)

    def test_managed_policy_rejects_includes_and_only_accepts_generated_grammar(self):
        from app.services.managed_config import validate_managed_config
        from app.services.deployment import generate_config
        self._app()
        self.assertTrue(validate_managed_config(generate_config()))
        for text in ['include /etc/shadow','external_acl_type attack /bin/sh','http_access allow all']:
            with self.assertRaises(ValueError):validate_managed_config(text)

    def test_saved_smtp_password_cannot_move_to_a_new_server_implicitly(self):
        from app.services.notification_config import validate_settings
        cfg=self.config()
        with self.assertRaisesRegex(ValueError,'Re-enter'):
            validate_settings({**cfg,'smtp_host':'new.example.com','smtp_password':''},cfg)


if __name__=='__main__':
    with tempfile.TemporaryDirectory(prefix='swg-v3110-') as td:
        os.environ.update(SWG_DB_PATH=str(Path(td)/'initial.db'),SWG_DATA_ROOT=td,SWG_LIVE_MANAGED_CONF=str(Path(td)/'live.conf'),SWG_MODE='production',SWG_PROXY_IP='127.0.0.1',SWG_FQDN='localhost')
        subprocess.check_call([sys.executable,str(ROOT/'tools/migrate.py'),'--db',os.environ['SWG_DB_PATH'],'--root',str(ROOT)])
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(HealthWorkflows))
        if not result.wasSuccessful():sys.exit(1)
