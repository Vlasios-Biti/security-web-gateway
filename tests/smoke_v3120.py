#!/usr/bin/env python3
"""Exclusive GUI access choices, generic starter and safe profile deletion."""
import unittest
from unittest.mock import patch
import smoke_v3111 as prior

class AccessWorkflows(prior.SimpleWorkflows):
    def test_exclusive_application_access_and_existing_combined_preservation(self):
        from app.services.access_model import create_policy_group,get_application,update_application
        aid=self._app();gid=create_policy_group('Office profile','',[],[],[1],'admin')
        update_application(aid,'Learning App','Test','','portal.example.com','observed','https://portal.example.com',False,[1],'admin',[gid])
        client,csrf=self.client_for('admin')
        data={'name':'Learning App','seed_domain':'portal.example.com','source_kind':'observed','source_ref':'https://portal.example.com','csrf_token':csrf}
        with client,patch('app.routers.applications.apply_saved_change',return_value={'ok':True,'applied':True}):
            self.assertIn('value="profiles_keep_networks" selected',client.get('/applications/'+str(aid)+'/edit').text)
            self.assertEqual(client.post('/applications/'+str(aid)+'/edit',data={**data,'access_mode':'keep'},follow_redirects=False).status_code,303)
            self.assertEqual(get_application(aid)['group_ids'],[gid]);self.assertEqual(get_application(aid)['network_ids'],[1])
            client.post('/applications/'+str(aid)+'/edit',data={**data,'access_mode':'profiles','policy_group_ids':str(gid),'network_ids':'1'})
            self.assertEqual(get_application(aid)['group_ids'],[gid]);self.assertEqual(get_application(aid)['network_ids'],[])
            client.post('/applications/'+str(aid)+'/edit',data={**data,'access_mode':'networks','policy_group_ids':str(gid),'network_ids':'1'})
            self.assertEqual(get_application(aid)['group_ids'],[]);self.assertEqual(get_application(aid)['network_ids'],[1])
            bad=client.post('/applications/'+str(aid)+'/edit',data={**data,'access_mode':'profiles'})
            self.assertEqual(bad.status_code,400);self.assertEqual(get_application(aid)['network_ids'],[1])

    def test_discovery_can_assign_vlan_in_the_first_form(self):
        client,csrf=self.client_for('admin')
        with client,patch('app.routers.applications.create_run',return_value=123):
            response=client.post('/applications/discover/custom',data={'name':'New Portal','source_ref':'https://portal.example.com','method':'browser_auto','access_mode':'networks','network_ids':'1','auto_approve':'1','csrf_token':csrf},follow_redirects=False)
            self.assertEqual(response.status_code,303)
            c=self.connect();aid=c.execute("SELECT id FROM applications WHERE name='New Portal'").fetchone()[0];self.assertTrue(c.execute('SELECT 1 FROM application_networks WHERE application_id=? AND network_id=1',(aid,)).fetchone());self.assertFalse(c.execute('SELECT 1 FROM policy_group_applications WHERE application_id=?',(aid,)).fetchone());c.close()

    def test_generic_google_starter_is_unassigned_and_idempotent(self):
        from app.services.defaults import setup_defaults,GOOGLE_HOSTS
        from app.services.access_model import list_applications,get_application
        from app.services.deployment import generate_config
        before=generate_config();result=setup_defaults();aid=result['google_search']
        self.assertEqual([a['name'] for a in list_applications()],['Google Search'])
        app=get_application(aid);self.assertEqual(app['network_ids'],[]);self.assertEqual(app['group_ids'],[])
        self.assertEqual({d['destination'] for d in app['dependencies']},set(GOOGLE_HOSTS))
        self.assertEqual(before,generate_config());self.assertFalse(setup_defaults()['changed'])
        c=self.connect();c.execute('INSERT INTO application_networks VALUES(?,1)',(aid,));c.commit();c.close()
        content=generate_config();self.assertIn('www.google.com',content);self.assertNotIn('youtube.com',content);self.assertNotIn('dstdomain .google.com\n',content)

    def test_bootstrap_preserves_configured_google(self):
        from app.services.defaults import setup_defaults
        from app.services.access_model import create_application_dependency,get_application
        c=self.connect();aid=c.execute("SELECT id FROM applications WHERE name='Google Search'").fetchone()[0];c.execute('INSERT INTO application_networks VALUES(?,1)',(aid,));c.commit();c.close()
        create_application_dependency(aid,'domain','custom-google.example','HTTPS','admin')
        before=get_application(aid)
        self.assertFalse(setup_defaults()['installed_starter'])
        after=get_application(aid);self.assertEqual(before['network_ids'],after['network_ids']);self.assertEqual(before['dependencies'],after['dependencies'])

    def test_profile_delete_preserves_shared_access_and_allows_name_reuse(self):
        from app.services.access_model import create_policy_group,get_policy_group,get_application,create_application,create_application_dependency
        from app.services.deployment import generate_config
        aid=self._app()
        exclusive=create_application('Exclusive','Test','','exclusive.example','manual','',False,'admin');create_application_dependency(exclusive,'domain','exclusive.example','HTTPS','admin')
        one=create_policy_group('Mistaken profile','',[aid,exclusive],[],[1],'admin');two=create_policy_group('Keep profile','',[aid],[],[1],'admin')
        client,csrf=self.client_for('admin')
        with client,patch('app.routers.groups.apply_saved_change',return_value={'ok':True,'applied':True}):
            self.assertEqual(client.post('/policies/groups/'+str(one)+'/delete',data={'csrf_token':'wrong'}).status_code,403)
            response=client.post('/policies/groups/'+str(one)+'/delete',data={'csrf_token':csrf},follow_redirects=False);self.assertEqual(response.status_code,303)
        self.assertEqual(get_policy_group(one)['status'],'deleted');self.assertEqual(get_policy_group(one)['network_ids'],[])
        self.assertIsNotNone(get_application(aid));self.assertIn('portal.example.com',generate_config());self.assertNotIn('exclusive.example',generate_config());self.assertIsNotNone(get_application(exclusive));self.assertEqual(get_policy_group(two)['network_ids'],[1])
        create_policy_group('Mistaken profile','',[],[],[],'admin')
        client,_=self.client_for('viewer')
        with client:self.assertEqual(client.post('/policies/groups/'+str(two)+'/delete',data={'csrf_token':'wrong'}).status_code,403)
        c=self.connect();c.execute('UPDATE policy_groups SET system_managed=1 WHERE id=?',(two,));c.commit();c.close()
        client,csrf=self.client_for('operator')
        with client:self.assertEqual(client.post('/policies/groups/'+str(two)+'/delete',data={'csrf_token':csrf}).status_code,403)

    def test_snmp_read_only_source_filter_and_local_trap(self):
        import socket
        from app.services.notification_config import validate_settings,public_settings
        from app.services.snmp import respond,send_trap,v2,encoder,decoder
        cfg=validate_settings({'snmp_enabled':True,'snmp_host':'127.0.0.1','snmp_agent_enabled':True,'snmp_managers':['127.0.0.1/32'],'snmp_community':'fixture-snmp-community'})
        self.assertNotIn('fixture-snmp-community',str(public_settings(cfg)))
        pdu=v2.GetRequestPDU();v2.apiPDU.set_defaults(pdu);oid=tuple(map(int,(cfg['snmp_oid']+'.1.0').split('.')));v2.apiPDU.set_varbinds(pdu,[(oid,v2.Null(''))])
        message=v2.Message();v2.apiMessage.set_defaults(message);v2.apiMessage.set_community(message,cfg['snmp_community']);v2.apiMessage.set_pdu(message,pdu);packet=encoder.encode(message)
        answer=respond(packet,'127.0.0.1',cfg,{oid:v2.Integer32(3)});self.assertIsNotNone(answer)
        response,_=decoder.decode(answer,asn1Spec=v2.Message());self.assertEqual(int(v2.apiPDU.get_varbinds(v2.apiMessage.get_pdu(response))[0][1]),3)
        self.assertIsNone(respond(packet,'192.0.2.90',cfg,{oid:v2.Integer32(3)}));self.assertIsNone(respond(packet,'127.0.0.1',{**cfg,'snmp_community':'different-secret'},{oid:v2.Integer32(3)}));self.assertIsNone(respond(b'bad BER','127.0.0.1',cfg,{}))
        for pdu_type in (v2.SetRequestPDU,v2.GetBulkRequestPDU):
            request=pdu_type()
            if pdu_type==v2.GetBulkRequestPDU:
                v2.apiBulkPDU.set_defaults(request);v2.apiBulkPDU.set_max_repetitions(request,1000)
            else:v2.apiPDU.set_defaults(request)
            v2.apiPDU.set_varbinds(request,[(oid,v2.Integer32(0))]);v2.apiMessage.set_pdu(message,request)
            answer=respond(encoder.encode(message),'127.0.0.1',cfg,{oid:v2.Integer32(3)})
            parsed,_=decoder.decode(answer,asn1Spec=v2.Message());reply=v2.apiMessage.get_pdu(parsed)
            if pdu_type==v2.SetRequestPDU:self.assertEqual(int(v2.apiPDU.get_error_status(reply)),6)
            else:self.assertLessEqual(len(v2.apiPDU.get_varbinds(reply)),48)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as receiver:
            receiver.bind(('127.0.0.1',0));receiver.settimeout(2);send_trap({**cfg,'snmp_port':receiver.getsockname()[1]},'CRITICAL: fixture incident')
            packet,_=receiver.recvfrom(8192);trap,_=decoder.decode(packet,asn1Spec=v2.Message());self.assertEqual(v2.apiMessage.get_pdu(trap).tagSet,v2.SNMPv2TrapPDU.tagSet)
            self.assertIn('fixture incident',str(v2.apiPDU.get_varbinds(v2.apiMessage.get_pdu(trap))))
        for fields in ({'snmp_agent_enabled':True,'snmp_managers':['0.0.0.0/0'],'snmp_community':'long-enough-community'},{'snmp_enabled':True,'snmp_host':'','snmp_community':'long-enough-community'}):
            with self.assertRaises(ValueError):validate_settings(fields)

    def test_unified_access_and_bypass_preserve_connection_switches(self):
        client,csrf=self.client_for('admin')
        with client,patch('app.routers.applications.create_run',return_value=321),patch('app.routers.applications.apply_saved_change',return_value={'ok':True,'applied':True}):
            response=client.post('/applications/allow',data={'destination':'portal.example.com','access_mode':'networks','network_ids':'1','csrf_token':csrf},follow_redirects=False)
            self.assertEqual(response.status_code,303);self.assertIn('/applications/',response.headers['location'])
            # Refreshing an already-known website without a new assignment must not revoke its access.
            client.post('/applications/allow',data={'destination':'portal.example.com','access_mode':'none','csrf_token':csrf},follow_redirects=False)
            c=self.connect();aid=c.execute("SELECT id FROM applications WHERE seed_domain='portal.example.com'").fetchone()[0];self.assertTrue(c.execute('SELECT 1 FROM application_networks WHERE application_id=? AND network_id=1',(aid,)).fetchone());c.close()
            response=client.post('/applications/allow',data={'destination':'203.0.113.12','access_mode':'networks','network_ids':'1','csrf_token':csrf},follow_redirects=False)
            self.assertEqual(response.status_code,303)
            self.assertIn('203.0.113.12',client.get('/applications').text)
        with client,patch('app.routers.connection.connection_policy',return_value={'fail_open':True,'internal_direct':True,'bypass':[]}),patch('app.routers.connection.save_connection_policy') as save:
            response=client.post('/connection/bypass',data={'bypass':'one.example\ntwo.example','csrf_token':csrf},follow_redirects=False)
            self.assertEqual(response.status_code,303);self.assertTrue(save.call_args.args[0]['fail_open']);self.assertEqual(save.call_args.args[0]['bypass'],['one.example','two.example'])

    def test_edge_policy_tracks_central_fail_open_switch(self):
        import json
        client,_=self.client_for('admin')
        with client:
            for enabled in (True,False):
                with patch('app.routers.connection.connection_policy',return_value={'fail_open':enabled}):
                    response=client.get('/connection/edge-policy.json');self.assertEqual(response.status_code,200)
                    self.assertEqual(json.loads(response.text)['ProxyPacMandatory'],not enabled)

if __name__=='__main__':
    h=prior.health
    with h.tempfile.TemporaryDirectory(prefix='swg-v3120-') as td:
        h.os.environ.update(SWG_DB_PATH=str(h.Path(td)/'initial.db'),SWG_DATA_ROOT=td,SWG_LIVE_MANAGED_CONF=str(h.Path(td)/'live.conf'),SWG_MODE='production',SWG_PROXY_IP='127.0.0.1',SWG_FQDN='localhost')
        h.subprocess.check_call([h.sys.executable,str(h.ROOT/'tools/migrate.py'),'--db',h.os.environ['SWG_DB_PATH'],'--root',str(h.ROOT)])
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(AccessWorkflows))
        if not result.wasSuccessful():h.sys.exit(1)
