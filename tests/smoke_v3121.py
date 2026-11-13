#!/usr/bin/env python3
"""One-save profile/VLAN onboarding and atomic validation."""
import unittest
from unittest.mock import patch
import smoke_v3120 as prior

class CombinedProfileWorkflows(prior.AccessWorkflows):
    def test_profile_and_vlan_are_created_together_with_one_apply(self):
        from app.services.deployment import generate_config
        from app.services.access_model import get_policy_group
        aid=self._app();client,csrf=self.client_for('admin')
        with client,patch('app.routers.groups.apply_saved_change',return_value={'ok':True,'applied':True}) as publish:
            response=client.post('/policies/groups/add',data={'name':'Finance','new_cidr':'10.55.0.0/24','new_vlan_id':'155','application_ids':str(aid),'combined_setup':'true','csrf_token':csrf},follow_redirects=False)
            self.assertEqual(response.status_code,303,response.text);publish.assert_called_once()
        c=self.connect();group=c.execute("SELECT id FROM policy_groups WHERE name='Finance'").fetchone()[0];network=c.execute("SELECT * FROM networks WHERE cidr='10.55.0.0/24'").fetchone();self.assertEqual(network['vlan_id'],155);self.assertTrue(network['proxy_enabled']);c.close()
        self.assertEqual(get_policy_group(group)['network_ids'],[network['id']]);self.assertIn('portal.example.com',generate_config())

    def test_invalid_combined_save_rolls_back_vlan_and_retains_input(self):
        from app.services.access_model import create_policy_group
        create_policy_group('Already exists','',[],[],[],'admin')
        client,csrf=self.client_for('admin')
        with client,patch('app.routers.groups.apply_saved_change') as publish:
            response=client.post('/policies/groups/add',data={'name':'Already exists','new_cidr':'10.56.0.0/24','new_vlan_id':'156','combined_setup':'true','csrf_token':csrf})
            self.assertEqual(response.status_code,400);self.assertIn('10.56.0.0/24',response.text);self.assertIn('Already exists',response.text);publish.assert_not_called()
            c=self.connect();self.assertFalse(c.execute("SELECT 1 FROM networks WHERE cidr='10.56.0.0/24'").fetchone());c.close()
            response=client.post('/policies/groups/add',data={'name':'Overlapping','new_cidr':'10.20.0.0/25','combined_setup':'true','csrf_token':csrf});self.assertEqual(response.status_code,400)
            c=self.connect();self.assertFalse(c.execute("SELECT 1 FROM policy_groups WHERE name='Overlapping'").fetchone());c.close()
            response=client.post('/policies/groups/add',data={'name':'No VLAN chosen','combined_setup':'true','csrf_token':csrf});self.assertEqual(response.status_code,400)

    def test_adding_vlan_to_profile_keeps_old_assignments_and_permissions(self):
        from app.services.access_model import create_policy_group,get_policy_group
        aid=self._app();gid=create_policy_group('Office','',[aid],[],[1],'admin');client,csrf=self.client_for('admin')
        data={'name':'Office','network_ids':'1','application_ids':str(aid),'new_cidr':'10.57.0.0/24','new_vlan_id':'157','combined_setup':'true','csrf_token':csrf}
        with client,patch('app.routers.groups.apply_saved_change',return_value={'ok':True,'applied':True}):
            response=client.post('/policies/groups/'+str(gid)+'/edit',data=data,follow_redirects=False);self.assertEqual(response.status_code,303)
        c=self.connect();nid=c.execute("SELECT id FROM networks WHERE cidr='10.57.0.0/24'").fetchone()[0];c.close()
        self.assertEqual(set(get_policy_group(gid)['network_ids']),{1,nid});self.assertEqual(get_policy_group(gid)['application_ids'],[aid])
        client,csrf=self.client_for('operator')
        with client:
            data.update(csrf_token=csrf,new_cidr='10.58.0.0/24',new_vlan_id='158')
            self.assertEqual(client.post('/policies/groups/'+str(gid)+'/edit',data=data).status_code,403)
        c=self.connect();self.assertFalse(c.execute("SELECT 1 FROM networks WHERE cidr='10.58.0.0/24'").fetchone());c.close()

    def test_profile_copy_is_read_only_and_existing_vlan_is_prefilled(self):
        from app.services.access_model import create_policy_group
        aid=self._app();gid=create_policy_group('Source','',[aid],[],[1],'admin');client,_=self.client_for('admin')
        c=self.connect();count=c.execute('SELECT COUNT(*) FROM policy_groups').fetchone()[0];c.close()
        with client:
            response=client.get('/policies/groups/'+str(gid)+'/copy');self.assertEqual(response.status_code,200);self.assertIn('Source (copy)',response.text);self.assertIn('name="new_cidr"',response.text)
            response=client.get('/policies/groups/add?network_id=1');self.assertEqual(response.status_code,200);self.assertIn('value="1" checked',response.text)
        c=self.connect();self.assertEqual(c.execute('SELECT COUNT(*) FROM policy_groups').fetchone()[0],count);c.close()

    def test_unused_vlan_delete_returns_to_combined_page_and_keeps_used_vlan(self):
        from app.services.rules import create_network
        from app.services.access_model import create_policy_group
        unused=create_network('Unused','10.59.0.0/24','admin','Test record')['id']
        create_policy_group('Used VLAN','',[],[],[1],'admin')
        client,csrf=self.client_for('admin')
        with client,patch('app.routers.policies.apply_saved_change',return_value={'ok':True,'applied':True}):
            response=client.post('/policies/networks/'+str(unused)+'/delete',data={'csrf_token':csrf,'return_to':'profiles'},follow_redirects=False)
            self.assertEqual(response.status_code,303);self.assertTrue(response.headers['location'].startswith('/policies/groups?'))
            response=client.post('/policies/networks/1/delete',data={'csrf_token':csrf,'return_to':'profiles'},follow_redirects=False)
            self.assertIn('/policies/groups?error=',response.headers['location'])
        c=self.connect();self.assertFalse(c.execute('SELECT 1 FROM networks WHERE id=?',(unused,)).fetchone());self.assertTrue(c.execute('SELECT 1 FROM networks WHERE id=1').fetchone());c.close()

if __name__=='__main__':
    h=prior.prior.health
    with h.tempfile.TemporaryDirectory(prefix='swg-v3121-') as td:
        h.os.environ.update(SWG_DB_PATH=str(h.Path(td)/'initial.db'),SWG_DATA_ROOT=td,SWG_LIVE_MANAGED_CONF=str(h.Path(td)/'live.conf'),SWG_MODE='production',SWG_PROXY_IP='127.0.0.1',SWG_FQDN='localhost')
        h.subprocess.check_call([h.sys.executable,str(h.ROOT/'tools/migrate.py'),'--db',h.os.environ['SWG_DB_PATH'],'--root',str(h.ROOT)])
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CombinedProfileWorkflows))
        if not result.wasSuccessful():h.sys.exit(1)
