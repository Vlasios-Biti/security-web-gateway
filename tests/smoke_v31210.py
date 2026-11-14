#!/usr/bin/env python3
"""One application profile selector with safe legacy assignment preservation."""
import os, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import smoke_v3129 as prior


class ApplicationProfiles(prior.CandidateFilters):
    def test_application_forms_use_profiles_and_show_inherited_vlans(self):
        from app.services.access_model import create_policy_group
        aid=self._app();create_policy_group('Office access','',[],[],[1],'admin')
        c=self.connect();c.execute('UPDATE networks SET vlan_id=131 WHERE id=1');c.commit();c.close()
        client,_=self.client_for('admin')
        with client:
            for path in ('/applications/allow','/applications/discover','/applications/add',f'/applications/{aid}/edit'):
                response=client.get(path);self.assertEqual(response.status_code,200)
                self.assertIn('Office access',response.text);self.assertIn('VLAN 131',response.text)
                self.assertNotIn('data-access-method',response.text);self.assertNotIn('name="network_ids"',response.text)
                self.assertNotIn('value="networks"',response.text)
                self.assertIn('name="policy_group_ids"',response.text)

    def test_profile_edit_preserves_legacy_networks_until_explicit_replacement(self):
        from app.services.access_model import create_policy_group,update_application,get_application
        aid=self._app();old=create_policy_group('Old profile','',[],[],[1],'admin');new=create_policy_group('New profile','',[],[],[1],'admin')
        update_application(aid,'Learning App','Test','','portal.example.com','manual','',False,[1],'admin',[old])
        client,csrf=self.client_for('admin');data={'name':'Learning App','seed_domain':'portal.example.com','csrf_token':csrf,'policy_group_ids':str(new)}
        with client,patch('app.routers.applications.apply_saved_change',return_value={'ok':True,'applied':True}):
            response=client.post(f'/applications/{aid}/edit',data={**data,'access_mode':'profiles_keep_networks','network_ids':'999'},follow_redirects=False)
            self.assertEqual(response.status_code,303);self.assertEqual(get_application(aid)['network_ids'],[1]);self.assertEqual(get_application(aid)['group_ids'],[new])
            response=client.post(f'/applications/{aid}/edit',data={**data,'access_mode':'profiles_optional'},follow_redirects=False)
            self.assertEqual(response.status_code,303);self.assertEqual(get_application(aid)['network_ids'],[]);self.assertEqual(get_application(aid)['group_ids'],[new])
            response=client.post(f'/applications/{aid}/edit',data={'name':'Learning App','csrf_token':csrf,'access_mode':'profiles_optional'},follow_redirects=False)
            self.assertEqual(response.status_code,303);self.assertEqual(get_application(aid)['group_ids'],[])

    def test_new_application_assignment_creates_no_extra_profile_or_direct_scope(self):
        from app.services.access_model import create_policy_group,get_application
        gid=create_policy_group('Chosen profile','',[],[],[1],'admin')
        c=self.connect();before=c.execute('SELECT COUNT(*) FROM policy_groups').fetchone()[0];c.close()
        client,csrf=self.client_for('admin')
        with client:
            response=client.post('/applications/allow',data={'destination':'portal.example.test','access_mode':'profiles','policy_group_ids':gid,'network_ids':1,'csrf_token':csrf},follow_redirects=False)
            self.assertEqual(response.status_code,303)
            c=self.connect();aid=c.execute("SELECT id FROM applications WHERE seed_domain='portal.example.test'").fetchone()[0];self.assertEqual(c.execute('SELECT COUNT(*) FROM policy_groups').fetchone()[0],before);c.close()
            self.assertEqual(get_application(aid)['network_ids'],[]);self.assertEqual(get_application(aid)['group_ids'],[gid])
            response=client.post('/applications/allow',data={'destination':'other.example.test','access_mode':'profiles','csrf_token':csrf},follow_redirects=False)
            self.assertEqual(response.status_code,400)
        from app.services.access_choice import choose_access
        self.assertEqual(choose_access('profiles_optional',[1],[]),([],[],'selected'))
        with self.assertRaises(ValueError):choose_access('profiles_keep_networks',[1],[])


if __name__=='__main__':
    root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix='swg-v31210-') as td:
        os.environ.update(SWG_DB_PATH=td+'/initial.db',SWG_DATA_ROOT=td,SWG_LIVE_MANAGED_CONF=td+'/live.conf',SWG_MODE='production',SWG_PROXY_IP='127.0.0.1',SWG_FQDN='localhost')
        subprocess.run([sys.executable,str(root/'tools/migrate.py'),'--db',os.environ['SWG_DB_PATH'],'--root',str(root)],check=True)
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ApplicationProfiles))
        if not result.wasSuccessful():sys.exit(1)
