#!/usr/bin/env python3
"""Server-side candidate filters, pagination and review continuity."""
import os, subprocess, sys, tempfile, unittest
from pathlib import Path
from urllib.parse import urlencode, urlsplit, parse_qs
from unittest.mock import patch
import smoke_v3128 as prior


class CandidateFilters(prior.ConnectionBranding):
    def candidate(self, aid, destination, confidence='high', status='pending'):
        c=self.connect()
        cid=c.execute('INSERT INTO application_dependency_candidates(application_id,destination,confidence,confidence_score,status) VALUES(?,?,?,?,?)',(aid,destination,confidence,90 if confidence=='high' else 40,status)).lastrowid
        c.commit();c.close();return cid

    def test_candidate_filters_search_entire_dataset_and_paginate(self):
        from app.services.access_model import create_application
        aid=self._app();other=create_application('Second app','Test','','second.example.test','manual','',False,'admin')
        c=self.connect();c.executemany('INSERT INTO application_dependency_candidates(application_id,destination,confidence_score) VALUES(?,?,90)',[(aid,f'host-{i}.example.test') for i in range(505)]);c.commit();c.close()
        self.candidate(other,'api.second.example.test','medium')
        self.candidate(other,'history.second.example.test','high','ignored')
        client,_=self.client_for('admin')
        with client:
            response=client.get('/intelligence/dependency-candidates',params={'application_id':other,'q':'API.SECOND','confidence':'medium'})
            self.assertEqual(response.status_code,200);self.assertIn('api.second.example.test',response.text);self.assertNotIn('host-0.example.test',response.text)
            self.assertEqual(response.context['total'],1)
            response=client.get('/intelligence/dependency-candidates',params={'application_id':aid,'page':2})
            self.assertEqual(response.context['total'],505);self.assertEqual(len(response.context['rows']),50);self.assertEqual(response.context['pages'],11)
            response=client.get('/intelligence/dependency-candidates',params={'application_id':other,'status':'ignored'})
            self.assertEqual(response.context['total'],1);self.assertIn('history.second.example.test',response.text);self.assertNotIn('>Approve</button>',response.text)
            response=client.get('/intelligence/dependency-candidates',params={'application_id':other,'status':''})
            self.assertEqual(response.context['total'],2)
            for params in ({'q':'%'},{'q':"' OR 1=1 --"},{'application_id':999999,'page':999}):
                response=client.get('/intelligence/dependency-candidates',params=params)
                self.assertEqual(response.status_code,200);self.assertEqual(response.context['total'],0);self.assertEqual(response.context['filters']['page'],1)
            for params in ({'application_id':-1},{'application_id':'bad'},{'page':0},{'status':'bad'},{'confidence':'bad'},{'q':'x'*201}):
                self.assertEqual(client.get('/intelligence/dependency-candidates',params=params).status_code,400)

    def test_candidate_review_keeps_filters_and_history_is_read_only(self):
        aid=self._app();approved=self.candidate(aid,'api.approve.example.test');ignored=self.candidate(aid,'api.ignore.example.test')
        client,csrf=self.client_for('admin')
        filters={'application_id':str(aid),'q':'api.','status':'','confidence':'high','page':'2'}
        with client,patch('app.routers.intelligence.apply_saved_change',return_value={'ok':True}),patch('app.routers.intelligence.apply_message',return_value='Applied'):
            for cid,action in ((approved,'approve'),(ignored,'ignore')):
                response=client.post(f'/intelligence/dependency-candidates/{cid}/review',data={'action':action,'csrf_token':csrf,'filters':urlencode(filters)},follow_redirects=False)
                self.assertEqual(response.status_code,303)
                result=parse_qs(urlsplit(response.headers['location']).query,keep_blank_values=True)
                for key,value in filters.items():self.assertEqual(result[key],[value])
                returned=client.get(response.headers['location']);self.assertEqual(returned.status_code,200);self.assertEqual(returned.context['filters']['page'],1)
            self.assertEqual(client.post(f'/intelligence/dependency-candidates/{approved}/review',data={'action':'ignore','csrf_token':csrf}).status_code,404)
        c=self.connect();self.assertEqual(c.execute('SELECT status FROM application_dependency_candidates WHERE id=?',(approved,)).fetchone()[0],'approved');self.assertEqual(c.execute('SELECT status FROM application_dependency_candidates WHERE id=?',(ignored,)).fetchone()[0],'ignored');c.close()

    def test_invalid_review_filters_do_not_mutate_candidate(self):
        cid=self.candidate(self._app(),'api.example.test');client,csrf=self.client_for('admin')
        with client:
            response=client.post(f'/intelligence/dependency-candidates/{cid}/review',data={'action':'ignore','csrf_token':csrf,'filters':'status=invalid'},follow_redirects=False)
            self.assertEqual(response.status_code,400)
        c=self.connect();self.assertEqual(c.execute('SELECT status FROM application_dependency_candidates WHERE id=?',(cid,)).fetchone()[0],'pending');c.close()


if __name__=='__main__':
    root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix='swg-v3129-') as td:
        os.environ.update(SWG_DB_PATH=td+'/initial.db',SWG_DATA_ROOT=td,SWG_LIVE_MANAGED_CONF=td+'/live.conf',SWG_MODE='production',SWG_PROXY_IP='127.0.0.1',SWG_FQDN='localhost')
        subprocess.run([sys.executable,str(root/'tools/migrate.py'),'--db',os.environ['SWG_DB_PATH'],'--root',str(root)],check=True)
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CandidateFilters))
        if not result.wasSuccessful():sys.exit(1)
