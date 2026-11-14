#!/usr/bin/env python3
"""Per-source traffic evidence, scoped exports and searchable PC inventory."""
import csv
import io
import json
import time
import unittest
from datetime import datetime
from html import unescape
import re
import smoke_v3124 as prior


class ClientActivityWorkflows(prior.ReviewedWorkflows):
    def event(self,ip,host,index,epoch=None,decision='ALLOW',network='Office',vlan=131):
        epoch=time.time() if epoch is None else epoch
        c=self.connect()
        c.execute("""INSERT INTO telemetry_events(epoch,event_time,client_ip,decision,event_hash,destination_host,destination_ip,destination_port,network_name,vlan_id,bytes,method,result_code,http_status)
            VALUES(?,?,?,?,?,?,?,?,?,?,100,'CONNECT',?,?)""",(epoch,datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S'),ip,decision,'pc-fixture-'+str(index),host,'203.0.113.15',443,network,vlan,'TCP_DENIED' if decision=='DENY' else 'TCP_TUNNEL',403 if decision=='DENY' else 200))
        c.commit();c.close()

    def test_pc_detail_filters_pages_and_latest_metadata_use_same_window(self):
        from app.services.traffic import client_detail
        now=time.time()
        self.event('10.20.0.10','old.example.com','old',now-3*86400,network='ZZZ old network',vlan=999)
        for index in range(151):self.event('10.20.0.10','work.example.com',index,now-300+index,'DENY' if index%3==0 else 'ALLOW',network='AAA current network',vlan=131)
        self.event('10.20.0.20','other-pc.example.com','other',now)
        result=client_detail('10.20.0.10','24h',{'client_ip':'10.20.0.20','decision':'DENY','destination':'work.example.com'},2,25)
        self.assertEqual(result['summary']['total'],51);self.assertEqual(result['events']['page'],2);self.assertEqual(len(result['events']['rows']),25)
        self.assertTrue(all(row['client_ip']=='10.20.0.10' and row['decision']=='DENY' for row in result['events']['rows']))
        self.assertEqual(result['meta']['network_name'],'AAA current network');self.assertEqual(result['meta']['vlan_id'],131)
        self.assertNotIn('old.example.com',[row['name'] for row in result['destinations']])
        self.assertEqual(client_detail('10.20.0.10','all')['summary']['total'],152)

    def test_pc_inventory_searches_all_pages_and_cached_names(self):
        from app.services.traffic import client_inventory
        for index in range(1,66):self.event('10.20.0.'+str(index),'work.example.com',index)
        c=self.connect();c.execute("INSERT INTO dashboard_cache(key,payload_json,expires_at) VALUES(?,?,?)",('client-ptr:10.20.0.64',json.dumps({'hostname':'PC-HR.example.internal'}),time.time()+600));c.commit();c.close()
        result=client_inventory({'range':'24h'},2,50)
        self.assertEqual(result['total'],65);self.assertEqual(result['pages'],2);self.assertEqual(len(result['rows']),15)
        found=client_inventory({'range':'24h'},1,50,'PC-HR')
        self.assertEqual(found['total'],1);self.assertEqual(found['rows'][0]['ip'],'10.20.0.64');self.assertEqual(found['rows'][0]['destinations'],1)

    def test_pc_route_and_exports_cannot_switch_to_another_source_ip(self):
        self.event('10.20.0.10','work.example.com',1,decision='DENY')
        self.event('10.20.0.20','other-pc.example.com',2)
        client,_=self.client_for('viewer')
        with client:
            page=client.get('/traffic/clients/10.20.0.10?client_ip=10.20.0.20&decision=DENY&destination=work.example.com')
            self.assertEqual(page.status_code,200);self.assertIn('work.example.com',page.text);self.assertNotIn('other-pc.example.com',page.text)
            self.assertIn('source IP',page.text);self.assertIn('not an authenticated AD username',page.text)
            export=unescape(re.search(r'href="([^"]*export.csv[^"]*)"',page.text).group(1))
            self.assertIn('client_ip=10.20.0.10',export);self.assertNotIn('10.20.0.20',export)
            rows=list(csv.reader(io.StringIO(client.get(export).content.decode('utf-8-sig'))))
            self.assertEqual(len(rows),2);self.assertEqual(rows[1][1],'10.20.0.10');self.assertEqual(rows[1][8],'work.example.com')
            invalid=client.get('/traffic/clients/not-an-ip',follow_redirects=False);self.assertEqual(invalid.status_code,303)

    def test_client_search_and_explorer_link_preserve_monitoring_context(self):
        self.event('10.20.0.10','work.example.com',1)
        client,_=self.client_for('admin')
        with client:
            page=client.get('/traffic/clients?q=10.20.0.10&range=7d')
            self.assertEqual(page.status_code,200);self.assertIn('View activity',page.text);self.assertIn('value="10.20.0.10"',page.text)
            explorer=client.get('/traffic/explorer?client_ip=10.20.0.10&range=7d&destination=work.example.com')
            self.assertIn('/traffic/clients/10.20.0.10?range=7d',unescape(explorer.text))
            page=client.get('/traffic/clients/10.20.0.10?range=7d&destination=work.example.com')
            self.assertIn('value="work.example.com"',page.text);self.assertIn('AD login to this console',page.text)


if __name__=='__main__':
    h=prior.prior.prior.prior.prior.health
    with h.tempfile.TemporaryDirectory(prefix='swg-v3125-') as td:
        h.os.environ.update(SWG_DB_PATH=str(h.Path(td)/'initial.db'),SWG_DATA_ROOT=td,SWG_LIVE_MANAGED_CONF=str(h.Path(td)/'live.conf'),SWG_MODE='production',SWG_PROXY_IP='127.0.0.1',SWG_FQDN='localhost')
        h.subprocess.check_call([h.sys.executable,str(h.ROOT/'tools/migrate.py'),'--db',h.os.environ['SWG_DB_PATH'],'--root',str(h.ROOT)])
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ClientActivityWorkflows))
        if not result.wasSuccessful():h.sys.exit(1)
