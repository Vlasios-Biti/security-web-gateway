#!/usr/bin/env python3
"""GUI certificate import, self-signed renewal and public-only export."""
import base64,importlib.util,os,ssl,subprocess,sys,tempfile,unittest
from datetime import datetime,timezone
from pathlib import Path
from unittest.mock import patch
import smoke_v31212 as prior

ROOT=Path(__file__).resolve().parents[1]


class CertificateGUI(prior.CandidateVisibility):
    def tls_fixture(self):
        spec=importlib.util.spec_from_file_location('tls_gui_fixture',ROOT/'privileged/tls_install.py')
        tls=importlib.util.module_from_spec(spec);spec.loader.exec_module(tls)
        folder=Path(self.tmp.name);tls.TLS=folder/'tls';tls.TLS.mkdir();tls.NGINX=folder/'nginx';tls.ENV=folder/'production.env'
        cert=tls.TLS/'management.crt';key=tls.TLS/'management.key'
        tls.NGINX.write_text(f'ssl_certificate {cert};\nssl_certificate_key {key};\n');tls.ENV.write_text('SWG_FQDN=localhost\nSWG_PROXY_IP=192.0.2.44\n')
        subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',str(key),'-out',str(cert)],capture_output=True,check=True)
        key.chmod(0o600);real=tls.command
        def simulate(args,input_data=None):
            return real(args,input_data) if args[0]=='/usr/bin/openssl' else subprocess.CompletedProcess(args,0)
        return tls,cert,key,simulate

    def test_pfx_import_validates_password_and_never_publishes_private_material_as_certificate(self):
        tls,cert,key,simulate=self.tls_fixture();bundle=Path(self.tmp.name)/'bundle.pfx';password='Dummy-pfx-password-482!'
        subprocess.run(['/usr/bin/openssl','pkcs12','-export','-in',str(cert),'-inkey',str(key),'-out',str(bundle),'-passout','stdin'],input=(password+'\n').encode(),capture_output=True,check=True)
        payload={'certificate_format':'pfx','bundle':base64.b64encode(bundle.read_bytes()).decode(),'password':password,'hostname':'localhost'}
        previous=(cert.read_bytes(),key.read_bytes())
        with patch.object(tls,'command',side_effect=simulate):
            with self.assertRaises(ValueError):tls.install({**payload,'password':'wrong'})
            self.assertEqual((cert.read_bytes(),key.read_bytes()),previous)
            self.assertTrue(tls.install(payload)['ok'])
        self.assertNotIn(b'PRIVATE KEY',cert.read_bytes());self.assertNotIn(password.encode(),cert.read_bytes());self.assertEqual(key.stat().st_mode&0o777,0o600)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)

    def test_self_signed_renewal_reuses_key_and_covers_current_ip_and_pac_name(self):
        tls,cert,key,simulate=self.tls_fixture();previous_key=key.read_bytes()
        with patch.object(tls,'command',side_effect=simulate):
            self.assertTrue(tls.renew_self_signed({'days':365,'hostname':'pac.example.test'})['ok'])
        data=ssl._ssl._test_decode_cert(str(cert));self.assertEqual(key.read_bytes(),previous_key)
        self.assertIn(('IP Address','192.0.2.44'),data['subjectAltName']);self.assertIn(('DNS','pac.example.test'),data['subjectAltName'])
        self.assertGreater(ssl.cert_time_to_seconds(data['notAfter'])-datetime.now(timezone.utc).timestamp(),360*86400)
        with patch.object(tls,'command',side_effect=simulate):
            self.assertTrue(tls.renew_self_signed({'days':90,'hostname':'pac.example.test'})['ok'])
        self.assertEqual(key.read_bytes(),previous_key)
        with self.assertRaises(ValueError):tls.renew_self_signed({'days':999})

    def test_ca_issued_certificate_cannot_be_replaced_through_self_signed_renewal(self):
        tls,cert,key,simulate=self.tls_fixture();folder=Path(self.tmp.name);ca=folder/'ca.crt';cakey=folder/'ca.key';csr=folder/'leaf.csr'
        subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=Fixture CA','-keyout',str(cakey),'-out',str(ca)],capture_output=True,check=True)
        subprocess.run(['/usr/bin/openssl','req','-new','-key',str(key),'-subj','/CN=localhost','-out',str(csr)],capture_output=True,check=True)
        subprocess.run(['/usr/bin/openssl','x509','-req','-in',str(csr),'-CA',str(ca),'-CAkey',str(cakey),'-CAcreateserial','-days','2','-out',str(cert)],capture_output=True,check=True)
        before=(cert.read_bytes(),key.read_bytes())
        with patch.object(tls,'command',side_effect=simulate):
            with self.assertRaises(ValueError):tls.renew_self_signed({'days':365})
        self.assertEqual((cert.read_bytes(),key.read_bytes()),before)

    def test_renewal_restores_old_pair_if_nginx_reload_fails(self):
        tls,cert,key,simulate=self.tls_fixture();before=(cert.read_bytes(),key.read_bytes())
        def fail(args,input_data=None):
            return subprocess.CompletedProcess(args,1) if args[:2]==['/usr/bin/systemctl','reload'] else simulate(args,input_data)
        with patch.object(tls,'command',side_effect=fail):
            with self.assertRaises(ValueError):tls.renew_self_signed({'days':90})
        self.assertEqual((cert.read_bytes(),key.read_bytes()),before)

    def test_certificate_routes_use_fixed_helper_and_public_download_never_includes_key(self):
        tls,cert,key,_=self.tls_fixture();client,csrf=self.client_for('admin')
        with client,patch('app.services.deployment.helper_request',return_value={'ok':True}) as helper,patch('app.db.audit') as audit:
            response=client.post('/connection/certificate',data={'csrf_token':csrf,'certificate_format':'pfx','pfx_password':'Dummy-pfx-secret'},files={'bundle':('dummy.pfx',b'fixture','application/octet-stream')},follow_redirects=False)
            self.assertEqual(response.status_code,303);self.assertNotIn('error=',response.headers['location'])
            self.assertEqual(helper.call_args.args[0],'install_certificate');self.assertEqual(helper.call_args.kwargs['certificate_data']['password'],'Dummy-pfx-secret')
            self.assertNotIn('Dummy-pfx-secret',repr(audit.call_args))
            response=client.post('/connection/certificate/renew',data={'csrf_token':csrf,'validity_days':'365'},follow_redirects=False)
            self.assertEqual(response.status_code,303);self.assertEqual(helper.call_args.args[0],'renew_self_signed_certificate')
            response=client.post('/connection/certificate/renew',data={'csrf_token':'bad','validity_days':'365'},follow_redirects=False);self.assertEqual(response.status_code,403)
            with patch('app.services.system.MANAGEMENT_CERT',cert):
                # Even a legacy combined PEM file cannot expose its key through Download.
                cert.write_bytes(cert.read_bytes()+key.read_bytes());response=client.get('/connection/certificate/download')
                self.assertEqual(response.status_code,200);self.assertIn(b'BEGIN CERTIFICATE',response.content);self.assertNotIn(b'PRIVATE KEY',response.content)

    def test_certificate_card_exposes_import_and_renew_in_gui(self):
        client,_=self.client_for('admin')
        value={'days_remaining':20,'expires_at':'2026-12-04','state':'warning','ok':True,'subject':'Local gateway','issuer':'Local gateway','self_signed':True,'names':['localhost','192.0.2.44']}
        with client,patch('app.routers.connection.certificate_health',return_value=value):
            response=client.get('/connection');self.assertEqual(response.status_code,200)
            for label in ('id="https-certificate"','Windows PFX','Import certificate','Renew self-signed certificate','Download public certificate'):
                self.assertIn(label,response.text)


if __name__=='__main__':
    root=ROOT
    with tempfile.TemporaryDirectory(prefix='swg-v31213-') as td:
        os.environ.update(SWG_DB_PATH=td+'/initial.db',SWG_DATA_ROOT=td,SWG_LIVE_MANAGED_CONF=td+'/live.conf',SWG_MODE='production',SWG_PROXY_IP='127.0.0.1',SWG_FQDN='localhost')
        subprocess.run([sys.executable,str(root/'tools/migrate.py'),'--db',os.environ['SWG_DB_PATH'],'--root',str(root)],check=True)
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CertificateGUI))
        if not result.wasSuccessful():sys.exit(1)
