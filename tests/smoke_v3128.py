#!/usr/bin/env python3
"""PAC delivery and company block-page workflow regressions."""
import asyncio
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
from unittest.mock import patch
import unittest
import struct
import zlib
import smoke_v3127 as prior

ROOT = Path(__file__).resolve().parents[1]
def chunk(kind, content):
    return struct.pack('>I', len(content)) + kind + content + struct.pack('>I', zlib.crc32(kind + content))
PNG = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(b'\x00\x36\x5c\xe6')) + chunk(b'IEND', b'')


class ConnectionBranding(prior.SecurityCorrections):
    def test_branding_admin_save_preview_escape_keep_remove_and_reject_logo(self):
        from app.services import block_page_settings
        client, csrf = self.client_for('admin')
        data = {'csrf_token': csrf, 'company': 'Company & Team', 'title': 'Access blocked',
                'message': '<script>alert(1)</script> 100% private', 'contact': 'IT help desk'}
        with client, patch.object(block_page_settings, 'MODE', 'candidate'):
            response = client.post('/connection/blocked-page', data=data, files={'logo': ('logo.png', PNG, 'image/png')}, follow_redirects=False)
            self.assertEqual(response.status_code, 303); self.assertNotIn('error=', response.headers['location'])
            response = client.get('/connection/blocked-page/preview')
            self.assertEqual(response.status_code, 200)
            self.assertIn('&lt;script&gt;', response.text); self.assertNotIn('<script>', response.text)
            self.assertIn('data:image/png;base64,', response.text); self.assertIn('/static/css/block-page.css', response.text)
            self.assertIn('100% private', response.text)
            response = client.post('/connection/blocked-page', data=data, follow_redirects=False)
            self.assertNotIn('error=', response.headers['location']); self.assertTrue(block_page_settings.settings()['logo'])
            previous = block_page_settings.settings()
            for raw in (b'<svg onload="alert(1)"></svg>', b'x' * 131073, b''):
                response = client.post('/connection/blocked-page', data=data, files={'logo': ('fake.png', raw, 'image/png')}, follow_redirects=False)
                self.assertIn('error=', response.headers['location']); self.assertEqual(block_page_settings.settings(), previous)
            response = client.post('/connection/blocked-page', data={**data, 'remove_logo': 'true'}, follow_redirects=False)
            self.assertNotIn('error=', response.headers['location']); self.assertEqual(block_page_settings.settings()['logo'], '')

    def test_branding_production_uses_fixed_helper_and_keeps_secrets_out_of_audit(self):
        from app.services import block_page_settings, block_page
        with patch.object(block_page_settings, 'MODE', 'production'), patch('app.services.deployment.helper_request', return_value={'ok': True}) as helper, patch.object(block_page_settings, 'audit') as audit:
            block_page_settings.save(block_page.DEFAULTS, 'admin', '127.0.0.1')
            helper.assert_called_once_with('save_block_page', settings=block_page.DEFAULTS)
            self.assertNotIn(block_page.DEFAULTS['message'], repr(audit.call_args))
        with patch.object(block_page_settings, 'MODE', 'production'), patch('app.services.deployment.helper_request', return_value={'ok': False}):
            with self.assertRaises(RuntimeError): block_page_settings.save(block_page.DEFAULTS, 'admin')

    def test_branding_fixed_publisher_rolls_back_failed_config_write(self):
        from app.services import block_page
        spec = importlib.util.spec_from_file_location('brand_publisher', ROOT / 'privileged/block_page_install.py')
        publisher = importlib.util.module_from_spec(spec); spec.loader.exec_module(publisher)
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            page = Path(td) / 'blocked.html'; cfg = Path(td) / 'settings.json'
            page.write_text('old page'); cfg.write_text('old config')
            def replace(path, data, mode):
                if path == cfg: raise OSError('fixture write failure')
                path.write_text(data)
            with patch.object(publisher, 'PAGE', page), patch.object(publisher, 'CONFIG', cfg), patch.object(publisher, 'model', return_value=block_page), patch.object(publisher, 'replace', side_effect=replace):
                with self.assertRaises(OSError): publisher.install(block_page.DEFAULTS)
            self.assertEqual(page.read_text(), 'old page'); self.assertEqual(cfg.read_text(), 'old config')

    def test_block_page_deployment_preserves_allow_order_and_private_nginx_routes(self):
        from tools.configure_block_page import patch_squid, patch_nginx
        from tools.validate_policy import transformed
        from scripts.patch_squid import transform
        original = 'acl CONNECT method CONNECT\nhttp_access allow localnet allowed_site\nhttp_access deny all\n'
        updated = patch_squid(original, '192.0.2.10')
        self.assertEqual(patch_squid(updated, '192.0.2.10'), updated)
        self.assertLess(updated.index('allow localnet'), updated.index('http_access deny CONNECT'))
        self.assertLess(updated.index('http_access deny CONNECT'), updated.index('deny_info'))
        self.assertIn(r'^http://192\.0\.2\.10:8081/blocked$', updated)
        for convert in (transformed, transform):
            text = convert(updated, Path('/tmp/test-managed.conf'))
            self.assertLess(text.index('include /tmp/test-managed.conf'), text.index('http_access deny CONNECT'))
        for invalid in ('example.test', '127.0.0.1;allow all', '::1'):
            with self.assertRaises(ValueError): patch_squid(original, invalid)
        nginx = (ROOT / 'deploy/templates/nginx.conf.tpl').read_text().replace('__BIND_IP__', '192.0.2.10')
        new_nginx = patch_nginx(nginx)
        self.assertEqual(patch_nginx(new_nginx), new_nginx)
        self.assertEqual(new_nginx.count('location = /blocked {'), 1)
        self.assertIn('location / { return 404; }', new_nginx)
        self.assertNotIn('alias /etc/security-web-gateway/;', new_nginx)

    def test_block_page_schema_rejects_invalid_png_dimensions_and_non_text(self):
        from app.services import block_page
        for changes in ({'company': ''}, {'title': []}, {'message': 'x' * 1501}, {'logo': 'https://example.test/logo.png'}):
            with self.assertRaises(ValueError): block_page.validate({**block_page.DEFAULTS, **changes})
        raw = bytearray(PNG); raw[16:20] = (99999).to_bytes(4, 'big')
        with self.assertRaises(ValueError): block_page.validate({**block_page.DEFAULTS, 'logo': base64.b64encode(raw).decode()})


if __name__ == '__main__':
    import tempfile, subprocess, sys
    with tempfile.TemporaryDirectory(prefix='swg-v3128-') as td:
        os.environ.update(SWG_DB_PATH=td+'/initial.db', SWG_DATA_ROOT=td, SWG_LIVE_MANAGED_CONF=td+'/live.conf', SWG_MODE='production', SWG_PROXY_IP='127.0.0.1', SWG_FQDN='localhost')
        subprocess.run([sys.executable, str(ROOT/'tools/migrate.py'), '--db', os.environ['SWG_DB_PATH'], '--root', str(ROOT)], check=True)
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ConnectionBranding))
        if not result.wasSuccessful(): sys.exit(1)
