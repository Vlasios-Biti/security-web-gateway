"""GUI access to local company branding; production writes use the root helper."""
import json
import os
import tempfile
from app.config import MODE, DATA_ROOT
from app.services import block_page
from app.db import audit


def settings_path():
    return block_page.PATH if MODE == 'production' else DATA_ROOT / 'block-page-preview.json'


def settings():
    return block_page.read_settings(settings_path())


def save(value, actor, source_ip=None):
    value = block_page.validate(value)
    if MODE == 'production':
        from app.services.deployment import helper_request
        result = helper_request('save_block_page', settings=value)
        if not result.get('ok'):
            raise RuntimeError('Could not publish the company block page.')
    else:
        target = settings_path()
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix='.branding-', dir=target.parent)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as output:
                json.dump(value, output, ensure_ascii=False)
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)
    audit(actor, 'BLOCK_PAGE_SAVE', 'SUCCESS', 'settings', 'block_page', source_ip)
