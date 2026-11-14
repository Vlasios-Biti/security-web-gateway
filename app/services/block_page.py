"""Typed, escaped company branding shared with the root publisher."""
import base64
import binascii
import html
import json
from pathlib import Path
import struct
import zlib

MAX_LOGO_BYTES=128*1024
DEFAULTS={'company':'Security Web Gateway','title':'Website blocked','message':'Your organization has not allowed this website. Contact IT if you need access.','contact':'','logo':''}
PATH=Path('/etc/security-web-gateway/block-page.json')
HTML_PATH=Path('/etc/security-web-gateway/blocked.html')


def validate(value):
    if not isinstance(value,dict):raise ValueError('Invalid block-page settings.')
    result={}
    for key,limit in (('company',100),('title',120),('message',1500),('contact',200)):
        text=value.get(key,DEFAULTS[key])
        if not isinstance(text,str) or len(text)>limit or any(ord(c)<32 and c not in '\n\t' for c in text):raise ValueError('Invalid block-page '+key+'.')
        result[key]=text.strip()
    if not result['company'] or not result['title'] or not result['message']:raise ValueError('Company, title and message are required.')
    logo=value.get('logo','')
    if not isinstance(logo,str) or len(logo)>4*((MAX_LOGO_BYTES+2)//3):raise ValueError('Use a PNG logo of at most 128 KB.')
    if logo:
        try:raw=base64.b64decode(logo,validate=True)
        except (ValueError,binascii.Error) as exc:raise ValueError('Invalid PNG logo.') from exc
        if len(raw)>MAX_LOGO_BYTES or len(raw)<45 or raw[:8]!=b'\x89PNG\r\n\x1a\n' or raw[8:16]!=b'\x00\x00\x00\x0dIHDR' or raw[-12:]!=b'\x00\x00\x00\x00IEND\xaeB`\x82':raise ValueError('Use a valid PNG logo of at most 128 KB.')
        position=8;has_image=False
        while position<len(raw):
            if position+12>len(raw):raise ValueError('Invalid PNG chunk.')
            size=struct.unpack('>I',raw[position:position+4])[0];end=position+12+size
            if end>len(raw) or zlib.crc32(raw[position+4:end-4])!=struct.unpack('>I',raw[end-4:end])[0]:raise ValueError('Invalid PNG checksum.')
            kind=raw[position+4:position+8]
            if kind==b'IDAT':has_image=True
            if kind==b'IEND' and end!=len(raw):raise ValueError('Invalid PNG ending.')
            position=end
        if not has_image:raise ValueError('PNG image data is missing.')
        width,height=struct.unpack('>II',raw[16:24])
        if not 1<=width<=2048 or not 1<=height<=2048:raise ValueError('Logo dimensions must be at most 2048 × 2048.')
        logo=base64.b64encode(raw).decode('ascii')
    result['logo']=logo
    return result


def read_settings(path=PATH):
    path=Path(path)
    if not path.exists():return dict(DEFAULTS)
    if path.stat().st_size>220000:raise ValueError('Block-page configuration too large.')
    return validate(json.loads(path.read_text(encoding='utf-8')))


def render(value,preview=False):
    cfg=validate(value);esc=lambda text:html.escape(text,quote=True)
    if preview:
        style='<link rel="stylesheet" href="/static/css/block-page.css">'
    else:
        css=(Path(__file__).resolve().parents[2]/'static/css/block-page.css').read_text(encoding='utf-8')
        style='<style>'+css+'</style>'
    logo='<img class="company-logo" alt="Company logo" src="data:image/png;base64,'+cfg['logo']+'">' if cfg['logo'] else '<div class="block-symbol" aria-hidden="true">&#128274;</div>'
    contact='<p class="contact">'+esc(cfg['contact'])+'</p>' if cfg['contact'] else ''
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>'+esc(cfg['title'])+'</title>'+style+'</head><body><main class="blocked-card">'+logo+'<p class="company">'+esc(cfg['company'])+'</p><h1>'+esc(cfg['title'])+'</h1><p class="message">'+esc(cfg['message'])+'</p>'+contact+'<div class="policy-note">Access is restricted by your organization’s web policy.</div></main></body></html>'
