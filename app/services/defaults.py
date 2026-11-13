"""Transactional, idempotent, unassigned public Google Search starter."""
import hashlib,json
from app.db import connect
GOOGLE_HOSTS=('google.com','www.google.com','consent.google.com','www.gstatic.com','ssl.gstatic.com')

def setup_defaults():
    c=connect()
    try:
        c.execute('BEGIN IMMEDIATE')
        if c.execute("SELECT 1 FROM settings WHERE key='generic_defaults_v1'").fetchone():
            c.rollback();return {'changed':False}
        # Retire the old empty Maps placeholder, never a configured application.
        for row in c.execute("SELECT a.id,a.name,a.slug FROM applications a WHERE a.slug='google-maps' AND a.created_by='migration-007' AND a.status='active' AND NOT EXISTS(SELECT 1 FROM application_rules ar WHERE ar.application_id=a.id)").fetchall():
            for table in ('application_networks','policy_group_applications'):c.execute('DELETE FROM '+table+' WHERE application_id=?',(row['id'],))
            c.execute("UPDATE applications SET name=?,slug=?,status='deleted',pending=1 WHERE id=?",(row['name']+' [retired empty '+str(row['id'])+']',row['slug']+'-retired-'+str(row['id']),row['id']))
        row=c.execute("SELECT * FROM applications WHERE name='Google Search' AND status!='deleted'").fetchone()
        install=False
        if row:
            aid=row['id']
            install=row['created_by']=='migration-007' and row['status']=='active' and not c.execute('SELECT 1 FROM application_rules WHERE application_id=?',(aid,)).fetchone()
        else:
            # Deleted names/slugs are archived by normal application deletion.
            slug='default-google-search';number=1
            while c.execute('SELECT 1 FROM applications WHERE slug=?',(slug,)).fetchone():number+=1;slug='default-google-search-'+str(number)
            aid=c.execute("INSERT INTO applications(name,slug,provider,seed_domain,source_kind,source_ref,system_managed,status,pending,created_by) VALUES('Google Search',?,'Google','www.google.com','builtin','https://www.google.com',1,'active',0,'defaults')",(slug,)).lastrowid;install=True
        if install:
            # Old migrations attached empty placeholders to profiles. Do not
            # turn those into automatic access grants when adding dependencies.
            c.execute('DELETE FROM application_networks WHERE application_id=?',(aid,))
            c.execute('DELETE FROM policy_group_applications WHERE application_id=?',(aid,))
            c.execute("UPDATE applications SET seed_domain='www.google.com',source_ref='https://www.google.com',description='Public Google search starter. Assign a profile or VLAN to allow access.' WHERE id=?",(aid,))
            c.execute("INSERT OR IGNORE INTO categories(name,slug,system_managed) VALUES('Google Search','google-search',1)")
            cid=c.execute("SELECT id FROM categories WHERE slug='google-search'").fetchone()[0]
            for host in GOOGLE_HOSTS:
                row=c.execute("SELECT id FROM rules WHERE rule_type='domain' AND destination=? AND protocol IN('HTTPS','BOTH') AND status='active'",(host,)).fetchone()
                if row:rid=row['id']
                else:
                    fp=hashlib.sha256(('google-starter-v1|'+host).encode()).hexdigest()
                    c.execute("INSERT OR IGNORE INTO rules(rule_type,destination,protocol,category_id,management_type,status,pending,reason,fingerprint,created_by,scope_mode) VALUES('domain',?,'HTTPS',?,'system','active',0,'Public Google search starter',?,'defaults','selected')",(host,cid,fp))
                    rid=c.execute('SELECT id FROM rules WHERE fingerprint=?',(fp,)).fetchone()[0]
                c.execute("INSERT INTO application_rules(application_id,rule_id,required,source,confidence,enabled) VALUES(?,?,1,'default-starter','high',1)",(aid,rid))
        c.execute("INSERT INTO settings(key,value) VALUES('generic_defaults_v1','1')")
        c.execute("INSERT INTO audit_events(actor,action,result,object_type,object_id,details_json) VALUES('system','DEFAULTS_SETUP','SUCCESS','application',?,?)",(aid,json.dumps({'preset':'google-search','installed_starter':install})))
        c.commit();return {'changed':True,'google_search':aid,'installed_starter':install}
    except Exception:c.rollback();raise
    finally:c.close()
