"""Shared resource checks for browser and deferred policy writers."""

def actor_role(c,actor):
    row=c.execute('SELECT role FROM users WHERE username=? AND enabled=1',(actor,)).fetchone()
    return row['role'] if row else None


def require_application_write(c,application_id,actor):
    app=c.execute("SELECT * FROM applications WHERE id=? AND status!='deleted'",(application_id,)).fetchone()
    if not app:raise ValueError('Application not found.')
    if app['system_managed'] and actor_role(c,actor)!='admin':raise ValueError('Administrator required for this protected application.')
    return app


def check_profile_membership_changes(c,old_ids,new_ids,actor):
    changed={int(x) for x in old_ids}^{int(x) for x in new_ids}
    if not changed:return
    protected=any(c.execute("SELECT 1 FROM policy_groups WHERE id=? AND system_managed=1",(gid,)).fetchone() for gid in changed)
    if protected and actor_role(c,actor)!='admin':raise ValueError('Administrator required to change membership of a protected profile.')
