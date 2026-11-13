"""A single explicit access method in GUI forms; legacy API calls stay compatible."""
def choose_access(mode, network_ids, group_ids, existing=None, scope_mode="selected", allow_all=False):
    networks=list(dict.fromkeys(network_ids or []));groups=list(dict.fromkeys(group_ids or []))
    if not mode:return networks,groups,scope_mode
    if mode=="profiles":
        if not groups:raise ValueError("Select an access profile.")
        return [],groups,"selected"
    if mode=="networks":
        if not networks:raise ValueError("Select a VLAN or network.")
        return networks,[],"selected"
    if mode=="none":return [],[],"selected"
    if mode=="all" and allow_all:return [],[],"all_proxy"
    if mode=="keep" and existing:
        return list(existing.get("network_ids",[])),list(existing.get("group_ids",existing.get("policy_group_ids",[]))),existing.get("scope_mode","selected")
    raise ValueError("Choose an access method.")


def save_discovery_access(aid,mode,network_ids,group_ids):
    from app.db import connect
    from app.services.access_model import get_application
    existing=get_application(aid)
    networks,groups,_=choose_access(mode,network_ids,group_ids,existing)
    c=connect()
    try:
        if mode:
            c.execute("DELETE FROM application_networks WHERE application_id=?",(aid,))
            c.execute("DELETE FROM policy_group_applications WHERE application_id=?",(aid,))
        for nid in networks:c.execute("INSERT OR IGNORE INTO application_networks VALUES(?,?)",(aid,nid))
        for gid in groups:c.execute("INSERT OR IGNORE INTO policy_group_applications VALUES(?,?)",(gid,aid))
        c.execute("UPDATE applications SET pending=1 WHERE id=?",(aid,));c.commit()
    except Exception:c.rollback();raise
    finally:c.close()
