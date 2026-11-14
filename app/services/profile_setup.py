"""Save a profile, optional new VLAN and all memberships atomically."""
from app.db import connect
from app.services.rules import create_network
from app.services.access_model import create_policy_group,update_policy_group


def save_profile_setup(name,description,application_ids,rule_ids,network_ids,actor,new_cidr='',new_vlan_id='',group_id=None,require_network=False):
    name=name.strip();new_cidr=new_cidr.strip();new_vlan_id=str(new_vlan_id or '').strip()
    if len(name)<2:raise ValueError('Profile name is required.')
    if new_vlan_id and not new_cidr:raise ValueError('Enter a subnet for the new VLAN.')
    networks={int(n) for n in (network_ids or [])}
    if require_network and not networks and not new_cidr:raise ValueError('Choose an existing VLAN or enter a subnet below.')
    c=connect();created=None
    try:
        c.execute('BEGIN IMMEDIATE')
        if new_cidr:
            network_name=name;suffix=2
            while c.execute('SELECT 1 FROM networks WHERE name=?',(network_name,)).fetchone():network_name=name+' '+str(suffix);suffix+=1
            created=create_network(network_name,new_cidr,actor,'Created with access profile',vlan_id=new_vlan_id,policy_group_ids=[],c=c)
            networks.add(created['id'])
        if group_id is None:group_id=create_policy_group(name,description,application_ids,rule_ids,networks,actor,c=c)
        else:update_policy_group(group_id,name,description,application_ids,rule_ids,networks,actor,c=c)
        c.commit();return {'group_id':group_id,'network':created}
    except Exception:c.rollback();raise
    finally:c.close()
