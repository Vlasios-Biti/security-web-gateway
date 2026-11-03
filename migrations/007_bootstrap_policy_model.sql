-- Bootstrap Application Policies without widening any existing source scope.
INSERT OR IGNORE INTO applications(name,slug,provider,description,source_kind,system_managed,status,pending,created_by)
VALUES('Google Search','google-search','Google','Protected application bundle imported from the existing Google Search policy.','builtin',1,'active',0,'migration-007');
INSERT OR IGNORE INTO applications(name,slug,provider,description,source_kind,system_managed,status,pending,created_by)
VALUES('Google Maps','google-maps','Google','Protected application bundle imported from the existing Google Maps policy.','builtin',1,'active',0,'migration-007');

INSERT OR IGNORE INTO application_rules(application_id,rule_id,required,source,confidence)
SELECT a.id,r.id,1,'baseline','high'
FROM applications a JOIN categories c ON c.slug=a.slug JOIN rules r ON r.category_id=c.id
WHERE a.slug IN('google-search','google-maps') AND r.status!='deleted';

-- Preserve the union of all legacy per-dependency network scopes as the direct
-- Application Policy scope before migration 008 removes the redundant links.
INSERT OR IGNORE INTO application_networks(application_id,network_id)
SELECT DISTINCT ar.application_id,rn.network_id
FROM application_rules ar JOIN rule_networks rn ON rn.rule_id=ar.rule_id;

INSERT OR IGNORE INTO policy_groups(name,description,status,pending,system_managed,created_by)
VALUES('Restricted Internet - Standard','Reusable baseline profile containing only policies that were already effective for every current proxy network.','active',0,1,'migration-007');

-- Add an Application Policy to the common baseline only when its imported
-- scope already covers EVERY enabled proxy network. This avoids privilege
-- expansion when legacy Google policies had different source scopes.
INSERT OR IGNORE INTO policy_group_applications(group_id,application_id)
SELECT g.id,a.id FROM policy_groups g CROSS JOIN applications a
WHERE g.name='Restricted Internet - Standard'
  AND a.slug IN('google-search','google-maps')
  AND NOT EXISTS (
      SELECT 1 FROM networks n
      WHERE n.enabled=1 AND n.proxy_enabled=1
        AND NOT EXISTS (
            SELECT 1 FROM application_networks an
            WHERE an.application_id=a.id AND an.network_id=n.id
        )
  );

-- Likewise, only standalone custom ALLOW rules that were already effective for
-- every current proxy network become part of the default profile. Exceptions
-- keep their exact legacy direct scope and must be grouped explicitly by an admin.
INSERT OR IGNORE INTO policy_group_rules(group_id,rule_id)
SELECT g.id,r.id FROM policy_groups g CROSS JOIN rules r
WHERE g.name='Restricted Internet - Standard'
  AND r.management_type='custom' AND r.status!='deleted'
  AND NOT EXISTS (
      SELECT 1 FROM networks n
      WHERE n.enabled=1 AND n.proxy_enabled=1
        AND NOT EXISTS (
            SELECT 1 FROM rule_networks rn
            WHERE rn.rule_id=r.id AND rn.network_id=n.id
        )
  );

-- The common baseline profile is assigned to every current proxy network. Its
-- contents were constrained above to objects that already had the same reach.
INSERT OR IGNORE INTO policy_group_networks(group_id,network_id)
SELECT g.id,n.id FROM policy_groups g CROSS JOIN networks n
WHERE g.name='Restricted Internet - Standard' AND n.enabled=1 AND n.proxy_enabled=1;
