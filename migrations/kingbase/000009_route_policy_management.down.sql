SELECT set_config('app.actor_id','authorization-service:migration',false);
UPDATE route_policy_permission_refs SET deleted_at=CURRENT_TIMESTAMP,deleted_by='authorization-service:migration' WHERE id IN ('e61a65a3-074e-50c2-bc2c-b3121dcb7bd0','a002c85b-172a-51e1-9c55-0dfbafc1a02e','47bac175-cd20-56db-b3be-25d4653dfb16');
UPDATE route_policy_definitions SET deleted_at=CURRENT_TIMESTAMP,deleted_by='authorization-service:migration' WHERE id IN ('a2b04521-2deb-5e06-8cc9-7c73d7f6a369','9546fecb-7076-5c60-b2f9-89efdf78c794','de0d501a-0543-51b6-9f69-d936a7661329');
UPDATE route_definitions SET deleted_at=CURRENT_TIMESTAMP,deleted_by='authorization-service:migration' WHERE id IN ('f0220831-7389-5b8e-acfc-7f0c28075c32','b6b49211-4b6f-506d-8923-c587990e70da','117e46ad-8453-508c-bca0-f723fda8066c');
