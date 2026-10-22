-- This migration has been superseded by declarative role/permission management
-- in atlas/schema/roles.hcl (Atlas v1.1 Security as Code).
--
-- Original content: GRANT ALL ON ALL TABLES/SEQUENCES + ALTER DEFAULT PRIVILEGES.
-- Now managed by Atlas's roles/permissions mode in atlas.hcl.
SELECT 1;
