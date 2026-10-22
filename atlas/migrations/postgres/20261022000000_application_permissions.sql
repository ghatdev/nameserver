-- A fresh installation applies migrations independently of host provisioning.
-- Grant the application DML access and identity-sequence access after all tables exist.
REVOKE CREATE ON SCHEMA public FROM nameserver;
GRANT USAGE ON SCHEMA public TO nameserver;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO nameserver;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO nameserver;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO nameserver;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO nameserver;
ALTER DEFAULT PRIVILEGES FOR ROLE nameserver_admin IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO nameserver;
ALTER DEFAULT PRIVILEGES FOR ROLE nameserver_admin IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO nameserver;
