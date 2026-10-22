variable "clickhouse_url" {
  type    = string
  default = "clickhouse://localhost:9000/nameserver"
}

variable "postgres_url" {
  type    = string
  default = "postgres://nameserver_admin@localhost/nameserver?sslmode=disable"
}

env "clickhouse" {
  src = "file://atlas/schema/clickhouse.sql"
  dev = "docker://clickhouse/23.11/nameserver"
  url = var.clickhouse_url

  migration {
    dir = "file://atlas/migrations/clickhouse"
  }
}

env "postgres" {
  schema {
    src = "file://atlas/schema/postgres.sql"
    mode {
      roles       = true
      permissions = true
    }
  }
  dev = "docker://pgvector/pg18/dev"
  url = var.postgres_url

  diff {
    skip {
      // Roles are provisioned by NixOS on production; Atlas manages the
      // desired state but we skip DROP ROLE in diffs to avoid accidents.
      drop_role = true
    }
  }

  migration {
    dir = "file://atlas/migrations/postgres"
  }
}
