use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

#[derive(Clone)]
pub struct Database {
    pub pool: PgPool,
}

impl Database {
    /// Connect to PostgreSQL.
    ///
    /// Schema is managed by Atlas migrations (`atlas migrate apply --env postgres`).
    /// Indicator sources are managed declaratively via `nameserver source apply sources.toml`.
    /// Profiles are managed via `nameserver profile create/update`.
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .min_connections(2)
            .connect(url)
            .await?;
        Ok(Self { pool })
    }
}
