-- Create extension "vector"
CREATE EXTENSION "vector" WITH SCHEMA "public";
-- Create extension "fuzzystrmatch"
CREATE EXTENSION "fuzzystrmatch" WITH SCHEMA "public";
-- Create "domain_label_embeddings" table
CREATE TABLE "public"."domain_label_embeddings" (
  "label" text NOT NULL,
  "embedding" public.vector(32) NOT NULL,
  "domains" jsonb NOT NULL DEFAULT '[]',
  "ns_domains" jsonb NOT NULL DEFAULT '[]',
  "updated_at" timestamptz NOT NULL,
  PRIMARY KEY ("label")
);
-- Create index "idx_dle_embedding" to table: "domain_label_embeddings"
CREATE INDEX "idx_dle_embedding" ON "public"."domain_label_embeddings" USING HNSW ("embedding" public.vector_cosine_ops);
