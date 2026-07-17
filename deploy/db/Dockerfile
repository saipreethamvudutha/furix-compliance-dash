# Postgres 16 with BOTH Apache AGE (graph) and pgvector (embeddings).
# Base = the official Apache AGE image (Postgres 16 + AGE preinstalled); we add
# pgvector by building it from source (fast, reliable).
FROM apache/age:release_PG16_1.6.0

USER root
# pgvector from the PGDG apt repo (already configured in the Postgres-based AGE
# image) — no source build, no network CA-cert dependency.
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-16-pgvector \
 && rm -rf /var/lib/apt/lists/*

# init.sql runs on first container init (creates DBs + enables both extensions).
COPY init.sql /docker-entrypoint-initdb.d/10-furix-init.sql
