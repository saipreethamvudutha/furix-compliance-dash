# Postgres 16 with BOTH Apache AGE (graph) and pgvector (embeddings).
# Base = the official Apache AGE image (Postgres 16 + AGE preinstalled); we add
# pgvector by building it from source (fast, reliable).
FROM apache/age:PG16_latest

USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential git postgresql-server-dev-16 \
 && git clone --depth 1 --branch v0.8.0 https://github.com/pgvector/pgvector.git /tmp/pgvector \
 && cd /tmp/pgvector && make && make install \
 && rm -rf /tmp/pgvector \
 && apt-get purge -y build-essential git postgresql-server-dev-16 \
 && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# init.sql runs on first container init (creates DBs + enables both extensions).
COPY init.sql /docker-entrypoint-initdb.d/10-furix-init.sql
