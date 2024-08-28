#!/usr/bin/env bash

echo "Enabling extensions on database $POSTGRES_DB"
psql -U $POSTGRES_USER --dbname="$POSTGRES_DB" <<-'EOSQL'
  CREATE EXTENSION IF NOT EXISTS pg_trgm;
  CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
EOSQL
echo "Finished with exit code $?"
