#!/bin/bash
set -e

echo "Creating Keycloak database..."

# Create keycloak_dev database
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE DATABASE keycloak_dev;
EOSQL

echo "Keycloak database created successfully"