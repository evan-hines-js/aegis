#!/bin/bash
set -e

echo "Starting Aegis MCP Hub..."

# Wait for database to be ready
echo "Waiting for database connection..."
until pg_isready -h postgres -p 5432 -U postgres -d aegis_dev; do
  echo "Database not ready, waiting..."
  sleep 2
done

echo "Database ready, running migrations..."

# Run database migrations
mix ash.setup

echo "Migrations completed, starting server..."

# Start the application
exec /app/bin/server