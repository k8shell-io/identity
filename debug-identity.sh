#!/bin/bash

# Script to run identity service with debug support

echo "Starting identity service with debug support..."

# Set environment variables
export SECRET_FILES="/opt/shared/identity/secrets"
export POSTGRES_DATABASE="postgres"
export POSTGRES_HOSTNAME="127.0.0.1"
export POSTGRES_PORT="5432"
export MEMCACHED_HOSTNAME="127.0.0.1"
export MEMCACHED_PORT="11211"

echo "Starting identity service with Delve debugger..."
echo "Service will be available on port 9090, debugger on port 2345"

dlv debug --headless --listen=:2345 --api-version=2 --accept-multiclient -- --logtext --config config/config.yaml
