#!/bin/bash

# Load environment variables and run the identity service

# Source the .env file
set -a  
source .env
set +a  

# Run the application
go run main.go --logtext --config config/config.yaml
