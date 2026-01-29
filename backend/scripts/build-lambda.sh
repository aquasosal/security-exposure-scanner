#!/bin/bash

# Build Go Lambda function for deployment

set -e

cd "$(dirname "$0")/.."

echo "Building Lambda function..."

# Build for Linux (Lambda runtime)
GOOS=linux GOARCH=amd64 go build -tags lambda.norpc -o bootstrap cmd/api/main.go

# Create deployment package
zip -r function.zip bootstrap

echo "Build complete: function.zip"
