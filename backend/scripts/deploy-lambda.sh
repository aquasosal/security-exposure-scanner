#!/bin/bash

# Deploy Go Lambda function to AWS

set -e

if [ -z "$LAMBDA_FUNCTION_NAME" ]; then
  echo "Error: LAMBDA_FUNCTION_NAME environment variable not set"
  exit 1
fi

cd "$(dirname "$0")"

# Build first
./build-lambda.sh

echo "Deploying to Lambda function: $LAMBDA_FUNCTION_NAME"

# Update Lambda function code
aws lambda update-function-code \
  --function-name "$LAMBDA_FUNCTION_NAME" \
  --zip-file fileb://../function.zip \
  --region "${AWS_REGION:-ap-northeast-2}"

echo "Deployment complete!"

echo "Updating Lambda configuration..."
aws lambda update-function-configuration \
  --function-name "$LAMBDA_FUNCTION_NAME" \
  --timeout 300 \
  --memory-size 512 \
  --region "${AWS_REGION:-ap-northeast-2}"

echo "Configuration updated!"
