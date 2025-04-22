#!/bin/bash

IMAGE_NAME=go-ws-gateway-proxy

# Check if image exists locally
if ! docker image inspect "$IMAGE_NAME" > /dev/null 2>&1; then
  echo "Image '$IMAGE_NAME' not found locally. Building..."
  docker build -t "$IMAGE_NAME" .
  if [ $? -ne 0 ]; then
    echo "Docker build failed. Exiting."
    exit 1
  fi
fi

# Run the container
docker run --rm \
  -p 8099:8080 \
  --env-file .env \
  "$IMAGE_NAME"
