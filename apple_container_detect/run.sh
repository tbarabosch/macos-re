#!/bin/sh
set -eu

IMAGE="ubuntu:24.04"
WORKDIR="/workspace"

container run --rm \
  -v "$(pwd):$WORKDIR" \
  -w "$WORKDIR" \
  "$IMAGE" bash -lc '
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y g++ && \
    g++ -std=c++17 -O2 -Wall -Wextra apple_container_detect.cpp -o apple_container_detect && \
    ./apple_container_detect; \
    status=$?; \
    rm -f apple_container_detect; \
    exit $status
  '
