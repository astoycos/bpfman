#!/bin/sh
set -e 

# Clean first to avoid sending a huge build context
cargo clean
DOCKER_BUILDKIT=1 docker build -f packaging/container-deployment/Dockerfile -t bpfd:latest .