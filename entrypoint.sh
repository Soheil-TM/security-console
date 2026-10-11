#!/bin/sh
set -eu
if ! command -v git >/dev/null 2>&1; then
  apt-get update
  apt-get install -y --no-install-recommends git ca-certificates
  rm -rf /var/lib/apt/lists/*
fi
if ! python -c 'import flask,docker' >/dev/null 2>&1; then
  pip install --no-cache-dir flask==3.1.2 docker==7.1.0
fi
exec python /app/app.py
