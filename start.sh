#!/bin/sh
set -eu
cd "$(dirname "$0")"
exec uvicorn proxy_server:app --host 0.0.0.0 --port ${PORT:-8000}
