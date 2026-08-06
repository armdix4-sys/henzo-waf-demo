#!/bin/bash
set -e
python -m uvicorn proxy_server:app --host 0.0.0.0 --port ${PORT:-10000}
