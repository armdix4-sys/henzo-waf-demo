#!/usr/bin/env bash
export PYTHONPATH=$PYTHONPATH:.
uvicorn proxy_server:app --host 0.0.0.0 --port ${PORT:-8000}
