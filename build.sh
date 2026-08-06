#!/bin/bash
set -e

echo "=== Installing dependencies ==="
pip install -r requirements.txt

echo "=== Skip Cython compilation (Pre-compiled module exists) ==="

echo "=== Build phase completed successfully ==="
