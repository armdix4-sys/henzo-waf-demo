#!/bin/bash
set -e
echo "=== Installing dependencies ==="
pip install -r requirements.txt
echo "=== Building Cython extension ==="
python setup.py build_ext --inplace
echo "=== Build phase completed successfully ==="
