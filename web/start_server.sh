#!/bin/bash
echo "======================================================================"
echo "Recon Tool Web Dashboard"
echo "======================================================================"
echo "Starting API server..."
echo ""
cd "$(dirname "$0")/.."
python3 web/api_server.py

