#!/usr/bin/env python3
"""
Quick start script for the Recon Tool Web Dashboard
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api_server import app

if __name__ == "__main__":
    print("=" * 70)
    print("Recon Tool Web Dashboard")
    print("=" * 70)
    print("Starting API server on http://localhost:5000")
    print("Open http://localhost:5000 in your browser")
    print("=" * 70)
    print("Press Ctrl+C to stop the server")
    print("=" * 70)
    app.run(host="0.0.0.0", port=5000, debug=True)

