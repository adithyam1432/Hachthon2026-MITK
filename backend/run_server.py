"""
Backend REST API Gateway Launcher.
Runs the Flask HTTP API on port 5000.
"""

import sys
from pathlib import Path

# Ensure backend directory is in sys.path
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from pii_firewall.server import create_app

if __name__ == "__main__":
    app = create_app()
    print("🚀 Starting PII Firewall Backend REST API Gateway on http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
