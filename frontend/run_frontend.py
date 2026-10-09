"""
Frontend Streamlit Dashboard Launcher.
Launches the Streamlit application on http://localhost:8501.
"""

import os
import subprocess
import sys
from pathlib import Path

if __name__ == "__main__":
    app_path = Path(__file__).resolve().parent / "app.py"
    cmd = [sys.executable, "-m", "streamlit", "run", str(app_path), "--server.port", "8501"]
    print(f"🚀 Launching PII Firewall Frontend on http://localhost:8501: {' '.join(cmd)}")
    subprocess.run(cmd)
