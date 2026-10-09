"""
PII Firewall Web Dashboard Launcher.
Loads and executes the frontend application from frontend/app.py.
"""

import runpy
import sys
from pathlib import Path

# Add backend directory to Python path
backend_path = Path(__file__).resolve().parent / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

# Add frontend directory to Python path
frontend_path = Path(__file__).resolve().parent / "frontend"
if str(frontend_path) not in sys.path:
    sys.path.insert(0, str(frontend_path))

# Execute the dedicated frontend application
frontend_app_file = frontend_path / "app.py"
runpy.run_path(str(frontend_app_file), run_name="__main__")
