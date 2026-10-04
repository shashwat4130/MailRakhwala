import sys
from pathlib import Path

backend_dir = Path("backend")
sys.path.insert(0, str(backend_dir))

from scripts.generate_demo_pcaps import smtp_capture, KINDS
print("Current KINDS in generate_demo_pcaps:", KINDS)
