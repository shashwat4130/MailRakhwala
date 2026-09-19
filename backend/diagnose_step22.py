import sys
import os
import json
from pathlib import Path
import subprocess

print("=" * 70)
print("MAILRAKHWALA STEP 22 COMPREHENSIVE DIAGNOSTIC REPORT")
print("=" * 70)

# 1. Environment & Paths
backend_dir = Path.cwd()
repo_root = backend_dir.parent
print(f"\n[1] Python Executable : {sys.executable}")
print(f"[1] Python Version    : {sys.version.split()[0]}")
print(f"[1] Current Directory : {backend_dir}")
print(f"[1] Inferred Repo Root: {repo_root}")

# 2. Check vulnerability_rules.json locations & content
print("\n[2] Checking rules/vulnerability_rules.json locations:")
candidate_paths = [
    repo_root / "rules" / "vulnerability_rules.json",
    backend_dir / "rules" / "vulnerability_rules.json",
    backend_dir.parent / "rules" / "vulnerability_rules.json",
]

found_paths = []
for p in candidate_paths:
    p_res = p.resolve()
    if p_res.exists() and p_res not in found_paths:
        found_paths.append(p_res)
        print(f"    -> FOUND: {p_res} ({p_res.stat().st_size} bytes)")
        try:
            with open(p_res, "r", encoding="utf-8") as f:
                data = json.load(f)
            mappings = data.get("mappings", [])
            print(f"       Total mappings: {len(mappings)}")
            
            # Check specifically for STARTTLS category
            starttls_mappings = [m for m in mappings if m.get("mapping_id") == "MAP-STARTTLS-001"]
            if starttls_mappings:
                cat = starttls_mappings[0].get("category")
                print(f"       MAP-STARTTLS-001 category: '{cat}'")
                if cat == "STARTTLS":
                    print("       [!] ERROR: 'STARTTLS' is present in this file!")
                elif cat == "PROTOCOL":
                    print("       [*] OK: Set to 'PROTOCOL'")
            else:
                print("       [!] WARNING: MAP-STARTTLS-001 not found!")
                
            # List all categories used in the file
            cats = {m.get("category") for m in mappings}
            print(f"       Categories used: {cats}")
        except Exception as e:
            print(f"       [!] ERROR reading JSON: {e}")

if not found_paths:
    print("    [!] CRITICAL: No vulnerability_rules.json file found anywhere!")

# 3. Check FindingCategory enum in domain.py
print("\n[3] Checking FindingCategory Enum members:")
try:
    from app.schemas.domain import FindingCategory
    print(f"    FindingCategory members: {[m.value for m in FindingCategory]}")
    if "STARTTLS" in [m.value for m in FindingCategory]:
        print("    FindingCategory HAS 'STARTTLS'")
    else:
        print("    FindingCategory DOES NOT have 'STARTTLS'")
except Exception as e:
    print(f"    [!] Error importing FindingCategory: {e}")

# 4. Test import of vulnerability_mapping service directly
print("\n[4] Importing app.services.vulnerability_mapping:")
try:
    from app.services.vulnerability_mapping import (
        VulnerabilityCatalog,
        vulnerability_catalog,
        vulnerability_mapping_engine,
        VULN_RULES_PATH
    )
    print(f"    VULN_RULES_PATH resolved to: {VULN_RULES_PATH}")
    print(f"    vulnerability_catalog is loaded: {vulnerability_catalog.is_loaded}")
    print(f"    Indexed rule count: {len(vulnerability_catalog.mapping_by_id)}")
except Exception as e:
    print(f"    [!] FAILED importing service: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()

# 5. Check test file collection
print("\n[5] Pytest Collection for test_vulnerability_mapping.py:")
res = subprocess.run(
    [sys.executable, "-m", "pytest", "tests/test_vulnerability_mapping.py", "--collect-only", "-q"],
    capture_output=True,
    text=True
)
if res.stdout:
    for line in res.stdout.splitlines()[:15]:
        print(f"    {line}")
if res.stderr:
    for line in res.stderr.splitlines()[:15]:
        print(f"    [STDERR] {line}")

print("\n" + "=" * 70)
