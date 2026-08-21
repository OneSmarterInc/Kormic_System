import subprocess
import sys

demos = [
    "demos/demo_phase2.py",
    "demos/demo_end_to_end.py",
    "demos/demo_attacks.py",
    "demos/demo_security_hardening.py",
    "demos/demo_recon_gap.py",
    "demos/demo_golden_path.py"
]

all_passed = True

for demo in demos:
    print(f"Running {demo}...")
    try:
        process = subprocess.run(
            [sys.executable, demo],
            input=b"\n" * 100,
            check=True
        )
        print(f"OK {demo} passed")
            
    except subprocess.CalledProcessError as e:
        print(f"FAIL {demo} failed with code {e.returncode}")
        print(e.stderr.decode('utf-8', errors='replace'))
        all_passed = False

if not all_passed:
    sys.exit(1)
print("All demos passed successfully!")
        
