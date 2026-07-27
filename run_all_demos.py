import subprocess
import sys

demos = [
    "demo_phase2.py",
    "demos/demo_end_to_end.py",
    "demos/demo_attacks.py",
    "demos/demo_security_hardening.py"
]

all_passed = True

for demo in demos:
    print(f"Running {demo}...")
    try:
        # Pass plenty of newlines to stdin to instantly satisfy any input() calls
        process = subprocess.run(
            [sys.executable, demo],
            input=b"\n" * 100,
            capture_output=True,
            check=True
        )
        
        output = process.stdout.decode('utf-8', errors='replace')
        # Check for expected success output
        if "successfully" not in output.lower() and "blocked" not in output.lower() and "passed" not in output.lower():
            print(f"FAIL {demo} - Exited 0 but missing success marker in stdout")
            print("Output was:", output[:500])
            all_passed = False
        else:
            print(f"OK {demo} passed")
            
    except subprocess.CalledProcessError as e:
        print(f"FAIL {demo} failed with code {e.returncode}")
        print(e.stderr.decode('utf-8', errors='replace'))
        all_passed = False

if not all_passed:
    sys.exit(1)
print("All demos passed successfully!")
        
