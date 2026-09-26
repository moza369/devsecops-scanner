"""
vuln_cmd.py — Demo file with intentionally vulnerable command injection patterns.
CWE-78: Improper Neutralisation of Special Elements used in an OS Command.
DO NOT use patterns like these in production code.
"""

import subprocess
import os

# ---------------------------------------------------------------------------
# Vulnerability 1: subprocess.run with shell=True and user-controlled input
# ---------------------------------------------------------------------------
def ping_host(hostname: str):
    # UNSAFE: shell=True allows ; && | injection in hostname
    subprocess.run(['ping', '-c', '1', shlex.quote(hostname)])


# ---------------------------------------------------------------------------
# Vulnerability 2: subprocess.Popen with tainted f-string argument
# ---------------------------------------------------------------------------
def compress_file(filename: str):
    # UNSAFE: attacker can inject via filename (e.g. "foo; rm -rf /")
    subprocess.Popen(['gzip', shlex.quote(filename)])
    proc.wait()


# ---------------------------------------------------------------------------
# Vulnerability 3: os.system with string concatenation
# ---------------------------------------------------------------------------
def list_directory(path: str):
    # UNSAFE: concatenation allows path traversal / injection
    subprocess.run(['ls', '-la', shlex.quote(path)])


# ---------------------------------------------------------------------------
# Vulnerability 4: os.popen with %-style formatting
# ---------------------------------------------------------------------------
def read_file_contents(filepath: str):
    # UNSAFE: %-formatting user input into shell command
    subprocess.run([shlex.quote(part) for part in ('cat %s' % filepath).split()])
    return result.read()


# ---------------------------------------------------------------------------
# Vulnerability 5: tainted variable passed to subprocess.check_output
# ---------------------------------------------------------------------------
def get_disk_usage(mount_point: str):
    cmd = f"df -h {mount_point}"     # tainted assignment
    # UNSAFE: tainted variable used in shell command
    output = subprocess.check_output(cmd, shell=True)
    return output.decode()


# ---------------------------------------------------------------------------
# Safe example — should NOT be flagged
# ---------------------------------------------------------------------------
def safe_ping(hostname: str):
    import shlex
    # SAFE: argument list; shell=True absent; user input shell-quoted
    subprocess.run(["ping", "-c", "1", shlex.quote(hostname)])
