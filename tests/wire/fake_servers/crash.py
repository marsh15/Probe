"""Reads one request, complains on stderr, and exits without answering.

Usage: crash.py <exit_code>
"""

import sys

sys.stdin.readline()
sys.stderr.write("fatal: something broke\n")
sys.stderr.flush()
sys.exit(int(sys.argv[1]))
