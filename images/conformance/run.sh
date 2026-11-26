#!/bin/sh
# Usage: run.sh <install prefix> <target url> [suite arguments...]
# Runs the conformance suite against the target, then prints every scenario's checks.json to
# stdout between markers, so Probe can read the results from the container log (the container's
# filesystem is read-only and its scratch space disappears when it stops).
set -u
prefix=$1
url=$2
shift 2
mkdir -p /tmp/results
cd /tmp/results || exit 2
binary=$(ls "$prefix"/bin/* 2>/dev/null | head -n 1)
if [ -z "$binary" ]; then
  echo "@@PROBE-ERROR@@ no conformance binary under $prefix"
  exit 2
fi
node /opt/relay.mjs "$binary" "$url" "$@" >/tmp/conformance.log 2>&1
status=$?
find /tmp/results -name checks.json | sort | while read -r file; do
  echo "@@PROBE-SCENARIO@@ $(basename "$(dirname "$file")")"
  cat "$file"
  echo
done
echo "@@PROBE-END@@ $status"
