#!/usr/bin/env bash
# Runs the BEFORE and AFTER assessment against localhost only.
set -u
cd "$(dirname "$0")"
mkdir -p evidence
rm -f app_v2_fixed/auth.log

python3 app_v1_vulnerable/app.py >/dev/null 2>&1 & P1=$!
AUTH_LOG="$PWD/app_v2_fixed/auth.log" python3 app_v2_fixed/app.py >/dev/null 2>&1 & P2=$!
trap 'kill $P1 $P2 2>/dev/null' EXIT
sleep 2

python3 assess.py http://127.0.0.1:5001 --requirements app_v1_vulnerable/requirements.txt \
  | tee evidence/before.txt
echo
python3 assess.py http://127.0.0.1:5002 --requirements app_v2_fixed/requirements.txt \
  --log app_v2_fixed/auth.log --lab-pass 'Lab-Only-Str0ng-Pass!' | tee evidence/after.txt
