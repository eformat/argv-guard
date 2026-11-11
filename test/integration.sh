#!/usr/bin/env bash
# Integration test: builds the cdylib and exercises it end-to-end.
set -u
cd "$(dirname "$0")/.."

cargo build --release 2>&1 | grep -E "warning|error" && exit 1
LIB="$PWD/target/release/libargvguard.so"
[[ -f "$LIB" ]] || { echo "FAIL: $LIB missing"; exit 1; }

pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  PASS: $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL: $1"; }

MARKER="$(mktemp -d)/marker"

echo "== 1. clean exec passes =="
if out=$(LD_PRELOAD="$LIB" bash -c 'echo guard-ok' 2>&1) && [[ "$out" == "guard-ok" ]]; then
  ok "clean command runs normally"
else bad "clean command broken: $out"; fi

echo "== 2. secret-bearing exec vetoed (and never runs) =="
out=$(LD_PRELOAD="$LIB" bash -c '/bin/true "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWX" && touch '"$MARKER" 2>&1); rc=$?
if [[ "$out" == *BLOCKED* && "$rc" -ne 0 && ! -f "$MARKER" ]]; then
  ok "veto fired, /bin/true never executed (rc=$rc)"
else bad "expected BLOCKED + no marker; rc=$rc out=$out"; fi
if [[ "$out" == *"ghp_ABCDEFGHIJKLMNOPQRSTUVWX"* ]]; then
  bad "stderr leaked the full secret"
else ok "stderr shows only redacted preview"; fi

echo "== 3. benign long args pass (no false positive) =="
if LD_PRELOAD="$LIB" bash -c '/bin/true --flag=this-is-a-normal-long-value-1234567890' 2>/dev/null; then
  ok "long benign flag passes"
else bad "false positive on benign long arg"; fi

echo "== 4. bypass works =="
if ARVGUARD_OFF=1 LD_PRELOAD="$LIB" bash -c '/bin/true "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWX"' 2>/dev/null; then
  ok "ARVGUARD_OFF=1 bypasses the veto"
else bad "bypass broken"; fi

echo "== 5. multiple pattern families =="
for t in 'oc login --token=sha256~eyJhbGciOiJSUzI1NiIsImtpZCI6' 'aws s3 ls --key AKIAIOSFODNN7EXAMPLE' 'slack-cli --tok xoxb-123456789012-abcdef' 'git push https://oauth2:glpat-abcdefghijklmnopqrst@gitlab.com/x/y' 'openai curl -H "Authorization: Bearer sk-proj-T3BlbkFJabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ"'; do
  if LD_PRELOAD="$LIB" bash -c "/bin/true $t" 2>&1 | grep -q BLOCKED; then
    ok "blocked: ${t:0:30}…"
  else bad "missed: $t"; fi
done

echo "== 6. private key as argv =="
if LD_PRELOAD="$LIB" bash -c '/bin/true "-----BEGIN OPENSSH PRIVATE KEY-----"' 2>&1 | grep -q BLOCKED; then
  ok "private key block matched"
else bad "private key missed"; fi

echo "== 6b. private key via stdin (the SAFE pattern) passes =="
if out=$(LD_PRELOAD="$LIB" bash -c '/bin/cat <<< "-----BEGIN OPENSSH PRIVATE KEY-----" > /dev/null && echo stdin-safe' 2>&1) && [[ "$out" == *stdin-safe* ]]; then
  ok "stdin-transported key is not argv — correctly allowed"
else bad "stdin pattern wrongly blocked: $out"; fi

echo "== 7. hits log: exists, redacted =="
HITS="$HOME/.local/share/argv-guard/hits.log"
if [[ -f "$HITS" ]] && ! grep -q "ghp_ABCDEFGHIJKLMNOPQRSTUVWX" "$HITS"; then
  ok "hits.log exists and contains no full secret"
else bad "hits.log missing or leaked the secret"; fi

echo "== 8. overhead: 300 execs with vs without (nanoseconds) =="
t0=$(date +%s%N); for i in $(seq 300); do /bin/true; done; t1=$(date +%s%N)
t2=$(date +%s%N); for i in $(seq 300); do LD_PRELOAD="$LIB" /bin/true; done; t3=$(date +%s%N)
base=$(( (t1 - t0) / 300 )); guarded=$(( (t3 - t2) / 300 ))
echo "  baseline $((base / 1000))µs/exec, guarded $((guarded / 1000))µs/exec (delta $(( (guarded - base) / 1000 ))µs — dyn-link dominated)"
if (( guarded - base < 1000000 )); then ok "overhead under 1ms/exec"; else bad "overhead too high: $(( (guarded - base) / 1000 ))µs"; fi

echo
echo "RESULT: $pass passed, $fail failed"
exit $((fail > 0))
