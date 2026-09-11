#!/usr/bin/env bash
# Run the dudect constant-time campaign N times and summarize.
#
# Usage: ./dudect_campaign.sh [N]
#   N = number of full-suite repetitions (default 10)
#
# Decision rule (upstream dudect practice): a real timing leak fails in
# EVERY repetition (t grows with sample count); host noise does not
# replicate. A test is treated as leaking only if it fails in the majority
# of repetitions. Per-test medians are summarized as evidence.
set -u

N="${1:-10}"
cd "$(dirname "$0")"

mkdir -p dudect_campaign
EXE=$(find target/release/deps -maxdepth 1 -name 'dudect_ct_verification-*' -type f -executable ! -name '*.d' | head -n1)
if [ -z "$EXE" ]; then
    echo "error: dudect test binary not found; run 'cargo build --release' first" >&2
    exit 2
fi
echo "test binary: $EXE"
echo "repetitions: $N"

FAILS=dudect_campaign/failing_tests.txt
: > "$FAILS"

for i in $(seq 1 "$N"); do
    echo "===== repetition $i/$N ====="
    if "$EXE" --test-threads=1 --nocapture 2>&1 | tee "dudect_campaign/run_${i}.log" | grep -E '^test |t-statistic|PASS:|FAIL:|test result'; then
        echo "repetition $i: PASSED"
    else
        echo "repetition $i: FAILED"
        grep -E '^✗ FAIL' "dudect_campaign/run_${i}.log" \
            | sed 's/^✗ FAIL: //; s/ \(has timing leak\|is NOT constant-time\).*//' >> "$FAILS" || true
        if ! grep -q 'test result: FAILED' "dudect_campaign/run_${i}.log"; then
            echo "infra-error-run-${i}" >> "$FAILS"
        fi
    fi
done

echo
echo "================= CAMPAIGN SUMMARY ================="
echo "--- failing-test tally over $N repetitions ---"
sort "$FAILS" | uniq -c | sort -rn || true

LEAKING=$(grep -v '^infra-error' "$FAILS" | sort | uniq -c | awk -v n="$N" '$1 > n/2 {print $2}')
INFRA=$(grep -c '^infra-error' "$FAILS" || true)

if [ -n "$LEAKING" ]; then
    echo "VERDICT: ✗ CONSTANT-TIME REGRESSION"
    echo "  The following tests failed in a majority of $N repetitions"
    echo "  (a real leak fails every time; noise does not replicate):"
    echo "$LEAKING" | sed 's/^/    - /'
    exit 1
fi

if [ "$INFRA" -gt $((N / 2)) ]; then
    echo "VERDICT: ✗ INFRASTRUCTURE FAILURE"
    echo "  The campaign itself errored in $INFRA/$N repetitions"
    echo "  (build/harness problems, not timing leaks)."
    exit 2
fi

echo "VERDICT: ✓ CONSTANT-TIME (no test failed in a majority of $N repetitions)"
echo
echo "Median t per test across repetitions:"
grep -h -E '^=== dudect test:' dudect_campaign/run_*.log | sed 's/=== dudect test: //; s/ ===//' | sort -u | while read -r name; do
    MED=$(grep -A3 "^=== dudect test: ${name} ===" dudect_campaign/run_*.log 2>/dev/null \
        | grep -oE 'median of [0-9]+ campaigns, max [0-9.]+\): [0-9.]+' \
        | grep -oE '[0-9.]+$' | sort -n | awk '{a[NR]=$1} END {if (NR%2) print a[(NR+1)/2]; else print (a[NR/2]+a[NR/2+1])/2}')
    MAX=$(grep -A3 "^=== dudect test: ${name} ===" dudect_campaign/run_*.log 2>/dev/null \
        | grep -oE 'max [0-9.]+' | grep -oE '[0-9.]+' | sort -n | tail -n1)
    [ -n "$MED" ] && printf '  %-55s median=%-8s worst-draw=%s\n' "$name" "$MED" "$MAX"
done
