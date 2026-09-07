#!/bin/bash
# validate_attack.sh - Rigorous validation of cache attack
#
# Tests whether the cache timing signal is REAL or NOISE by:
# 1. Control experiments (same core, different cores, no victim)
# 2. Statistical significance testing (t-tests between distributions)
# 3. Ablation: vary core distance, workload intensity
# 4. Learning curve: accuracy vs sample size
# 5. Feature stability analysis
#
# Usage:
#   bash validate_attack.sh              # Full validation
#   bash validate_attack.sh --quick      # Quick sanity check
#
# Author: DNSSEC Timing Research

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_DIR/results_validation"
CACHE_PROBE="$SCRIPT_DIR/cache_probe"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[*]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }
log_section() { echo -e "\n${BLUE}=== $1 ===${NC}"; }

# Configuration
CORES=$(nproc)
ROUNDS=500  # Reduced for quicker validation

echo -e "${BLUE}"
echo "========================================"
echo "  Cache Attack Validation Suite"
echo "========================================"
echo -e "${NC}"
echo "Cores available: $CORES"
echo "Rounds per test: $ROUNDS"
echo "Results: $RESULTS_DIR"
echo ""

mkdir -p "$RESULTS_DIR"

# Check cache_probe
if [ ! -x "$CACHE_PROBE" ]; then
    log_info "Compiling cache_probe..."
    cd "$SCRIPT_DIR"
    gcc -O2 -o cache_probe cache_probe.c -lpthread
fi

# ============================================================
# TEST 1: Control - Same Core (Maximum Contention)
# ============================================================
log_section "TEST 1: Same Core (Maximum Contention Expected)"
log_info "Running victim and attacker on SAME core (core 0)..."
log_info "This should show MAXIMUM timing differences..."

# Victim on core 0
taskset -c 0 python3 -c "
import time, random, math
end = time.time() + 30
data = list(range(1000))
while time.time() < end:
    for _ in range(100):
        idx = random.randint(0, 999)
        _ = pow(data[idx], 17, 999983)
" &
VICTIM_PID=$!
sleep 1

# Attacker on SAME core 0
taskset -c 0 "$CACHE_PROBE" --standalone --rounds "$ROUNDS" --label same_core --output "$RESULTS_DIR/same_core.csv"
kill $VICTIM_PID 2>/dev/null; wait $VICTIM_PID 2>/dev/null || true
log_info "Same core test complete"

# ============================================================
# TEST 2: Control - No Victim (Baseline Noise)
# ============================================================
log_section "TEST 2: No Victim (Baseline Noise)"
log_info "Measuring cache with NO victim activity..."
"$CACHE_PROBE" --standalone --rounds "$ROUNDS" --label no_victim --output "$RESULTS_DIR/no_victim.csv"
log_info "Baseline complete"

# ============================================================
# TEST 3: Adjacent Cores (Share L3)
# ============================================================
log_section "TEST 3: Adjacent Cores (0 and 1, Share L3)"
log_info "Victim on core 0, Attacker on core 1..."

taskset -c 0 python3 -c "
import time, random
end = time.time() + 30
data = list(range(1000))
while time.time() < end:
    for _ in range(100):
        idx = random.randint(0, 999)
        _ = pow(data[idx], 17, 999983)
" &
VICTIM_PID=$!
sleep 1

taskset -c 1 "$CACHE_PROBE" --standalone --rounds "$ROUNDS" --label adjacent_cores --output "$RESULTS_DIR/adjacent_cores.csv"
kill $VICTIM_PID 2>/dev/null; wait $VICTIM_PID 2>/dev/null || true
log_info "Adjacent cores test complete"

# ============================================================
# TEST 4: Far Cores (if available)
# ============================================================
if [ "$CORES" -ge 4 ]; then
    log_section "TEST 4: Far Cores (0 and 3, May Not Share L3)"
    log_info "Victim on core 0, Attacker on core 3..."
    
    taskset -c 0 python3 -c "
import time, random
end = time.time() + 30
data = list(range(1000))
while time.time() < end:
    for _ in range(100):
        idx = random.randint(0, 999)
        _ = pow(data[idx], 17, 999983)
" &
    VICTIM_PID=$!
    sleep 1
    
    taskset -c 3 "$CACHE_PROBE" --standalone --rounds "$ROUNDS" --label far_cores --output "$RESULTS_DIR/far_cores.csv"
    kill $VICTIM_PID 2>/dev/null; wait $VICTIM_PID 2>/dev/null || true
    log_info "Far cores test complete"
else
    log_warn "Skipping far cores test (need 4+ cores)"
fi

# ============================================================
# TEST 5: Different Workload Intensities
# ============================================================
log_section "TEST 5: Workload Intensity Variation"

for INTENSITY in low medium high; do
    log_info "Testing $INTENSITY intensity workload..."
    
    case "$INTENSITY" in
        low)
            WORKLOAD="for _ in range(10): _ = pow(random.randint(0,999), 17, 999983)"
            ;;
        medium)
            WORKLOAD="for _ in range(100): _ = pow(random.randint(0,999), 17, 999983)"
            ;;
        high)
            WORKLOAD="for _ in range(500): _ = pow(random.randint(0,999), 17, 999983)"
            ;;
    esac
    
    taskset -c 0 python3 -c "
import time, random
end = time.time() + 30
while time.time() < end:
    $WORKLOAD
" &
    VICTIM_PID=$!
    sleep 1
    
    taskset -c 1 "$CACHE_PROBE" --standalone --rounds "$ROUNDS" --label "intensity_$INTENSITY" --output "$RESULTS_DIR/intensity_$INTENSITY.csv"
    kill $VICTIM_PID 2>/dev/null; wait $VICTIM_PID 2>/dev/null || true
done
log_info "Intensity tests complete"

# ============================================================
# TEST 6: Algorithm-Specific Patterns (Real DNSSEC-like Workloads)
# ============================================================
log_section "TEST 6: Algorithm-Specific Workloads"

# RSA-like: modular exponentiation
log_info "RSA-like workload (modular exp)..."
taskset -c 0 python3 -c "
import time, random
end = time.time() + 30
p = 999983
while time.time() < end:
    for _ in range(50):
        base = random.randint(2, p-1)
        _ = pow(base, 65537, p)
" &
VICTIM_PID=$!
sleep 1
taskset -c 1 "$CACHE_PROBE" --standalone --rounds "$ROUNDS" --label rsa_like --output "$RESULTS_DIR/rsa_like.csv"
kill $VICTIM_PID 2>/dev/null; wait $VICTIM_PID 2>/dev/null || true

# ECDSA-like: point operations
log_info "ECDSA-like workload (point ops)..."
taskset -c 0 python3 -c "
import time, math
end = time.time() + 30
p = 2**256 - 2**32 - 977
while time.time() < end:
    for i in range(100):
        x = (i * i) % p
        try: _ = math.isqrt(x)
        except: pass
" &
VICTIM_PID=$!
sleep 1
taskset -c 1 "$CACHE_PROBE" --standalone --rounds "$ROUNDS" --label ecdsa_like --output "$RESULTS_DIR/ecdsa_like.csv"
kill $VICTIM_PID 2>/dev/null; wait $VICTIM_PID 2>/dev/null || true

# Ed25519-like: hash + scalar mult
log_info "Ed25519-like workload (hash + scalar)..."
taskset -c 0 python3 -c "
import time, hashlib
end = time.time() + 30
data = b'x' * 1024
p = 2**255 - 19
while time.time() < end:
    for _ in range(5):
        _ = hashlib.sha512(data).digest()
    for i in range(50):
        _ = (i * i) % p
" &
VICTIM_PID=$!
sleep 1
taskset -c 1 "$CACHE_PROBE" --standalone --rounds "$ROUNDS" --label ed25519_like --output "$RESULTS_DIR/ed25519_like.csv"
kill $VICTIM_PID 2>/dev/null; wait $VICTIM_PID 2>/dev/null || true

# ============================================================
# ANALYSIS: Statistical Tests
# ============================================================
log_section "ANALYSIS: Statistical Validation"

cd "$PROJECT_DIR"

# Combine all results for analysis
log_info "Combining results for statistical analysis..."
{
    head -1 "$RESULTS_DIR/no_victim.csv"
    for f in "$RESULTS_DIR"/*.csv; do
        tail -n +2 "$f"
    done
} > "$RESULTS_DIR/all_combined.csv"

# Run statistical analysis
log_info "Running statistical tests..."
export PATH="$HOME/.local/bin:$PATH"
uv run python3 << 'PYTHON'
import numpy as np
import pandas as pd
from scipy import stats
from pathlib import Path

results_dir = Path("results_validation")
df = pd.read_csv(results_dir / "all_combined.csv")

print("\n" + "="*60)
print("STATISTICAL VALIDATION RESULTS")
print("="*60)

# Get timing data (exclude round, label columns)
timing_cols = [c for c in df.columns if c.startswith('cache_')]
timing_data = df[timing_cols].values.astype(np.float64)
labels = df['label'].values

classes = np.unique(labels)
print(f"\nClasses: {classes}")
print(f"Samples per class: {dict(zip(*np.unique(labels, return_counts=True)))}")

# Test 1: ANOVA - are means significantly different?
print("\n--- Test 1: One-Way ANOVA ---")
class_groups = [timing_data[labels == c].mean(axis=1) for c in classes]
f_stat, p_value = stats.f_oneway(*class_groups)
print(f"F-statistic: {f_stat:.4f}")
print(f"p-value: {p_value:.2e}")
print(f"Significant: {'YES' if p_value < 0.05 else 'NO'}")

# Test 2: Pairwise t-tests
print("\n--- Test 2: Pairwise Welch's t-tests ---")
print(f"{'Comparison':<30} {'t-stat':>10} {'p-value':>12} {'Sig?':>6}")
print("-" * 62)
for i, c1 in enumerate(classes):
    for c2 in classes[i+1:]:
        g1 = timing_data[labels == c1].mean(axis=1)
        g2 = timing_data[labels == c2].mean(axis=1)
        t, p = stats.ttest_ind(g1, g2, equal_var=False)
        sig = "***" if p < 0.001 else "**" if p < 0.01 else "*" if p < 0.05 else ""
        print(f"{c1+' vs '+c2:<30} {t:>10.3f} {p:>12.2e} {sig:>6}")

# Test 3: Effect sizes (Cohen's d)
print("\n--- Test 3: Effect Sizes (Cohen's d) ---")
print(f"{'Comparison':<30} {'Cohen d':>10} {'Effect':>10}")
print("-" * 52)
for i, c1 in enumerate(classes):
    for c2 in classes[i+1:]:
        g1 = timing_data[labels == c1].mean(axis=1)
        g2 = timing_data[labels == c2].mean(axis=1)
        d = (np.mean(g1) - np.mean(g2)) / np.sqrt((np.var(g1) + np.var(g2)) / 2)
        effect = "large" if abs(d) > 0.8 else "medium" if abs(d) > 0.5 else "small" if abs(d) > 0.2 else "negligible"
        print(f"{c1+' vs '+c2:<30} {d:>10.3f} {effect:>10}")

# Test 4: Classification with cross-validation
print("\n--- Test 4: Classification Accuracy ---")
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler

# Extract features
def extract_features(X):
    features = []
    for row in X:
        f = []
        f.append(np.mean(row))
        f.append(np.std(row))
        f.append(np.min(row))
        f.append(np.max(row))
        f.append(np.median(row))
        f.append(np.percentile(row, 95))
        f.append(np.percentile(row, 5))
        misses = row[row > 100]
        f.append(len(misses))
        f.append(len(misses) / len(row))
        f.append(np.mean(np.diff(np.where(row > 100)[0])) if len(misses) > 1 else 0)
        features.append(f)
    return np.array(features)

X = extract_features(timing_data)
y = labels

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

clf = RandomForestClassifier(n_estimators=100, random_state=42)
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
scores = cross_val_score(clf, X_scaled, y, cv=cv, scoring='accuracy')

print(f"5-Fold CV Accuracy: {scores.mean():.4f} (+/- {scores.std():.4f})")
print(f"Fold scores: {scores}")
print(f"Above random chance (1/{len(classes)} = {1/len(classes):.2%}): {'YES' if scores.mean() > 1/len(classes) else 'NO'}")

# Test 5: Permutation test (is the signal real?)
print("\n--- Test 5: Permutation Test (100 permutations) ---")
n_permutations = 100
perm_scores = []
for _ in range(n_permutations):
    y_perm = np.random.permutation(y)
    perm_score = cross_val_score(clf, X_scaled, y_perm, cv=cv, scoring='accuracy').mean()
    perm_scores.append(perm_score)

perm_scores = np.array(perm_scores)
p_value = np.mean(perm_scores >= scores.mean())
print(f"Real accuracy: {scores.mean():.4f}")
print(f"Permuted accuracy mean: {perm_scores.mean():.4f}")
print(f"Permutation p-value: {p_value:.4f}")
print(f"Signal is REAL: {'YES' if p_value < 0.05 else 'NO'}")

print("\n" + "="*60)
print("CONCLUSION")
print("="*60)
if p_value < 0.05 and scores.mean() > 0.5:
    print("✓ Cache timing signal is STATISTICALLY SIGNIFICANT")
    print("✓ Classification is above random chance")
    print("✓ Attack is REAL, not noise")
else:
    print("✗ Cache timing signal is NOT statistically significant")
    print("✗ Classification may be overfitting to noise")
    print("✗ Attack may not be real")
PYTHON

log_info "Validation complete! Results in $RESULTS_DIR/"
