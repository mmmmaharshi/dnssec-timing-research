#!/bin/bash
# run_cache_attack.sh - Cross-process cache attack simulation
#
# Simulates cross-VM cache attack using processes instead of Docker.
# Pins victim and attacker to same CPU cores for shared L3 cache.
#
# Usage:
#   bash run_cache_attack.sh              # Run full attack
#   bash run_cache_attack.sh --baseline   # Baseline only
#   bash run_cache_attack.sh --rsa        # RSA pattern only
#
# Requirements:
#   - cache_probe compiled (gcc -O2 -o cache_probe cache_probe.c -lpthread)
#   - taskset (usually pre-installed)
#   - Two or more CPU cores
#
# Author: DNSSEC Timing Research

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_DIR/results_cache_attack"
CACHE_PROBE="$SCRIPT_DIR/cache_probe"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[*]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

# Configuration
CORES=$(nproc)
if [ "$CORES" -lt 2 ]; then
    log_error "Need at least 2 CPU cores for cache attack"
    exit 1
fi

# Use cores 0 and 1 (typically share L3 cache)
VICTIM_CORE=0
ATTACKER_CORE=1
ROUNDS=1000

log_info "Cache Attack Simulation"
log_info "======================"
log_info "Available cores: $CORES"
log_info "Victim core: $VICTIM_CORE"
log_info "Attacker core: $ATTACKER_CORE"
log_info "Rounds: $ROUNDS"
log_info "Results: $RESULTS_DIR"

# Create results directory
mkdir -p "$RESULTS_DIR"

# Check cache_probe exists
if [ ! -x "$CACHE_PROBE" ]; then
    log_info "Compiling cache_probe..."
    cd "$SCRIPT_DIR"
    gcc -O2 -o cache_probe cache_probe.c -lpthread
fi

# Function to simulate victim workload (crypto-like operations)
simulate_victim() {
    local algorithm="$1"
    local duration_ms="${2:-10}"
    
    # Simulate different computational patterns based on algorithm
    case "$algorithm" in
        rsa)
            # RSA-like: modular exponentiation pattern (irregular memory access)
            python3 -c "
import time, random, math
end = time.time() + $duration_ms / 1000
data = list(range(1000))
while time.time() < end:
    # Simulate table lookups and modular operations
    for _ in range(100):
        idx = random.randint(0, 999)
        _ = pow(data[idx], 17, 999983)
    " 2>/dev/null
            ;;
        ecdsa)
            # ECDSA-like: point operations (more regular pattern)
            python3 -c "
import time, math
end = time.time() + $duration_ms / 1000
p = 2**256 - 2**32 - 977
while time.time() < end:
    # Simulate point double-and-add
    for i in range(256):
        x = (i * i) % p
        _ = math.sqrt(x + 1) if x > 0 else 0
    " 2>/dev/null
            ;;
        ed25519)
            # Ed25519-like: hash then scalar mult (burst then regular)
            python3 -c "
import time, hashlib
end = time.time() + $duration_ms / 1000
data = b'x' * 1024
while time.time() < end:
    # SHA-512-like burst
    for _ in range(10):
        _ = hashlib.sha512(data).digest()
    # Regular scalar mult
    p = 2**255 - 19
    for i in range(100):
        _ = (i * i) % p
    " 2>/dev/null
            ;;
        *)
            # Baseline: minimal work
            sleep "$(echo "$duration_ms / 1000" | bc -l)"
            ;;
    esac
}

# Run baseline measurement
run_baseline() {
    log_info "Running baseline (no victim activity)..."
    taskset -c "$ATTACKER_CORE" "$CACHE_PROBE" \
        --standalone \
        --rounds "$ROUNDS" \
        --label baseline \
        --output "$RESULTS_DIR/baseline.csv"
    log_info "Baseline complete"
}

# Run attack for a specific algorithm
run_attack() {
    local algorithm="$1"
    log_info "Running attack: $algorithm"
    
    # Start victim process on victim core
    log_info "  Starting victim workload on core $VICTIM_CORE..."
    taskset -c "$VICTIM_CORE" bash -c "
        while true; do
            $(declare -f simulate_victim)
            simulate_victim $algorithm 5
        done
    " &
    VICTIM_PID=$!
    
    # Let victim stabilize
    sleep 1
    
    # Run cache probe on attacker core
    log_info "  Measuring cache on core $ATTACKER_CORE..."
    taskset -c "$ATTACKER_CORE" "$CACHE_PROBE" \
        --standalone \
        --rounds "$ROUNDS" \
        --label "$algorithm" \
        --output "$RESULTS_DIR/${algorithm}.csv"
    
    # Kill victim
    kill "$VICTIM_PID" 2>/dev/null || true
    wait "$VICTIM_PID" 2>/dev/null || true
    
    log_info "  $algorithm complete"
}

# Main execution
case "${1:-}" in
    --baseline)
        run_baseline
        ;;
    --rsa)
        run_attack rsa
        ;;
    --ecdsa)
        run_attack ecdsa
        ;;
    --ed25519)
        run_attack ed25519
        ;;
    --help|-h)
        echo "Usage: $0 [--baseline|--rsa|--ecdsa|--ed25519]"
        echo ""
        echo "Runs cache-based timing attack simulation using processes."
        echo "Pins victim and attacker to same CPU cores for shared L3 cache."
        ;;
    *)
        # Full attack campaign
        run_baseline
        run_attack rsa
        run_attack ecdsa
        run_attack ed25519
        ;;
esac

log_info "All measurements complete. Results in $RESULTS_DIR/"
log_info "Next step: python3 $PROJECT_DIR/analysis/cache_classifier.py --input $RESULTS_DIR/*.csv"
