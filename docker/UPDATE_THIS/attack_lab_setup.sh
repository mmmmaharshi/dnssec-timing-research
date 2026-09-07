#!/bin/bash
# attack_lab_setup.sh - Setup script for local cache attack lab
#
# This script sets up the local environment to test cache-based DNSSEC timing attack
# using Docker containers pinned to shared CPU cores.
#
# Usage:
#   bash attack_lab_setup.sh         # Start the lab
#   bash attack_lab_setup.sh attack  # Run the attack
#   bash attack_lab_setup.sh stop    # Stop the lab
#   bash attack_lab_setup.sh clean   # Clean up all containers and images

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[*]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Check if running on Linux (required for Docker cache pinning)
check_platform() {
    if [[ "$(uname)" != "Linux" ]]; then
        log_error "This script requires Linux for CPU pinning and cache probing"
        log_info "For Windows/WSL2, ensure WSL2 backend is enabled in Docker Desktop"
        exit 1
    fi
}

# Get available CPU cores
get_cpu_cores() {
    nproc
}

# Start the attack lab
start_lab() {
    log_info "Starting DNSSEC cache attack lab..."

    cd "$PROJECT_DIR/docker"

    # Create results directory
    mkdir -p "$PROJECT_DIR/results_cache"

    # Start containers
    log_info "Starting victim (BIND resolver) and attacker containers..."
    docker compose -f docker-compose.cache-attack.yml up -d --build

    # Wait for services
    log_info "Waiting for services to start..."
    sleep 10

    # Verify victim is running
    if docker exec dnssec-victim dig @localhost test-valid-rsa.example A +short &>/dev/null; then
        log_info "Victim resolver is running and responding"
    else
        log_error "Victim resolver is not responding"
        docker logs dnssec-victim
        exit 1
    fi

    # Verify attacker container
    if docker exec dnssec-attacker echo "ready" &>/dev/null; then
        log_info "Attacker container is ready"
    else
        log_error "Attacker container failed to start"
        docker logs dnssec-attacker
        exit 1
    fi

    # Build cache probe
    log_info "Building cache probe tool..."
    docker exec dnssec-attacker bash -c "cd /research/harness && gcc -O2 -o cache_probe cache_probe.c -lpthread"

    log_info "Lab is ready!"
    log_info "To run the attack, execute: $0 attack"
}

# Run the attack
run_attack() {
    log_info "Running cache-based DNSSEC timing attack..."

    CORES=$(get_cpu_cores)
    log_info "Available CPU cores: $CORES"

    if [[ $CORES -lt 2 ]]; then
        log_warn "Less than 2 cores available. Cache attack may not work well."
    fi

    # Run the attack inside attacker container
    docker exec -it dnssec-attacker bash -c "
        cd /research/harness

        echo '=== DNSSEC Cache Attack ==='
        echo 'Victim: victim:53'
        echo 'Attacker: this container'
        echo 'CPU cores: shared (L3 cache contention)'
        echo ''

        # First, test connectivity
        echo '[*] Testing connectivity to victim...'
        dig @victim test-valid-rsa.example A +short
        dig @victim test-valid-ecdsa.example A +short
        dig @victim test-valid-ed25519.example A +short

        # Run cache probe calibration
        echo ''
        echo '[*] Calibrating cache probe...'
        ./cache_probe --standalone --rounds 100 --label baseline --output /research/results/probe_baseline.csv

        # Run the full attack
        echo ''
        echo '[*] Running attack measurements...'
        python3 trigger_attack.py \
            --resolver victim \
            --port 53 \
            --algorithms rsa,ecdsa,ed25519 \
            --rounds 500 \
            --output /research/results

        # Run classifier on results
        echo ''
        echo '[*] Training classifier...'
        python3 /research/analysis/cache_classifier.py \
            --input /research/results/cache_timings.csv \
            --output /research/results \
            --classifier random_forest
    " || true

    # Copy results back to host
    log_info "Results saved to $PROJECT_DIR/results_cache/"
    ls -la "$PROJECT_DIR/results_cache/" 2>/dev/null || log_warn "No results found"
}

# Stop the lab
stop_lab() {
    log_info "Stopping DNSSEC cache attack lab..."
    cd "$PROJECT_DIR/docker"
    docker compose -f docker-compose.cache-attack.yml down
    log_info "Lab stopped"
}

# Clean up everything
clean_lab() {
    log_info "Cleaning up..."
    cd "$PROJECT_DIR/docker"
    docker compose -f docker-compose.cache-attack.yml down --rmi all --volumes
    rm -rf "$PROJECT_DIR/results_cache"
    log_info "Cleanup complete"
}

# Print usage
usage() {
    echo "DNSSEC Cache Attack Lab Setup"
    echo ""
    echo "Usage: $0 {start|attack|stop|clean}"
    echo ""
    echo "Commands:"
    echo "  start   - Start the lab (victim + attacker containers)"
    echo "  attack  - Run the cache-based attack"
    echo "  stop    - Stop the lab containers"
    echo "  clean   - Remove all containers and images"
}

# Main
case "${1:-}" in
    start)
        check_platform
        start_lab
        ;;
    attack)
        run_attack
        ;;
    stop)
        stop_lab
        ;;
    clean)
        clean_lab
        ;;
    *)
        usage
        exit 1
        ;;
esac
