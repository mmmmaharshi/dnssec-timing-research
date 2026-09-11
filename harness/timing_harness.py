#!/usr/bin/env python3
"""
DNSSEC Timing Side-Channel Harness

Measures resolver response times across different DNSSEC validation outcomes
to detect timing side-channels in signature verification.

Usage:
    python timing_harness.py --resolver unbound --outcome valid --samples 10000
    python timing_harness.py --all  # Run all combinations
"""

import argparse
import csv
import os
import statistics
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

try:
    import dns.message
    import dns.name
    import dns.query
    import dns.rdatatype
    import dns.rcode
except ImportError:
    print("ERROR: dnspython required. Install with: pip install dnspython")
    sys.exit(1)


# Resolver configurations
RESOLVERS = {
    "bind": {"host": "127.0.0.1", "port": 15354, "description": "BIND 9 resolver"},
    "unbound": {"host": "127.0.0.1", "port": 15355, "description": "Unbound resolver"},
    "knot": {"host": "127.0.0.1", "port": 15356, "description": "Knot Resolver"},
}

# Test domains for each validation outcome
# These map to zones we've configured on the authoritative server
TEST_DOMAINS = {
    "valid-rsa": {
        "domain": "test.test-valid-rsa.example",
        "description": "Valid RSA-SHA256 signature",
        "expected_rcode": dns.rcode.NOERROR,
        "expected_ad": True,
    },
    "valid-ecdsa": {
        "domain": "test.test-valid-ecdsa.example",
        "description": "Valid ECDSA P-256 signature",
        "expected_rcode": dns.rcode.NOERROR,
        "expected_ad": True,
    },
    "valid-ed25519": {
        "domain": "test.test-valid-ed25519.example",
        "description": "Valid Ed25519 signature",
        "expected_rcode": dns.rcode.NOERROR,
        "expected_ad": True,
    },
    "bogus": {
        "domain": "test.test-bogus.example",
        "description": "Bogus/invalid signature",
        "expected_rcode": dns.rcode.SERVFAIL,
        "expected_ad": False,
    },
    "expired": {
        "domain": "test.test-expired.example",
        "description": "Expired signature",
        "expected_rcode": dns.rcode.SERVFAIL,
        "expected_ad": False,
    },
    "unsigned": {
        "domain": "test.test-unsigned.example",
        "description": "Unsigned zone (no DNSSEC)",
        "expected_rcode": dns.rcode.NOERROR,
        "expected_ad": False,
    },
    "nsec3": {
        "domain": "nonexistent.test-nsec3.example",
        "description": "NSEC3 proof of non-existence",
        "expected_rcode": dns.rcode.NXDOMAIN,
        "expected_ad": True,
    },
}


@dataclass
class TimingResult:
    """Single timing measurement."""
    resolver: str
    outcome: str
    domain: str
    query_time_ns: int
    response_rcode: int
    ad_flag: bool
    timestamp: float
    cache_state: str = "cold"
    error: Optional[str] = None


@dataclass
class TimingStats:
    """Statistics for a set of timing measurements."""
    resolver: str
    outcome: str
    samples: int
    mean_ns: float
    median_ns: float
    stdev_ns: float
    errors: int = 0


class DNSSecTimingHarness:
    """Harness for measuring DNSSEC validation timing."""

    def __init__(self, resolver_name: str, timeout: float = 5.0):
        if resolver_name not in RESOLVERS:
            raise ValueError(f"Unknown resolver: {resolver_name}. Choose from: {list(RESOLVERS.keys())}")

        self.resolver = resolver_name
        self.config = RESOLVERS[resolver_name]
        self.timeout = timeout

    def measure_single_query(self, domain: str, protocol: str = "tcp") -> TimingResult:
        """Send a single DNS query and measure response time."""
        try:
            # Build query
            qname = dns.name.from_text(domain)
            query = dns.message.make_query(qname, dns.rdatatype.A)
            query.flags |= dns.flags.AD  # Request AD bit
            # Set DO bit via EDNS0 to request DNSSEC records
            query.use_edns(edns=0, ednsflags=0x8000, payload=4096)

            # Measure time
            start = time.perf_counter_ns()
            if protocol == "udp":
                response = dns.query.udp(
                    query,
                    self.config["host"],
                    port=self.config["port"],
                    timeout=self.timeout,
                )
            else:
                response = dns.query.tcp(
                    query,
                    self.config["host"],
                    port=self.config["port"],
                    timeout=self.timeout,
                )
            end = time.perf_counter_ns()

            query_time = end - start

            return TimingResult(
                resolver=self.resolver,
                outcome="",  # Filled in by caller
                domain=domain,
                query_time_ns=query_time,
                response_rcode=response.rcode(),
                ad_flag=bool(response.flags & dns.flags.AD),
                timestamp=time.time(),
            )

        except Exception as e:
            return TimingResult(
                resolver=self.resolver,
                outcome="",
                domain=domain,
                query_time_ns=0,
                response_rcode=-1,
                ad_flag=False,
                timestamp=time.time(),
                error=str(e),
            )

    def measure_outcome(
        self,
        outcome_name: str,
        samples: int = 10000,
        warmup: int = 100,
        progress: bool = True,
        cache_state: str = "cold",
        protocol: str = "tcp",
    ) -> List[TimingResult]:
        """Measure timing for a specific validation outcome."""
        if outcome_name not in TEST_DOMAINS:
            raise ValueError(f"Unknown outcome: {outcome_name}")

        test_config = TEST_DOMAINS[outcome_name]
        domain = test_config["domain"]

        results = []

        # Warmup queries (not recorded)
        if progress:
            print(f"  Warming up ({warmup} queries)...", end="", flush=True)
        for _ in range(warmup):
            self.measure_single_query(domain, protocol=protocol)
        if progress:
            print(" done")

        # Actual measurements
        if progress:
            print(f"  Collecting {samples} samples ({cache_state} cache, {protocol.upper()})...", end="", flush=True)

        for i in range(samples):
            result = self.measure_single_query(domain, protocol=protocol)
            result.outcome = outcome_name
            result.cache_state = cache_state
            results.append(result)

            if progress and (i + 1) % 1000 == 0:
                print(f" {i + 1}/{samples}", end="", flush=True)

        if progress:
            print(" done")

        return results

    def measure_cache_states(
        self,
        outcome_name: str,
        samples: int = 1000,
        progress: bool = True,
    ) -> List[TimingResult]:
        """Measure timing across cold, warm, and hot cache states."""
        if outcome_name not in TEST_DOMAINS:
            raise ValueError(f"Unknown outcome: {outcome_name}")

        test_config = TEST_DOMAINS[outcome_name]
        domain = test_config["domain"]
        all_results = []

        # Cold cache: first query (cache miss)
        if progress:
            print("  Cold cache (first query)...")
        for _ in range(5):
            self.measure_single_query(domain)  # Flush cache
        result = self.measure_single_query(domain)
        result.outcome = outcome_name
        result.cache_state = "cold"
        all_results.append(result)

        # Warm cache: second query (likely cache hit)
        if progress:
            print("  Warm cache (second query)...")
        for _ in range(samples):
            result = self.measure_single_query(domain)
            result.outcome = outcome_name
            result.cache_state = "warm"
            all_results.append(result)

        # Hot cache: many subsequent queries
        if progress:
            print("  Hot cache (subsequent queries)...")
        for _ in range(samples):
            result = self.measure_single_query(domain)
            result.outcome = outcome_name
            result.cache_state = "hot"
            all_results.append(result)

        return all_results

    @staticmethod
    def compute_stats(results: List[TimingResult]) -> TimingStats:
        """Compute statistics from timing results."""
        valid_times = [r.query_time_ns for r in results if r.error is None and r.query_time_ns > 0]
        errors = len(results) - len(valid_times)

        if not valid_times:
            return TimingStats(
                resolver=results[0].resolver if results else "unknown",
                outcome=results[0].outcome if results else "unknown",
                samples=0,
                mean_ns=0,
                median_ns=0,
                stdev_ns=0,
                errors=errors,
            )

        n = len(valid_times)
        return TimingStats(
            resolver=results[0].resolver,
            outcome=results[0].outcome,
            samples=n,
            mean_ns=statistics.mean(valid_times),
            median_ns=statistics.median(valid_times),
            stdev_ns=statistics.stdev(valid_times) if n > 1 else 0,
            errors=errors,
        )


def save_results(results: List[TimingResult], filepath: str) -> None:
    """Save timing results to CSV."""
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "resolver", "outcome", "domain", "cache_state", "query_time_ns",
            "response_rcode", "ad_flag", "timestamp", "error"
        ])
        for r in results:
            writer.writerow([
                r.resolver, r.outcome, r.domain, r.cache_state,
                r.query_time_ns, r.response_rcode, r.ad_flag,
                r.timestamp, r.error or ""
            ])


def apply_wan_delay(resolver_name: str, delay_ms: float) -> None:
    """Apply WAN delay to resolver container using tc netem."""
    container_map = {
        "bind": "dnssec-bind",
        "unbound": "dnssec-unbound",
        "knot": "dnssec-knot",
    }
    container = container_map.get(resolver_name)
    if not container:
        print(f"Warning: Unknown resolver {resolver_name}, cannot apply WAN delay")
        return

    print(f"Applying {delay_ms}ms WAN delay to {container}...")
    # Add network delay using tc netem
    cmd = (
        f"docker exec --privileged {container} "
        f"tc qdisc add dev eth0 root netem delay {delay_ms}ms"
    )
    os.system(cmd)
    print(f"  WAN delay applied to {container}")


def remove_wan_delay(resolver_name: str) -> None:
    """Remove WAN delay from resolver container."""
    container_map = {
        "bind": "dnssec-bind",
        "unbound": "dnssec-unbound",
        "knot": "dnssec-knot",
    }
    container = container_map.get(resolver_name)
    if not container:
        return

    print(f"Removing WAN delay from {container}...")
    cmd = (
        f"docker exec --privileged {container} "
        f"tc qdisc del dev eth0 root"
    )
    os.system(cmd)


def run_all_measurements(
    samples: int = 10000,
    output_dir: str = "../results",
    protocol: str = "tcp",
) -> Tuple[List[TimingResult], List[TimingStats]]:
    """Run all resolver × outcome combinations."""
    all_results = []
    all_stats = []

    for resolver_name in RESOLVERS:
        print(f"\n{'='*60}")
        print(f"Resolver: {RESOLVERS[resolver_name]['description']}")
        print(f"{'='*60}")

        harness = DNSSecTimingHarness(resolver_name)

        for outcome_name, test_config in TEST_DOMAINS.items():
            print(f"\nOutcome: {outcome_name} ({test_config['description']})")
            print(f"Domain: {test_config['domain']}")

            results = harness.measure_outcome(outcome_name, samples=samples, protocol=protocol)
            stats = DNSSecTimingHarness.compute_stats(results)

            all_results.extend(results)
            all_stats.append(stats)

            print(f"  Mean: {stats.mean_ns/1e6:.3f} ms")
            print(f"  Median: {stats.median_ns/1e6:.3f} ms")
            print(f"  Stdev: {stats.stdev_ns/1e6:.3f} ms")
            print(f"  Errors: {stats.errors}")

    # Save results
    suffix = f"_{protocol}" if protocol != "tcp" else ""
    save_results(all_results, os.path.join(output_dir, f"raw_timings{suffix}.csv"))

    print(f"\n{'='*60}")
    print(f"Results saved to {output_dir}/")
    print(f"{'='*60}")

    return all_results, all_stats


def main():
    parser = argparse.ArgumentParser(
        description="DNSSEC Timing Side-Channel Harness"
    )
    parser.add_argument(
        "--resolver",
        choices=list(RESOLVERS.keys()),
        help="Resolver to test",
    )
    parser.add_argument(
        "--outcome",
        choices=list(TEST_DOMAINS.keys()),
        help="Validation outcome to measure",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=10000,
        help="Number of samples (default: 10000)",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=100,
        help="Number of warmup queries (default: 100)",
    )
    parser.add_argument(
        "--output",
        default="../results",
        help="Output directory (default: ../results)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all resolver × outcome combinations",
    )
    parser.add_argument(
        "--cache-mode",
        action="store_true",
        help="Test cold/warm/hot cache states",
    )
    parser.add_argument(
        "--protocol",
        choices=["tcp", "udp"],
        default="tcp",
        help="Protocol to use (default: tcp)",
    )
    parser.add_argument(
        "--wan-delay",
        type=float,
        default=0,
        help="Simulate WAN delay in ms (uses tc netem on resolver container)",
    )

    args = parser.parse_args()

    # Apply WAN delay if requested
    if args.wan_delay > 0:
        apply_wan_delay(args.resolver, args.wan_delay)

    if args.all:
        run_all_measurements(samples=args.samples, output_dir=args.output, protocol=args.protocol)
    elif args.cache_mode and args.resolver:
        run_cache_state_measurements(args.resolver, args.samples, args.output)
    elif args.resolver and args.outcome:
        harness = DNSSecTimingHarness(args.resolver)
        results = harness.measure_outcome(
            args.outcome,
            samples=args.samples,
            warmup=args.warmup,
            protocol=args.protocol,
        )
        stats = DNSSecTimingHarness.compute_stats(results)

        print(f"\nResults for {args.resolver} / {args.outcome} ({args.protocol.upper()}):")
        print(f"  Samples: {stats.samples}")
        print(f"  Mean: {stats.mean_ns/1e6:.3f} ms")
        print(f"  Median: {stats.median_ns/1e6:.3f} ms")
        print(f"  Stdev: {stats.stdev_ns/1e6:.3f} ms")
        print(f"  Errors: {stats.errors}")

        # Save single result
        suffix = f"_{args.protocol}" if args.protocol != "tcp" else ""
        save_results(results, os.path.join(args.output, f"{args.resolver}{suffix}_{args.outcome}.csv"))
    else:
        parser.print_help()
        print("\nExamples:")
        print("  python timing_harness.py --resolver unbound --outcome valid-rsa --samples 5000")
        print("  python timing_harness.py --all --samples 10000")
        print("  python timing_harness.py --resolver bind --cache-mode --samples 1000")
        print("  python timing_harness.py --resolver bind --outcome valid-rsa --protocol udp")
        print("  python timing_harness.py --resolver bind --outcome valid-rsa --wan-delay 50")


def run_cache_state_measurements(
    resolver_name: str,
    samples: int,
    output_dir: str,
) -> None:
    """Run cache state measurements for all outcomes."""
    harness = DNSSecTimingHarness(resolver_name)
    all_results = []

    for outcome_name in ["valid-rsa", "valid-ecdsa", "valid-ed25519"]:
        print(f"\nOutcome: {outcome_name}")
        results = harness.measure_cache_states(outcome_name, samples=samples)
        all_results.extend(results)

        # Print summary by cache state
        for state in ["cold", "warm", "hot"]:
            state_results = [r for r in results if r.cache_state == state and r.error is None]
            if state_results:
                times = [r.query_time_ns for r in state_results]
                mean_ms = statistics.mean(times) / 1e6
                print(f"  {state}: {mean_ms:.3f} ms (n={len(times)})")

    save_results(all_results, os.path.join(output_dir, f"cache_states_{resolver_name}.csv"))
    print(f"\nResults saved to {output_dir}/cache_states_{resolver_name}.csv")


if __name__ == "__main__":
    main()
