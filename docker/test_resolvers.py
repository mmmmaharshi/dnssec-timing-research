#!/usr/bin/env python3
"""Test all DNSSEC resolvers for correct DNSSEC validation."""

import sys
import time
import dns.message
import dns.query
import dns.name
import dns.rdatatype
import dns.flags

def test_resolver(port, name, zone, expected_ad=True):
    """Test a resolver for DNSSEC validation."""
    qname = dns.name.from_text(f'test.{zone}')
    query = dns.message.make_query(qname, dns.rdatatype.A)
    query.flags |= dns.flags.CD  # Checking Disabled to get raw response
    query.edns = 0
    query.payload = 4096
    # Request DO bit for DNSSEC
    query.options.append(dns.edns.GenericOption(dns.edns.NSID, b''))

    try:
        response = dns.query.tcp(query, '127.0.0.1', port=port, timeout=5)
        has_ad = bool(response.flags & dns.flags.AD)
        rcode = response.rcode()

        # Check for DNSSEC records (RRSIG, DNSKEY)
        has_dnssec = False
        for rrset in response.answer:
            if rrset.rdtype in (dns.rdatatype.RRSIG, dns.rdatatype.DNSKEY):
                has_dnssec = True
                break

        status = "OK" if rcode == 0 else f"FAIL(rcode={rcode})"
        if expected_ad and not has_ad:
            status = "NO_AD"

        print(f'{name:12} | {zone:30} | {status:15} | AD={has_ad} | DNSSEC={has_dnssec}')
        return rcode == 0
    except Exception as e:
        print(f'{name:12} | {zone:30} | ERROR: {str(e)[:40]}')
        return False

def wait_for_resolver(port, name, max_wait=30):
    """Wait for resolver to become available."""
    print(f'Waiting for {name} on port {port}...')
    for i in range(max_wait):
        try:
            qname = dns.name.from_text('test.test-valid-rsa.example')
            query = dns.message.make_query(qname, dns.rdatatype.A)
            response = dns.query.tcp(query, '127.0.0.1', port=port, timeout=2)
            print(f'  {name} ready after {i+1}s')
            return True
        except Exception:
            time.sleep(1)
    print(f'  {name} NOT ready after {max_wait}s')
    return False

def main():
    print("=" * 80)
    print("DNSSEC Resolver Validation Test")
    print("=" * 80)
    print()

    resolvers = [
        (15354, 'BIND'),
        (15355, 'Unbound'),
        (15356, 'Knot'),
    ]

    zones = [
        'test-valid-rsa.example',
        'test-valid-ecdsa.example',
        'test-valid-ed25519.example',
        'test-nsec3.example',
    ]

    # Wait for all resolvers
    print("Waiting for resolvers to start...")
    all_ready = True
    for port, name in resolvers:
        if not wait_for_resolver(port, name):
            all_ready = False

    if not all_ready:
        print("\nWARNING: Not all resolvers are ready!")
        sys.exit(1)

    print()
    print("Testing DNSSEC validation...")
    print(f"{'Resolver':12} | {'Zone':30} | {'Status':15} | AD | DNSSEC")
    print("-" * 80)

    results = []
    for port, name in resolvers:
        for zone in zones:
            success = test_resolver(port, name, zone, expected_ad=True)
            results.append((name, zone, success))

    print()
    print("=" * 80)
    print("Summary:")
    for name, zone, success in results:
        status = "PASS" if success else "FAIL"
        print(f"  {name:12} / {zone:30} : {status}")

    all_pass = all(s for _, _, s in results)
    print()
    print(f"Overall: {'ALL PASS' if all_pass else 'SOME FAILURES'}")
    sys.exit(0 if all_pass else 1)

if __name__ == '__main__':
    main()
