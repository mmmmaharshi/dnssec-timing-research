#!/usr/bin/env python3
"""Test all DNSSEC resolvers."""

import dns.message
import dns.query
import dns.name
import dns.rdatatype

qname = dns.name.from_text('test.test-valid-rsa.example')
query = dns.message.make_query(qname, dns.rdatatype.A)

for port, name in [(15354, 'BIND'), (15355, 'Unbound'), (15356, 'Knot')]:
    try:
        response = dns.query.tcp(query, '127.0.0.1', port=port, timeout=5)
        print(f'{name}: rcode={response.rcode()}, flags={response.flags}')
    except Exception as e:
        print(f'{name}: ERROR - {e}')
