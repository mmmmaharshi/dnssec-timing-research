#!/usr/bin/env python3
"""Extract DNSKEY records from signed zones for unbound trust anchors."""

import re
import os

zones_dir = r"C:\Users\manoh\OneDrive\Desktop\dnssec-timing-research\docker"
zones = ['test-valid-rsa.example', 'test-valid-ecdsa.example', 'test-valid-ed25519.example', 'test-nsec3.example']

output_path = os.path.join(zones_dir, 'trust-anchors-unbound.txt')
with open(output_path, 'w') as out:
    for zone in zones:
        filepath = os.path.join(zones_dir, f'{zone}.zone.signed')
        if not os.path.exists(filepath):
            print(f"Warning: {filepath} not found")
            continue
        with open(filepath) as f:
            content = f.read()
        # Find KSK DNSKEY records (257)
        for match in re.finditer(r'(\d+)\s+DNSKEY\s+257\s+3\s+(\d+)\s*\(([^)]+)\)', content):
            ttl, alg, key_data = match.group(1), match.group(2), match.group(3).replace(' ', '').replace('\n', '')
            out.write(f'{zone}. {ttl} IN DNSKEY 257 3 {alg} {key_data}\n')

print(f"Trust anchors extracted to {output_path}")
