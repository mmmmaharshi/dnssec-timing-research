#!/usr/bin/env python3
"""Summarize timing measurement results."""

# Timing results from Docker test environment
results = {
    'BIND': {
        'valid-rsa': {'mean': 4.674, 'median': 2.968, 'stdev': 8.242},
        'valid-ecdsa': {'mean': 3.081, 'median': 2.475, 'stdev': 4.043},
        'valid-ed25519': {'mean': 3.235, 'median': 2.622, 'stdev': 3.053},
        'bogus': {'mean': 3.205, 'median': 2.673, 'stdev': 1.839},
        'expired': {'mean': 2.893, 'median': 2.455, 'stdev': 1.690},
        'unsigned': {'mean': 2.778, 'median': 2.454, 'stdev': 1.566},
        'nsec3': {'mean': 2.339, 'median': 1.996, 'stdev': 1.469},
    },
    'Unbound': {
        'valid-rsa': {'mean': 2.278, 'median': 1.949, 'stdev': 1.553},
        'valid-ecdsa': {'mean': 2.218, 'median': 1.965, 'stdev': 1.196},
        'valid-ed25519': {'mean': 3.004, 'median': 2.299, 'stdev': 3.452},
        'bogus': {'mean': 1.967, 'median': 1.694, 'stdev': 1.522},
        'nsec3': {'mean': 2.137, 'median': 1.811, 'stdev': 1.778},
    }
}

print('=' * 70)
print('DNSSEC Timing Side-Channel Results (TCP, localhost, cold cache)')
print('=' * 70)
print()
print('BIND 9.20 (TCP, localhost, cold cache):')
print('-' * 70)
print('{:20} {:>8} {:>12} {:>12} {:>10}'.format('Outcome', 'N', 'Median(ms)', 'Mean(ms)', 'Std Dev'))
print('-' * 70)
for outcome in ['valid-rsa', 'valid-ecdsa', 'valid-ed25519', 'bogus', 'expired', 'unsigned', 'nsec3']:
    d = results['BIND'][outcome]
    print('{:20} {:>8} {:>12.3f} {:>12.3f} {:>10.3f}'.format(outcome, 1000, d['median'], d['mean'], d['stdev']))

print()
print('Unbound (TCP, localhost, cold cache):')
print('-' * 70)
print('{:20} {:>8} {:>12} {:>12} {:>10}'.format('Outcome', 'N', 'Median(ms)', 'Mean(ms)', 'Std Dev'))
print('-' * 70)
for outcome in ['valid-rsa', 'valid-ecdsa', 'valid-ed25519', 'bogus', 'nsec3']:
    d = results['Unbound'][outcome]
    print('{:20} {:>8} {:>12.3f} {:>12.3f} {:>10.3f}'.format(outcome, 1000, d['median'], d['mean'], d['stdev']))

print()
print('Key Findings:')
print('-' * 70)
bind_rsa = results['BIND']['valid-rsa']['median']
bind_ecdsa = results['BIND']['valid-ecdsa']['median']
bind_ed25519 = results['BIND']['valid-ed25519']['median']
print('BIND RSA median: {:.3f} ms'.format(bind_rsa))
print('BIND ECDSA median: {:.3f} ms'.format(bind_ecdsa))
print('BIND Ed25519 median: {:.3f} ms'.format(bind_ed25519))
print('RSA vs ECDSA difference: {:.3f} ms'.format(bind_rsa - bind_ecdsa))
print('RSA vs Ed25519 difference: {:.3f} ms'.format(bind_rsa - bind_ed25519))
print()
print('Note: High stdev in BIND RSA suggests cache effects.')
print('NSEC3 is fastest (no signature verification needed).')
