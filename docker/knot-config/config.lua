-- Knot Resolver configuration for DNSSEC timing research

-- Network configuration
net.listen('0.0.0.0', 53, { kind = 'dns' })

-- DNSSEC validation with our trust anchors
trust_anchors.add_file('/etc/knot-resolver/trust-anchors.txt')

-- Single worker for consistent timing
workers(1)

-- Disable caching to isolate validation timing
cache.size = 0
cache.storage = 'none'

-- Forward to authoritative server
policy.add(policy.all(policy.FORWARD('172.20.0.10')))

-- Logging
log_level('error')
