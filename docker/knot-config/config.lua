-- Knot Resolver configuration for DNSSEC timing research
-- Docker image: cznic/knot-resolver:latest
--
-- This is the active configuration file (mounted as kresd.conf)

-- Network configuration
net.listen('0.0.0.0', 53, { kind = 'dns' })

-- DNSSEC validation with trust anchors for our test zones
-- Load each trust anchor file separately
trust_anchors.add_file('/etc/knot-resolver/trust-anchors/test-valid-rsa.example')
trust_anchors.add_file('/etc/knot-resolver/trust-anchors/test-valid-ecdsa.example')
trust_anchors.add_file('/etc/knot-resolver/trust-anchors/test-valid-ed25519.example')
trust_anchors.add_file('/etc/knot-resolver/trust-anchors/test-nsec3.example')

-- Single worker for consistent timing
workers(1)

-- Disable caching to isolate validation timing
cache.size = 0
cache.storage = 'none'

-- Forward to authoritative server
policy.add(policy.all(policy.FORWARD('172.20.0.10')))

-- Logging (reduce noise for timing measurements)
log_level('error')
