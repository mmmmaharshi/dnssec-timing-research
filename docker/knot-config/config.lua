-- Knot Resolver configuration for DNSSEC timing research
-- Docker image: cznic/knot-resolver:latest (v6.x)

-- Network configuration
net.listen('0.0.0.0', 53, { kind = 'dns' })

-- DNSSEC validation with trust anchors for our test zones
-- Disable root TA management (isolated Docker environment)
trust_anchors.manage_root_ta(false)

-- Load each trust anchor file separately (DS record format)
trust_anchors.add_file('/etc/knot-resolver/trust-anchors/test-valid-rsa.example')
trust_anchors.add_file('/etc/knot-resolver/trust-anchors/test-valid-ecdsa.example')
trust_anchors.add_file('/etc/knot-resolver/trust-anchors/test-valid-ed25519.example')
trust_anchors.add_file('/etc/knot-resolver/trust-anchors/test-nsec3.example')

-- Forward ALL queries to our authoritative server
policy.add(policy.all(policy.FORWARD('172.20.0.10')))
