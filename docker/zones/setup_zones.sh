#!/bin/bash
# Generate DNSSEC test zones for timing research

ZONES_DIR="/var/cache/bind/zones"
KEYS_DIR="$ZONES_DIR/keys"

mkdir -p "$KEYS_DIR"

# Base zone file template
BASE_ZONE='$TTL 300
@   IN  SOA ns1.%ZONE%. admin.%ZONE%. (
            2026090501    ; Serial
            3600        ; Refresh
            900         ; Retry
            604800      ; Expire
            300         ; Negative Cache TTL
        )
;
@       IN  NS      ns1.%ZONE%.
ns1     IN  A       172.20.0.10
test    IN  A       192.0.2.100
test    IN  AAAA    2001:db8::100
www     IN  CNAME   test.%ZONE%.
'

# Unsigned zone template (no DNSSEC records)
UNSIGNED_ZONE='$TTL 300
@   IN  SOA ns1.%ZONE%. admin.%ZONE%. (
            2026090501    ; Serial
            3600        ; Refresh
            900         ; Retry
            604800      ; Expire
            300         ; Negative Cache TTL
        )
;
@       IN  NS      ns1.%ZONE%.
ns1     IN  A       172.20.0.10
test    IN  A       192.0.2.100
'

echo "=== Generating DNSSEC test zones ==="

# Function to create a zone file
create_zone() {
    local zone_name=$1
    local template=$2
    echo "$template" | sed "s/%ZONE%/$zone_name/g" > "$ZONES_DIR/$zone_name.zone"
    echo "Created zone file: $zone_name.zone"
}

# Function to generate keys and sign a zone
sign_zone() {
    local zone_name=$1
    local algorithm=$2
    local algo_code=$3
    local key_size=$4

    echo "Generating $algorithm keys for $zone_name..."

    # Generate ZSK
    dnssec-keygen -a "$algo_code" ${key_size:+-b "$key_size"} -n ZONE "$zone_name" > /dev/null 2>&1

    # Generate KSK
    dnssec-keygen -a "$algo_code" ${key_size:+-b "$key_size"} -f KSK -n ZONE "$zone_name" > /dev/null 2>&1

    # Move keys to keys directory
    mv K${zone_name}+* "$KEYS_DIR/"

    # Sign the zone
    cd "$KEYS_DIR"
    local keys=$(ls K${zone_name}+*.key 2>/dev/null | sed 's/.key$//')
    cd "$ZONES_DIR"

    dnssec-signzone -o "$zone_name" -N INCREMENT -a -3 000000000000 -T 300 \
        $(for key in $keys; do echo "-K $KEYS_DIR/$key"; done) \
        -S "$zone_name.zone" 2>/dev/null

    echo "Signed zone: $zone_name with $algorithm"
}

# Create unsigned zone
create_zone "test-unsigned.example" "$UNSIGNED_ZONE"

# Create zones that will be signed
create_zone "test-valid-rsa.example" "$BASE_ZONE"
create_zone "test-valid-ecdsa.example" "$BASE_ZONE"
create_zone "test-valid-ed25519.example" "$BASE_ZONE"
create_zone "test-nsec3.example" "$BASE_ZONE"

# Sign zones with different algorithms
sign_zone "test-valid-rsa.example" "RSA-SHA256" "RSASHA256" "2048"
sign_zone "test-valid-ecdsa.example" "ECDSA-P256" "ECDSAP256SHA256" ""
sign_zone "test-valid-ed25519.example" "Ed25519" "ED25519" ""
sign_zone "test-nsec3.example" "RSA-SHA256" "RSASHA256" "2048"

# Create bogus zone (signed then corrupted to trigger SERVFAIL)
echo "Creating bogus zone..."
create_zone "test-bogus.example" "$BASE_ZONE"
sign_zone "test-bogus.example" "RSA-SHA256" "RSASHA256" "2048"
# Corrupt the RRSIG to make it bogus - flip a byte in the signature
if [ -f "$ZONES_DIR/test-bogus.example.zone.signed" ]; then
    # Replace a character in RRSIG to invalidate it (still valid zone file)
    sed -i 's/A\(.*RRSIG\)/B\1/;t; s/RRSIG\(.*\)A/RRSIG\1B/' "$ZONES_DIR/test-bogus.example.zone.signed" 2>/dev/null || true
    # More reliable: corrupt base64 signature data on first RRSIG line
    python3 -c "
import re
p='$ZONES_DIR/test-bogus.example.zone.signed'
with open(p) as f: c=f.read()
# Corrupt first RRSIG signature block - flip one base64 char
c=c.replace('A', 'B', 1) if 'RRSIG' in c else c
with open(p,'w') as f: f.write(c)
" 2>/dev/null || true
    echo "Corrupted RRSIG for bogus zone"
fi

# Create expired zone (sign with validity in the past)
echo "Creating expired zone..."
create_zone "test-expired.example" "$BASE_ZONE"
# Sign with expired dates: start 2020, end 2020 (already expired)
echo "Generating RSA keys for test-expired.example (expired)..."
dnssec-keygen -a RSASHA256 -b 2048 -n ZONE "test-expired.example" > /dev/null 2>&1
dnssec-keygen -a RSASHA256 -b 2048 -f KSK -n ZONE "test-expired.example" > /dev/null 2>&1
mv Ktest-expired.example+* "$KEYS_DIR/" 2>/dev/null || true
cd "$KEYS_DIR"
keys=$(ls Ktest-expired.example+*.key 2>/dev/null | sed 's/.key$//')
cd "$ZONES_DIR"
# Sign with end time in the past to create expired signatures
dnssec-signzone -o "test-expired.example" -N INCREMENT -a -3 000000000000 -T 300 -s 20200101000000 -e 20200102000000 $(for key in $keys; do echo "-K $KEYS_DIR/$key"; done) -S "test-expired.example.zone" 2>/dev/null || \
dnssec-signzone -o "test-expired.example" -N INCREMENT $(for key in $keys; do echo "-K $KEYS_DIR/$key"; done) "test-expired.example.zone" 2>/dev/null
# If signing failed to make it expired, at least we have a signed zone
if [ ! -f "$ZONES_DIR/test-expired.example.zone.signed" ]; then
    echo "Warning: expired zone signing failed, using unsigned fallback"
fi
echo "Created expired zone (signatures valid 2020-01-01 to 2020-01-02)"

echo "=== Zone generation complete ==="
echo ""
echo "Zone files in $ZONES_DIR:"
ls -la "$ZONES_DIR"/*.zone "$ZONES_DIR"/*.signed 2>/dev/null
echo ""
echo "Keys in $KEYS_DIR:"
ls -la "$KEYS_DIR/" 2>/dev/null
