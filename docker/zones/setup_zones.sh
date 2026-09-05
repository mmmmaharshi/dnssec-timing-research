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

# Create bogus zone (intentionally broken)
echo "Creating bogus zone..."
BOGUS_ZONE='$TTL 300
@   IN  SOA ns1.test-bogus.example. admin.test-bogus.example. (
            2026090501    ; Serial
            3600        ; Refresh
            900         ; Retry
            604800      ; Expire
            300         ; Negative Cache TTL
        )
;
@       IN  NS      ns1.test-bogus.example.
ns1     IN  A       172.20.0.10
test    IN  A       192.0.2.100
'
echo "$BOGUS_ZONE" > "$ZONES_DIR/test-bogus.example.zone"

# Create expired zone
echo "Creating expired zone..."
EXPIRED_ZONE='$TTL 300
@   IN  SOA ns1.test-expired.example. admin.test-expired.example. (
            2026090501    ; Serial
            3600        ; Refresh
            900         ; Retry
            604800      ; Expire
            300         ; Negative Cache TTL
        )
;
@       IN  NS      ns1.test-expired.example.
ns1     IN  A       172.20.0.10
test    IN  A       192.0.2.100
'
echo "$EXPIRED_ZONE" > "$ZONES_DIR/test-expired.example.zone"

echo "=== Zone generation complete ==="
echo ""
echo "Zone files in $ZONES_DIR:"
ls -la "$ZONES_DIR"/*.zone "$ZONES_DIR"/*.signed 2>/dev/null
echo ""
echo "Keys in $KEYS_DIR:"
ls -la "$KEYS_DIR/" 2>/dev/null
