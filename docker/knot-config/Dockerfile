FROM cznic/knot-resolver:latest

# Copy our Lua configuration
COPY knot-config/kresd.conf /config/kresd.conf

# Copy trust anchor DS record files
COPY trust-anchors/ /etc/knot-resolver/trust-anchors/

# Run kresd directly with Lua config
ENTRYPOINT ["kresd", "-c", "/config/kresd.conf", "-n"]
