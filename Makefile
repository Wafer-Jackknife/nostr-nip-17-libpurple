# Top-level Makefile for pidgin-nostr-plugin

.PHONY: all clean install nostr-core nostr-purple test

all: nostr-core nostr-purple

nostr-core:
	cd nostr-core && cargo build --release

nostr-purple: nostr-core
	$(MAKE) -C nostr-purple

install: all
	$(MAKE) -C nostr-purple install

clean:
	cd nostr-core && cargo clean
	$(MAKE) -C nostr-purple clean

# Generate a test keypair using nak
test-keypair:
	@echo "Generating test keypair..."
	@SK=$$(nak key generate) && \
	echo "Secret key (hex): $$SK" && \
	echo "nsec: $$(nak encode nsec $$SK)" && \
	echo "Public key (hex): $$(nak key public $$SK)" && \
	echo "npub: $$(nak encode npub $$(nak key public $$SK))"

# Run Pidgin with debug output
run-pidgin:
	@echo "Starting Pidgin with debug output..."
	@pidgin -d

# Show plugin info
info:
	@echo "Plugin location: ~/.purple/plugins/libnostr.dylib"
	@ls -la ~/.purple/plugins/libnostr.dylib 2>/dev/null || echo "Plugin not installed"
