# Pidgin Nostr Plugin

A libpurple protocol plugin that enables NIP-17 private direct messaging over the Nostr protocol.

Brought to you by the [Cathouse Propeller](http://6vhvsk7ximifkmnsv74ataoiit37lmpp2fmqkxcojdwf7dqe6ls22qad.onion/)

## What it does

- NIP-17 DMs: Send and receive end-to-end encrypted direct messages using the NIP-17 gift-wrap protocol
- NIP-44 Encryption: Modern ChaCha20-Poly1305 based encryption
- Identity Stuff: Generate a new keypair or bring an existing nsec


## Installation

### Pre-built Binaries (Recommended)

Download the latest release from [GitHub Releases](https://github.com/Wafer-Jackknife/nostr-nip-17-libpurple/releases):

#### Linux (including Tails)

```bash
# 1. Install Pidgin and dependencies (if not already installed)
sudo apt install pidgin libpurple0t64 libglib2.0-0

# 2. Create the plugins directory if it doesn't exist
mkdir -p ~/.purple/plugins

# 3. Download and install the plugin
# Choose the appropriate build:
# - libnostr-linux-x86_64.so (Ubuntu 24.04+ / Debian 13+, including Tails 7.x)
# - libnostr-linux-22.04.so (Ubuntu 22.04+ / Debian 12+ for maximum compatibility)

cp libnostr-linux-x86_64.so ~/.purple/plugins/libnostr.so

# 4. Start Pidgin
pidgin
```

**Note for Tails users**: Use the Ubuntu 24.04+ build (`libnostr-linux-x86_64.so`) as it's compatible with Debian 13.

#### macOS

**Currently not supported in releases - feel free to build it yourself**

```bash
# 1. Install Pidgin and dependencies
brew install pidgin purple glib

# 2. Create the plugins directory
mkdir -p ~/.purple/plugins

# 3. Install the plugin
cp libnostr-macos.dylib ~/.purple/plugins/libnostr.so

# 4. Start Pidgin
pidgin
```

### Build from Source

If you need a different version or want the latest development code:

#### Linux (Debian/Ubuntu/Tails)

```bash
# 1. Install build dependencies
sudo apt install pidgin libpurple-dev pkg-config build-essential git

# 2. Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# 3. Clone and build
git clone https://github.com/Wafer-Jackknife/nostr-nip-17-libpurple.git
cd nostr-nip-17-libpurple
make

# 4. Install the plugin
make install

# 5. Start Pidgin
pidgin
```

#### macOS

```bash
# 1. Install dependencies
brew install pidgin purple glib pkg-config gettext

# 2. Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# 3. Clone and build
git clone https://github.com/Wafer-Jackknife/nostr-nip-17-libpurple.git
cd nostr-nip-17-libpurple
make

# 4. Install the plugin
make install

# 5. Start Pidgin
pidgin
```

The plugin will be installed to `~/.purple/plugins/libnostr.so`.

## Usage

1. Start Pidgin
2. Go to Accounts → Manage Accounts → Add
3. Select "Nostr" as the protocol
4. Configure the account:
   - **Username**: Just put anything here, it will get stomped out by your npub (either the one you brought or one that gets generated for you)
   - **Password**: Enter your nsec (private key) in bech32 or hex format
	- Make sure "remember password" is checked.
   - OR enable "Generate new keypair" in Advanced options to generate a new keypair. You might still have to enter _something_ in **Username** when you do this - it'll get replaced with your npub
   - Add a local alias so you can recognize it - this is just for display in Pidgin, maybe you want to use your NIP-05 leader
5. Click "Add"

### Account Options

In **Accounts > Manage Accounts > Modify > Advanced**:

- Relays: Comma-separated list of relay WebSocket URLs
  - Default: `wss://relay.damus.io,wss://nos.lol,wss://relay.nostr.band`
- Generate new keypair: If enabled, creates a new Nostr identity on first login. don't fuck with this if you used an existing npub, I don't know what'll happen.
- History window (days): Number of days of message history to fetch (default: 30) - _not yet editable!_
- Max messages to fetch: Maximum messages to retrieve per conversation (default: 100) - _not yet editable!_

### Sending Messages

To send a message to someone:
1. Buddies -> New Instant Message
2. Enter the recipient's public key (npub or hex format)
3. Type your message and send

### Message History

When you connect, the plugin automatically fetches your recent message history from the relays. This includes:
- Messages you've received
- Messages you've sent (via NIP-17 self-copies)

NIP-17 "self-copies" are a little weird. This is how you see the messages _you_ sent in the DM. Sorting is weird, too, since the timestamp is inside the giftwrap - both of these are probably the reason most nostr DM clients are buggy with old messages and ordering. We did our best here...

Messages are sorted by timestamp and displayed in the conversation window. The history is limited to the last 30 days and 100 messages by default (visible in Advanced settings). Because of these two things, you might see weird inconsistencies in historical message display. If you test between two of your own accounts you can probably convince yourself it works correctly even if it often looks funny after the app closes and re-opens.

If you've got a better solution, plesae for the love of god open a PR.

## Architecture

```
┌─────────────────────────────────────────┐
│              Pidgin / Finch             │
├─────────────────────────────────────────┤
│              libpurple 2.x              │
├─────────────────────────────────────────┤
│          nostr-purple (C plugin)        │
│  - Protocol implementation              │
│  - GLib main loop integration           │
├─────────────────────────────────────────┤
│          nostr-core (Rust + C FFI)      │
│  - Wraps rust-nostr/nostr-sdk           │
│  - NIP-17, NIP-44, NIP-59               │
│  - Relay pool management                │
└─────────────────────────────────────────┘
```

## Project Structure

```
pidgin-nostr-plugin/
├── nostr-core/           # Rust library with C bindings
│   ├── src/
│   │   ├── lib.rs        # FFI exports
│   │   └── signaling.rs  # GLib event loop integration
│   ├── include/
│   │   └── nostr_core.h  # Generated C header
│   └── Cargo.toml
├── nostr-purple/         # libpurple protocol plugin
│   ├── src/
│   │   └── nostr.c       # Plugin implementation
│   └── Makefile
├── Makefile              # Top-level build
└── README.md
```

## Supported NIPs

- [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md): Basic protocol
- [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md): Private Direct Messages
- [NIP-19](https://github.com/nostr-protocol/nips/blob/master/19.md): bech32-encoded entities (npub, nsec)
- [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md): Encrypted Payloads
- [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md): Gift Wrap

## Current Limitations

- History settings in Advanced tab are display-only (changing them doesn't take effect yet)
- No local message storage - history is always fetched from relays on login
- No support for group chats (NIP-17 is for 1:1 DMs only)
	- One day we'd like to extract the basic nostr stuff from this into its own lib/plugin, and build a group chat plugin off that.
- Relay management is manual and doesn't pull from your profile
- In fact, we hardly do anything with profiles. Probably best to keep this simple

## Troubleshooting

### Plugin doesn't appear in Pidgin

1. Check that the plugin is installed: `ls ~/.purple/plugins/libnostr.*`
2. Run Pidgin with debug output: `pidgin -d`
3. Look for "nostr" in the debug output

### Connection issues

1. Check your relay URLs are correct (must start with `wss://` or `ws://`)
2. Try different relays
3. Check debug output for error messages

### Key format issues

- nsec format: `nsec1...` (bech32)
- hex format: 64 character hex string

## Development

### Generating a test keypair

```bash
# Using nak
nak key generate
```

### Running Pidgin with debug output

```bash
make run-pidgin
# or
pidgin -d
```

## Credits

Built on:
- [rust-nostr/nostr-sdk](https://github.com/rust-nostr/nostr) - Rust Nostr implementation
- [libpurple](https://developer.pidgin.im/) - IM library from Pidgin
