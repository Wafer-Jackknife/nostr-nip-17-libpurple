//! Nostr client library with C FFI bindings
//!
//! This library wraps nostr-sdk to provide NIP-17 private direct messaging
//! functionality for libpurple plugins.

use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::sync::{Arc, Mutex};

use nostr_sdk::prelude::*;
use tokio::runtime::Runtime;

mod error;
mod signaling;

use signaling::SignalPipe;

// =============================================================================
// Types exposed to C
// =============================================================================

/// Opaque handle to Nostr keys (keypair)
pub struct NostrKeys {
    inner: Keys,
}

/// Opaque handle to Nostr client
pub struct NostrClient {
    inner: Arc<Mutex<ClientInner>>,
    runtime: Runtime,
    signal_pipe: SignalPipe,
}

struct ClientInner {
    client: Client,
    dm_callback: Option<DmCallbackInfo>,
    connect_callback: Option<ConnectCallbackInfo>,
    pending_events: Vec<PendingDm>,
    seen_event_ids: HashSet<String>,  // Track processed event IDs to prevent duplicates
    history_loaded: bool,  // True after initial EOSE received - used to skip real-time self-copies
}

struct PendingDm {
    sender_pubkey: String,
    recipient_pubkey: String,  // For outgoing messages
    content: String,
    timestamp: u64,
    is_outgoing: bool,
}

struct DmCallbackInfo {
    callback: NostrDmCallback,
    user_data: *mut c_void,
}

// Safety: user_data is managed by the C side and only accessed from main thread
unsafe impl Send for DmCallbackInfo {}
unsafe impl Sync for DmCallbackInfo {}

struct ConnectCallbackInfo {
    callback: NostrConnectCallback,
    user_data: *mut c_void,
}

unsafe impl Send for ConnectCallbackInfo {}
unsafe impl Sync for ConnectCallbackInfo {}

// =============================================================================
// Callback types
// =============================================================================

/// Callback invoked when a DM is received or sent (for history)
///
/// # Parameters
/// - `sender_pubkey`: The sender's public key in npub format (must not be freed)
/// - `recipient_pubkey`: The recipient's public key in npub format (must not be freed)
/// - `content`: The message content (must not be freed)
/// - `timestamp`: Unix timestamp of the message
/// - `is_outgoing`: 1 if this is a message we sent, 0 if received
/// - `user_data`: User data passed to nostr_client_set_dm_callback
pub type NostrDmCallback = extern "C" fn(
    sender_pubkey: *const c_char,
    recipient_pubkey: *const c_char,
    content: *const c_char,
    timestamp: u64,
    is_outgoing: c_int,
    user_data: *mut c_void,
);

/// Callback invoked when relay connection status changes
///
/// # Parameters
/// - `relay_url`: The relay URL (must not be freed)
/// - `connected`: 1 if connected, 0 if disconnected
/// - `user_data`: User data passed to nostr_client_set_connect_callback
pub type NostrConnectCallback = extern "C" fn(
    relay_url: *const c_char,
    connected: c_int,
    user_data: *mut c_void,
);

// =============================================================================
// Error codes
// =============================================================================

/// Success
pub const NOSTR_OK: c_int = 0;
/// Invalid argument (null pointer, invalid format, etc.)
pub const NOSTR_ERR_INVALID_ARG: c_int = -1;
/// Network/relay error
pub const NOSTR_ERR_NETWORK: c_int = -2;
/// Cryptographic error
pub const NOSTR_ERR_CRYPTO: c_int = -3;
/// Internal error
pub const NOSTR_ERR_INTERNAL: c_int = -4;

// =============================================================================
// String utilities
// =============================================================================

/// Free a string allocated by this library
///
/// # Safety
/// - `s` must be a pointer returned by a nostr_* function, or NULL
#[no_mangle]
pub unsafe extern "C" fn nostr_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

// =============================================================================
// Key management
// =============================================================================

/// Generate a new random keypair
///
/// # Returns
/// - Pointer to NostrKeys on success
/// - NULL on failure
#[no_mangle]
pub extern "C" fn nostr_keys_generate() -> *mut NostrKeys {
    let keys = Keys::generate();
    Box::into_raw(Box::new(NostrKeys { inner: keys }))
}

/// Create keys from an nsec (bech32) or hex secret key
///
/// # Parameters
/// - `secret_key`: The secret key in nsec1... or hex format
///
/// # Returns
/// - Pointer to NostrKeys on success
/// - NULL on failure (invalid format)
///
/// # Safety
/// - `secret_key` must be a valid null-terminated C string
#[no_mangle]
pub unsafe extern "C" fn nostr_keys_from_nsec(secret_key: *const c_char) -> *mut NostrKeys {
    if secret_key.is_null() {
        return ptr::null_mut();
    }

    let secret_str = match CStr::from_ptr(secret_key).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    // Keys::parse handles both nsec and hex formats
    match Keys::parse(secret_str) {
        Ok(keys) => Box::into_raw(Box::new(NostrKeys { inner: keys })),
        Err(_) => ptr::null_mut(),
    }
}

/// Get the public key in npub (bech32) format
///
/// # Returns
/// - Newly allocated string that must be freed with nostr_string_free()
/// - NULL on failure
///
/// # Safety
/// - `keys` must be a valid pointer from nostr_keys_generate or nostr_keys_from_nsec
#[no_mangle]
pub unsafe extern "C" fn nostr_keys_npub(keys: *const NostrKeys) -> *mut c_char {
    if keys.is_null() {
        return ptr::null_mut();
    }

    let keys = &*keys;
    let npub = match keys.inner.public_key().to_bech32() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    match CString::new(npub) {
        Ok(s) => s.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Get the public key in hex format
///
/// # Returns
/// - Newly allocated string that must be freed with nostr_string_free()
/// - NULL on failure
///
/// # Safety
/// - `keys` must be a valid pointer from nostr_keys_generate or nostr_keys_from_nsec
#[no_mangle]
pub unsafe extern "C" fn nostr_keys_pubkey_hex(keys: *const NostrKeys) -> *mut c_char {
    if keys.is_null() {
        return ptr::null_mut();
    }

    let keys = &*keys;
    let hex = keys.inner.public_key().to_hex();

    match CString::new(hex) {
        Ok(s) => s.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Get the secret key in nsec (bech32) format
///
/// # Returns
/// - Newly allocated string that must be freed with nostr_string_free()
/// - NULL on failure
///
/// # Safety
/// - `keys` must be a valid pointer from nostr_keys_generate or nostr_keys_from_nsec
#[no_mangle]
pub unsafe extern "C" fn nostr_keys_nsec(keys: *const NostrKeys) -> *mut c_char {
    if keys.is_null() {
        return ptr::null_mut();
    }

    let keys = &*keys;
    let nsec = match keys.inner.secret_key().to_bech32() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    match CString::new(nsec) {
        Ok(s) => s.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a NostrKeys instance
///
/// # Safety
/// - `keys` must be a valid pointer from nostr_keys_generate or nostr_keys_from_nsec, or NULL
#[no_mangle]
pub unsafe extern "C" fn nostr_keys_free(keys: *mut NostrKeys) {
    if !keys.is_null() {
        drop(Box::from_raw(keys));
    }
}

// =============================================================================
// Client management
// =============================================================================

/// Create a new Nostr client
///
/// # Parameters
/// - `keys`: The keys to use for signing and decryption
///
/// # Returns
/// - Pointer to NostrClient on success
/// - NULL on failure
///
/// # Safety
/// - `keys` must be a valid pointer from nostr_keys_* functions
#[no_mangle]
pub unsafe extern "C" fn nostr_client_new(keys: *const NostrKeys) -> *mut NostrClient {
    if keys.is_null() {
        return ptr::null_mut();
    }

    let keys = &*keys;

    // Create tokio runtime
    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };

    // Create signal pipe for GLib integration
    let signal_pipe = match SignalPipe::new() {
        Ok(pipe) => pipe,
        Err(_) => return ptr::null_mut(),
    };

    // Create nostr-sdk client
    let client = Client::new(keys.inner.clone());

    let inner = ClientInner {
        client,
        dm_callback: None,
        connect_callback: None,
        pending_events: Vec::new(),
        seen_event_ids: HashSet::new(),
        history_loaded: false,
    };

    Box::into_raw(Box::new(NostrClient {
        inner: Arc::new(Mutex::new(inner)),
        runtime,
        signal_pipe,
    }))
}

/// Add a relay to the client
///
/// # Parameters
/// - `client`: The client instance
/// - `url`: The relay WebSocket URL (e.g., "wss://relay.damus.io")
///
/// # Returns
/// - NOSTR_OK on success
/// - Error code on failure
///
/// # Safety
/// - `client` must be a valid pointer from nostr_client_new
/// - `url` must be a valid null-terminated C string
#[no_mangle]
pub unsafe extern "C" fn nostr_client_add_relay(
    client: *mut NostrClient,
    url: *const c_char,
) -> c_int {
    if client.is_null() || url.is_null() {
        return NOSTR_ERR_INVALID_ARG;
    }

    let client = &*client;
    let url_str = match CStr::from_ptr(url).to_str() {
        Ok(s) => s,
        Err(_) => return NOSTR_ERR_INVALID_ARG,
    };

    let inner = client.inner.lock().unwrap();
    let sdk_client = inner.client.clone();
    drop(inner);

    let result = client.runtime.block_on(async {
        sdk_client.add_relay(url_str).await
    });

    match result {
        Ok(_) => NOSTR_OK,
        Err(_) => NOSTR_ERR_NETWORK,
    }
}

/// Connect to all added relays and start listening for events
///
/// # Parameters
/// - `client`: The client instance
///
/// # Returns
/// - NOSTR_OK on success
/// - Error code on failure
///
/// # Safety
/// - `client` must be a valid pointer from nostr_client_new
#[no_mangle]
pub unsafe extern "C" fn nostr_client_connect(client: *mut NostrClient) -> c_int {
    if client.is_null() {
        return NOSTR_ERR_INVALID_ARG;
    }

    let client = &*client;
    let inner_arc = client.inner.clone();
    let signal_writer = client.signal_pipe.writer();

    let inner = inner_arc.lock().unwrap();
    let sdk_client = inner.client.clone();
    drop(inner);

    // Connect to relays
    client.runtime.block_on(async {
        sdk_client.connect().await;
    });

    // Get public key for subscription
    let pubkey = match client.runtime.block_on(async {
        sdk_client.public_key().await
    }) {
        Ok(pk) => pk,
        Err(_) => return NOSTR_ERR_INTERNAL,
    };

    // Create filter for gift-wrapped events addressed to us (NIP-17)
    // Use `since` to get recent messages - relays return oldest first with limit,
    // so without `since` we'd get the 50 oldest messages ever, not the 50 newest.
    // Fetch messages from the last 30 days for history (max 100 messages).
    let thirty_days_ago = Timestamp::now() - 30 * 24 * 60 * 60;
    let filter = Filter::new()
        .kind(Kind::GiftWrap)
        .pubkey(pubkey)
        .since(thirty_days_ago)
        .limit(100);

    eprintln!("[nostr-core] Subscribing to GiftWrap events for pubkey: {} (fetching last 30 days, max 100 messages)", pubkey.to_hex());
    
    let subscribe_result = client.runtime.block_on(async {
        sdk_client.subscribe(filter, None).await
    });

    match &subscribe_result {
        Ok(output) => eprintln!("[nostr-core] Subscription successful: {:?}", output.val),
        Err(e) => {
            eprintln!("[nostr-core] Subscription failed: {:?}", e);
            return NOSTR_ERR_NETWORK;
        }
    }

    // Spawn background task to handle incoming events
    let inner_for_task = inner_arc.clone();
    let sdk_client_for_task = sdk_client.clone();
    let our_pubkey = pubkey;  // Our own public key to detect outgoing messages

    eprintln!("[nostr-core] Spawning notification handler task...");
    
    client.runtime.spawn(async move {
        eprintln!("[nostr-core] Notification handler task started, waiting for events...");
        let _ = sdk_client_for_task
            .handle_notifications(|notification| {
                let inner = inner_for_task.clone();
                let signal = signal_writer;
                let client = sdk_client_for_task.clone();
                let our_pk = our_pubkey;

                async move {
                    match &notification {
                        RelayPoolNotification::Event { event, .. } => {
                            // Event notification is for incoming messages from others
                            // (nostr-sdk already excludes events sent by this client)
                            if event.kind == Kind::GiftWrap {
                                // Check if we've already seen this event
                                let event_id = event.id.to_hex();
                                {
                                    let inner_guard = inner.lock();
                                    if let Ok(inner_ref) = inner_guard {
                                        if inner_ref.seen_event_ids.contains(&event_id) {
                                            return Ok(false);
                                        }
                                    }
                                }
                                
                                match client.unwrap_gift_wrap(&event).await {
                                    Ok(unwrapped) => {
                                        let content = unwrapped.rumor.content.clone();
                                        
                                        if !content.is_empty() {
                                            let is_outgoing = unwrapped.sender == our_pk;
                                            
                                            let sender_npub = unwrapped.sender.to_bech32()
                                                .unwrap_or_else(|_| unwrapped.sender.to_hex());
                                            
                                            // Get recipient from the p tag in the rumor
                                            let recipient_npub = unwrapped.rumor.tags.iter()
                                                .find(|tag| tag.kind() == nostr_sdk::TagKind::p())
                                                .and_then(|tag| {
                                                    let slice = tag.as_slice();
                                                    if slice.len() > 1 {
                                                        Some(slice[1].as_str())
                                                    } else {
                                                        tag.content().map(|s| s)
                                                    }
                                                })
                                                .and_then(|pk_str| PublicKey::parse(pk_str).ok())
                                                .map(|pk| pk.to_bech32().unwrap_or_else(|_| pk.to_hex()))
                                                .unwrap_or_else(|| String::new());
                                            
                                            // Skip outgoing messages without a recipient
                                            if is_outgoing && recipient_npub.is_empty() {
                                                return Ok(false);
                                            }
                                            
                                            eprintln!("[nostr-core] Received DM: from={}, outgoing={}, content: {}", 
                                                sender_npub, is_outgoing, content);
                                            
                                            let dm = PendingDm {
                                                sender_pubkey: sender_npub,
                                                recipient_pubkey: recipient_npub,
                                                content,
                                                timestamp: unwrapped.rumor.created_at.as_secs(),
                                                is_outgoing,
                                            };

                                            let should_signal;
                                            if let Ok(mut inner) = inner.lock() {
                                                inner.seen_event_ids.insert(event_id);
                                                inner.pending_events.push(dm);
                                                // Only signal immediately for real-time messages (after EOSE)
                                                // History messages will be signaled all at once when EOSE arrives
                                                should_signal = inner.history_loaded;
                                            } else {
                                                should_signal = false;
                                            }

                                            if should_signal {
                                                let _ = signal.signal();
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("[nostr-core] Failed to unwrap gift wrap: {:?}", e);
                                    }
                                }
                            }
                        }
                        RelayPoolNotification::Message { message, .. } => {
                            // Handle EndOfStoredEvents to mark history as loaded
                            if let nostr_sdk::RelayMessage::EndOfStoredEvents(_) = message {
                                if let Ok(mut inner_guard) = inner.lock() {
                                    if !inner_guard.history_loaded {
                                        inner_guard.history_loaded = true;
                                        eprintln!("[nostr-core] History loaded (EOSE received), signaling to deliver history");
                                        // Now signal to deliver all collected history messages
                                        let _ = signal.signal();
                                    }
                                }
                                return Ok(false);
                            }
                            
                            // Handle events that come through Message.
                            // RelayPoolNotification::Event excludes events sent by this client,
                            // so self-copies (our outgoing messages) ONLY arrive here via Message.
                            // We ONLY process outgoing messages here to avoid duplicates with Event.
                            if let nostr_sdk::RelayMessage::Event { event, .. } = message {
                                if event.kind == Kind::GiftWrap {
                                    // Check if we've already seen this event
                                    let event_id = event.id.to_hex();
                                    let history_loaded;
                                    {
                                        let inner_guard = inner.lock();
                                        if let Ok(inner_ref) = inner_guard {
                                            if inner_ref.seen_event_ids.contains(&event_id) {
                                                // Already processed this event, skip
                                                return Ok(false);
                                            }
                                            history_loaded = inner_ref.history_loaded;
                                        } else {
                                            return Ok(false);
                                        }
                                    }
                                    
                                    match client.unwrap_gift_wrap(&event).await {
                                        Ok(unwrapped) => {
                                            let is_outgoing = unwrapped.sender == our_pk;
                                            
                                            // Only process outgoing messages via Message notification
                                            // Incoming messages are handled by Event notification
                                            if !is_outgoing {
                                                return Ok(false);
                                            }
                                            
                                            // Skip real-time outgoing messages - Pidgin already echoes them
                                            // Only process outgoing messages during history load
                                            if history_loaded {
                                                eprintln!("[nostr-core] Skipping real-time self-copy (Pidgin already shows it)");
                                                return Ok(false);
                                            }
                                            
                                            let content = unwrapped.rumor.content.clone();
                                            
                                            if !content.is_empty() {
                                                let sender_npub = unwrapped.sender.to_bech32()
                                                    .unwrap_or_else(|_| unwrapped.sender.to_hex());
                                                
                                                let recipient_npub = unwrapped.rumor.tags.iter()
                                                    .find(|tag| tag.kind() == nostr_sdk::TagKind::p())
                                                    .and_then(|tag| {
                                                        let slice = tag.as_slice();
                                                        if slice.len() > 1 {
                                                            Some(slice[1].as_str())
                                                        } else {
                                                            tag.content().map(|s| s)
                                                        }
                                                    })
                                                    .and_then(|pk_str| PublicKey::parse(pk_str).ok())
                                                    .map(|pk| pk.to_bech32().unwrap_or_else(|_| pk.to_hex()))
                                                    .unwrap_or_else(|| String::new());
                                                
                                                if recipient_npub.is_empty() {
                                                    eprintln!("[nostr-core] Skipping outgoing message without recipient p-tag");
                                                    return Ok(false);
                                                }
                                                
                                                eprintln!("[nostr-core] Processing outgoing DM (history): content: {}", content);
                                                
                                                let dm = PendingDm {
                                                    sender_pubkey: sender_npub,
                                                    recipient_pubkey: recipient_npub,
                                                    content,
                                                    timestamp: unwrapped.rumor.created_at.as_secs(),
                                                    is_outgoing,
                                                };

                                                if let Ok(mut inner) = inner.lock() {
                                                    // Mark as seen and queue
                                                    inner.seen_event_ids.insert(event_id);
                                                    inner.pending_events.push(dm);
                                                }

                                                let _ = signal.signal();
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("[nostr-core] Failed to unwrap gift wrap (from Message): {:?}", e);
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                    Ok(false) // Keep listening
                }
            })
            .await;
    });

    NOSTR_OK
}

/// Disconnect from all relays
///
/// # Safety
/// - `client` must be a valid pointer from nostr_client_new
#[no_mangle]
pub unsafe extern "C" fn nostr_client_disconnect(client: *mut NostrClient) {
    if client.is_null() {
        return;
    }

    let client = &*client;
    let inner = client.inner.lock().unwrap();
    let sdk_client = inner.client.clone();
    drop(inner);

    client.runtime.block_on(async {
        sdk_client.disconnect().await;
    });
}

/// Free a NostrClient instance
///
/// # Safety
/// - `client` must be a valid pointer from nostr_client_new, or NULL
#[no_mangle]
pub unsafe extern "C" fn nostr_client_free(client: *mut NostrClient) {
    if !client.is_null() {
        let client = Box::from_raw(client);
        // Disconnect before dropping
        let inner = client.inner.lock().unwrap();
        let sdk_client = inner.client.clone();
        drop(inner);

        client.runtime.block_on(async {
            sdk_client.disconnect().await;
        });

        drop(client);
    }
}

// =============================================================================
// Event callbacks
// =============================================================================

/// Set the callback for received DMs
///
/// # Parameters
/// - `client`: The client instance
/// - `callback`: Function to call when a DM is received
/// - `user_data`: Opaque pointer passed to the callback
///
/// # Safety
/// - `client` must be a valid pointer from nostr_client_new
/// - `callback` must be a valid function pointer
/// - `user_data` will be passed to callback; caller is responsible for its lifetime
#[no_mangle]
pub unsafe extern "C" fn nostr_client_set_dm_callback(
    client: *mut NostrClient,
    callback: NostrDmCallback,
    user_data: *mut c_void,
) {
    if client.is_null() {
        return;
    }

    let client = &*client;
    let mut inner = client.inner.lock().unwrap();
    inner.dm_callback = Some(DmCallbackInfo {
        callback,
        user_data,
    });
}

/// Set the callback for relay connection status changes
///
/// # Safety
/// - `client` must be a valid pointer from nostr_client_new
/// - `callback` must be a valid function pointer
#[no_mangle]
pub unsafe extern "C" fn nostr_client_set_connect_callback(
    client: *mut NostrClient,
    callback: NostrConnectCallback,
    user_data: *mut c_void,
) {
    if client.is_null() {
        return;
    }

    let client = &*client;
    let mut inner = client.inner.lock().unwrap();
    inner.connect_callback = Some(ConnectCallbackInfo {
        callback,
        user_data,
    });
}

/// Get the file descriptor for event notification
///
/// This fd becomes readable when there are pending events to process.
/// Use with poll(), select(), or g_io_add_watch().
///
/// # Returns
/// - File descriptor on success
/// - -1 on failure
///
/// # Safety
/// - `client` must be a valid pointer from nostr_client_new
#[no_mangle]
pub unsafe extern "C" fn nostr_client_get_fd(client: *const NostrClient) -> c_int {
    if client.is_null() {
        return -1;
    }

    let client = &*client;
    client.signal_pipe.read_fd()
}

/// Process pending events and invoke callbacks
///
/// This should be called when the fd returned by nostr_client_get_fd() is readable.
/// All registered callbacks will be invoked synchronously from this function.
///
/// # Safety
/// - `client` must be a valid pointer from nostr_client_new
/// - Must be called from the main thread (GLib main loop)
#[no_mangle]
pub unsafe extern "C" fn nostr_client_process_events(client: *mut NostrClient) {
    if client.is_null() {
        return;
    }

    let client = &*client;

    // Clear the signal
    client.signal_pipe.clear();

    // Get pending events and callback
    let (mut pending, callback) = {
        let mut inner = client.inner.lock().unwrap();
        let pending = std::mem::take(&mut inner.pending_events);
        let callback = inner.dm_callback.clone();
        (pending, callback)
    };

    // Sort messages by timestamp (oldest first) so history displays in correct order
    pending.sort_by_key(|dm| dm.timestamp);

    // Invoke callback for each pending DM
    if let Some(cb_info) = callback {
        for dm in pending {
            let sender = CString::new(dm.sender_pubkey).unwrap_or_default();
            let recipient = CString::new(dm.recipient_pubkey).unwrap_or_default();
            let content = CString::new(dm.content).unwrap_or_default();

            (cb_info.callback)(
                sender.as_ptr(),
                recipient.as_ptr(),
                content.as_ptr(),
                dm.timestamp,
                if dm.is_outgoing { 1 } else { 0 },
                cb_info.user_data,
            );
        }
    }
}

// =============================================================================
// Messaging
// =============================================================================

/// Send a NIP-17 private direct message
///
/// # Parameters
/// - `client`: The client instance
/// - `recipient_pubkey`: The recipient's public key in hex or npub format
/// - `message`: The message content
///
/// # Returns
/// - NOSTR_OK on success
/// - Error code on failure
///
/// # Safety
/// - `client` must be a valid pointer from nostr_client_new
/// - `recipient_pubkey` and `message` must be valid null-terminated C strings
#[no_mangle]
pub unsafe extern "C" fn nostr_send_dm(
    client: *mut NostrClient,
    recipient_pubkey: *const c_char,
    message: *const c_char,
) -> c_int {
    if client.is_null() || recipient_pubkey.is_null() || message.is_null() {
        return NOSTR_ERR_INVALID_ARG;
    }

    let client = &*client;

    let recipient_str = match CStr::from_ptr(recipient_pubkey).to_str() {
        Ok(s) => s,
        Err(_) => return NOSTR_ERR_INVALID_ARG,
    };

    let message_str = match CStr::from_ptr(message).to_str() {
        Ok(s) => s,
        Err(_) => return NOSTR_ERR_INVALID_ARG,
    };

    eprintln!("[nostr-core] nostr_send_dm called: recipient={}, message='{}'", recipient_str, message_str);

    // Parse recipient public key (supports both hex and npub)
    let recipient = match PublicKey::parse(recipient_str) {
        Ok(pk) => pk,
        Err(_) => return NOSTR_ERR_INVALID_ARG,
    };

    let inner = client.inner.lock().unwrap();
    let sdk_client = inner.client.clone();
    drop(inner);

    // Send the NIP-17 private message
    // Note: nostr-sdk's send_private_msg sends to the recipient only.
    // For sent message history, we need to also send a gift-wrapped copy to ourselves.
    let result = client.runtime.block_on(async {
        // Get our own public key for self-copy
        let our_pk = match sdk_client.public_key().await {
            Ok(pk) => pk,
            Err(e) => {
                eprintln!("[nostr-core] Failed to get our public key: {:?}", e);
                return Err(e);
            }
        };
        
        // Send to the recipient (this wraps in gift wrap and sends)
        let send_result = sdk_client
            .send_private_msg(recipient, message_str, None)
            .await;
        
        if let Err(ref e) = send_result {
            eprintln!("[nostr-core] Failed to send DM to recipient: {:?}", e);
            return send_result;
        }
        
        eprintln!("[nostr-core] Sent DM to recipient: {}", recipient.to_hex());
        
        // NIP-17: Also send a gift-wrapped copy to ourselves for message history
        // The rumor contains the recipient in the p-tag, so we can reconstruct the conversation
        if our_pk != recipient {
            // Create the kind 14 rumor (unsigned DM event) with recipient in the p-tag
            let rumor = EventBuilder::private_msg_rumor(recipient, message_str).build(our_pk);
            
            eprintln!("[nostr-core] Self-copy rumor: kind={:?}, content='{}', tags={:?}", 
                rumor.kind, rumor.content, rumor.tags.iter().map(|t| t.as_slice()).collect::<Vec<_>>());
            eprintln!("[nostr-core] Sending gift-wrapped self-copy to our pubkey: {}", our_pk.to_hex());
            
            // Gift wrap the rumor to ourselves and send
            match sdk_client.gift_wrap(&our_pk, rumor, []).await {
                Ok(output) => eprintln!("[nostr-core] Sent self-copy for history, result: {:?}", output),
                Err(e) => eprintln!("[nostr-core] Warning: Failed to send self-copy: {:?}", e),
            }
        }
        
        send_result
    });

    match result {
        Ok(_) => NOSTR_OK,
        Err(_) => NOSTR_ERR_NETWORK,
    }
}

impl Clone for DmCallbackInfo {
    fn clone(&self) -> Self {
        DmCallbackInfo {
            callback: self.callback,
            user_data: self.user_data,
        }
    }
}
