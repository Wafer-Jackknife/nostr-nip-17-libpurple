/**
 * nostr.c - Nostr protocol plugin for libpurple
 *
 * This plugin enables NIP-17 private direct messaging over the Nostr protocol.
 */

#define PURPLE_PLUGINS

#include <glib.h>
#include <string.h>

#include <account.h>
#include <accountopt.h>
#include <blist.h>
#include <conversation.h>
#include <connection.h>
#include <debug.h>
#include <notify.h>
#include <plugin.h>
#include <prpl.h>
#include <request.h>
#include <util.h>
#include <version.h>

#include "nostr_core.h"

/* Plugin info */
#define NOSTR_PLUGIN_ID "prpl-nostr"
#define NOSTR_PLUGIN_NAME "Nostr"
#define NOSTR_PLUGIN_VERSION "0.1.0"
#define NOSTR_PLUGIN_SUMMARY "Nostr Protocol Plugin"
#define NOSTR_PLUGIN_DESCRIPTION "Send and receive encrypted direct messages over the Nostr protocol (NIP-17)"
#define NOSTR_PLUGIN_AUTHOR "pidgin-nostr-plugin contributors"
#define NOSTR_PLUGIN_WEBSITE "https://github.com/example/pidgin-nostr-plugin"

/* Account option keys */
#define NOSTR_OPT_RELAYS "relays"
#define NOSTR_OPT_GENERATE_KEY "generate_key"
#define NOSTR_OPT_HISTORY_DAYS "history_days"
#define NOSTR_OPT_HISTORY_LIMIT "history_limit"
#define NOSTR_OPT_DISPLAY_NSEC "display_nsec"

/* Default relays */
#define NOSTR_DEFAULT_RELAYS "wss://relay.damus.io,wss://nos.lol,wss://relay.nostr.band"

/* Default history settings */
#define NOSTR_DEFAULT_HISTORY_DAYS 30
#define NOSTR_DEFAULT_HISTORY_LIMIT 100

/* Connection data */
typedef struct {
    struct nostr_NostrClient *client;
    struct nostr_NostrKeys *keys;
    GIOChannel *io_channel;
    guint io_watch_id;
    PurpleConnection *gc;
} NostrConnectionData;

/* Forward declarations */
static void nostr_login(PurpleAccount *account);
static void nostr_close(PurpleConnection *gc);
static int nostr_send_im(PurpleConnection *gc, const char *who, const char *message, PurpleMessageFlags flags);
static const char *nostr_list_icon(PurpleAccount *account, PurpleBuddy *buddy);
static GList *nostr_status_types(PurpleAccount *account);
static void nostr_set_status(PurpleAccount *account, PurpleStatus *status);
static GList *nostr_account_options(void);
static void nostr_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group);
static void nostr_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group);

/* Callback when DM is received or sent (for history) */
static void dm_received_callback(const char *sender_pubkey, const char *recipient_pubkey, 
                                  const char *content, uint64_t timestamp, 
                                  int is_outgoing, void *user_data)
{
    NostrConnectionData *conn = (NostrConnectionData *)user_data;
    PurpleConnection *gc = conn->gc;
    PurpleAccount *account = purple_connection_get_account(gc);

    if (is_outgoing) {
        /* This is a message we sent - show it as outgoing */
        purple_debug_info("nostr", "History: Sent DM to %s: %s\n", recipient_pubkey, content);
        
        /* Find or create conversation with the recipient */
        PurpleConversation *conv = purple_find_conversation_with_account(
            PURPLE_CONV_TYPE_IM, recipient_pubkey, account);

        if (!conv) {
            conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, recipient_pubkey);
        }

        /* Write the message as if we sent it (for history) */
        purple_conv_im_write(PURPLE_CONV_IM(conv), 
                             purple_account_get_username(account),
                             content, 
                             PURPLE_MESSAGE_SEND | PURPLE_MESSAGE_DELAYED,
                             (time_t)timestamp);
    } else {
        /* This is a message we received */
        purple_debug_info("nostr", "Received DM from %s: %s\n", sender_pubkey, content);

        /* Find or create conversation */
        PurpleConversation *conv = purple_find_conversation_with_account(
            PURPLE_CONV_TYPE_IM, sender_pubkey, account);

        if (!conv) {
            conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, sender_pubkey);
        }

        /* Display the message */
        serv_got_im(gc, sender_pubkey, content, PURPLE_MESSAGE_RECV, (time_t)timestamp);
    }
}

/* GLib IO callback when Nostr events are ready */
static gboolean nostr_io_callback(GIOChannel *source, GIOCondition condition, gpointer data)
{
    NostrConnectionData *conn = (NostrConnectionData *)data;

    (void)source;  /* unused */
    (void)condition;  /* unused */

    if (conn && conn->client) {
        nostr_client_process_events(conn->client);
    }

    return TRUE;  /* Keep watching */
}

/* Login to Nostr */
static void nostr_login(PurpleAccount *account)
{
    PurpleConnection *gc = purple_account_get_connection(account);
    NostrConnectionData *conn;
    const char *nsec;
    const char *relays_str;
    char **relays;
    int i;
    int fd;

    purple_debug_info("nostr", "Logging in to Nostr\n");

    /* Allocate connection data */
    conn = g_new0(NostrConnectionData, 1);
    conn->gc = gc;
    purple_connection_set_protocol_data(gc, conn);

    /* Set connecting state */
    purple_connection_set_state(gc, PURPLE_CONNECTING);
    purple_connection_update_progress(gc, "Initializing keys...", 1, 4);

    /* Get the private key (nsec) from account password */
    nsec = purple_account_get_password(account);
    if (!nsec || strlen(nsec) == 0) {
        /* Check if we should generate a new key */
        gboolean generate = purple_account_get_bool(account, NOSTR_OPT_GENERATE_KEY, FALSE);
        if (generate) {
            conn->keys = nostr_keys_generate();
            if (conn->keys) {
                /* Save the generated nsec as password */
                char *new_nsec = nostr_keys_nsec(conn->keys);
                if (new_nsec) {
                    purple_account_set_password(account, new_nsec);
                    purple_account_set_remember_password(account, TRUE);

                    /* Show the user their new npub and nsec */
                    char *npub = nostr_keys_npub(conn->keys);
                    if (npub) {
                        char *msg = g_strdup_printf(
                            "Generated new Nostr identity!\n\n"
                            "Public key (npub):\n%s\n\n"
                            "Private key (nsec):\n%s\n\n"
                            "IMPORTANT: Save your private key (nsec) somewhere safe!\n"
                            "You can view it anytime in Account Settings > Modify Account.\n"
                            "Anyone with your nsec can impersonate you!",
                            npub, new_nsec);
                        purple_notify_info(gc, "Nostr Identity Created", "New Identity", msg);
                        g_free(msg);
                        nostr_string_free(npub);
                    }
                    nostr_string_free(new_nsec);

                    /* Disable generate_key for future logins */
                    purple_account_set_bool(account, NOSTR_OPT_GENERATE_KEY, FALSE);
                }
            }
        } else {
            purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
                "No private key (nsec) configured. Enter your nsec as the password, "
                "or enable 'Generate new keypair' in account settings.");
            return;
        }
    } else {
        /* Parse existing nsec */
        conn->keys = nostr_keys_from_nsec(nsec);
        if (conn->keys) {
            /* Ensure password is remembered so the nsec persists across restarts */
            purple_account_set_remember_password(account, TRUE);
        }
    }

    if (!conn->keys) {
        purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
            "Invalid private key format. Please use nsec or hex format.");
        return;
    }

    purple_connection_update_progress(gc, "Creating client...", 2, 4);

    /* Create the Nostr client */
    conn->client = nostr_client_new(conn->keys);
    if (!conn->client) {
        purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_OTHER_ERROR,
            "Failed to create Nostr client");
        return;
    }

    /* Set up DM callback */
    nostr_client_set_dm_callback(conn->client, dm_received_callback, conn);

    /* Add relays */
    relays_str = purple_account_get_string(account, NOSTR_OPT_RELAYS, NOSTR_DEFAULT_RELAYS);
    relays = g_strsplit(relays_str, ",", -1);

    purple_connection_update_progress(gc, "Adding relays...", 3, 4);

    for (i = 0; relays[i] != NULL; i++) {
        char *relay = g_strstrip(relays[i]);
        if (strlen(relay) > 0) {
            int result = nostr_client_add_relay(conn->client, relay);
            if (result == nostr_NOSTR_OK) {
                purple_debug_info("nostr", "Added relay: %s\n", relay);
            } else {
                purple_debug_warning("nostr", "Failed to add relay: %s\n", relay);
            }
        }
    }
    g_strfreev(relays);

    purple_connection_update_progress(gc, "Connecting to relays...", 4, 4);

    /* Connect to relays */
    int result = nostr_client_connect(conn->client);
    if (result != nostr_NOSTR_OK) {
        purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
            "Failed to connect to relays");
        return;
    }

    /* Set up GLib IO watch for event notifications */
    fd = nostr_client_get_fd(conn->client);
    if (fd >= 0) {
        conn->io_channel = g_io_channel_unix_new(fd);
        conn->io_watch_id = g_io_add_watch(conn->io_channel, G_IO_IN, nostr_io_callback, conn);
    }

    /* Set the account username to our npub if it's not already an npub */
    const char *username = purple_account_get_username(account);
    /* Replace username with npub if it's empty, a placeholder, or not already an npub */
    if (!username || strlen(username) == 0 || strncmp(username, "npub1", 5) != 0) {
        char *npub = nostr_keys_npub(conn->keys);
        if (npub) {
            purple_account_set_username(account, npub);
            nostr_string_free(npub);
        }
    }

    /* Update the display nsec field so users can view their private key */
    char *display_nsec = nostr_keys_nsec(conn->keys);
    if (display_nsec) {
        purple_account_set_string(account, NOSTR_OPT_DISPLAY_NSEC, display_nsec);
        nostr_string_free(display_nsec);
    }

    /* We're connected! */
    purple_connection_set_state(gc, PURPLE_CONNECTED);
    purple_debug_info("nostr", "Connected to Nostr!\n");

    /* Set all existing buddies as online (Nostr has no presence) */
    GSList *buddies = purple_find_buddies(account, NULL);
    GSList *iter;
    for (iter = buddies; iter != NULL; iter = iter->next) {
        PurpleBuddy *buddy = (PurpleBuddy *)iter->data;
        const char *name = purple_buddy_get_name(buddy);
        purple_prpl_got_user_status(account, name, "available", NULL);
    }
    g_slist_free(buddies);
}

/* Close connection */
static void nostr_close(PurpleConnection *gc)
{
    NostrConnectionData *conn = purple_connection_get_protocol_data(gc);

    purple_debug_info("nostr", "Closing Nostr connection\n");

    if (conn) {
        /* Remove IO watch */
        if (conn->io_watch_id > 0) {
            g_source_remove(conn->io_watch_id);
        }
        if (conn->io_channel) {
            g_io_channel_unref(conn->io_channel);
        }

        /* Disconnect and free client */
        if (conn->client) {
            nostr_client_disconnect(conn->client);
            nostr_client_free(conn->client);
        }

        /* Free keys */
        if (conn->keys) {
            nostr_keys_free(conn->keys);
        }

        g_free(conn);
        purple_connection_set_protocol_data(gc, NULL);
    }
}

/* Send IM */
static int nostr_send_im(PurpleConnection *gc, const char *who, const char *message, PurpleMessageFlags flags)
{
    NostrConnectionData *conn = purple_connection_get_protocol_data(gc);

    (void)flags;  /* unused */

    if (!conn || !conn->client) {
        return -1;
    }

    purple_debug_info("nostr", "Sending DM to %s: %s\n", who, message);

    int result = nostr_send_dm(conn->client, who, message);
    if (result == nostr_NOSTR_OK) {
        return 1;  /* Success */
    } else {
        purple_debug_error("nostr", "Failed to send DM: error %d\n", result);
        return -1;  /* Failure */
    }
}

/* Protocol icon */
static const char *nostr_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
    (void)account;  /* unused */
    (void)buddy;    /* unused */
    return "nostr";
}

/* Status types */
static GList *nostr_status_types(PurpleAccount *account)
{
    GList *types = NULL;
    PurpleStatusType *type;

    (void)account;  /* unused */

    /* Available status - Nostr doesn't have real presence, so everyone is "available" */
    type = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, NULL, NULL, TRUE, TRUE, FALSE);
    types = g_list_append(types, type);

    /* Offline status */
    type = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, NULL, NULL, TRUE, TRUE, FALSE);
    types = g_list_append(types, type);

    return types;
}

/* Set status (no-op for Nostr) */
static void nostr_set_status(PurpleAccount *account, PurpleStatus *status)
{
    (void)account;  /* unused */
    (void)status;   /* unused */
    /* Nostr doesn't have presence, so this is a no-op */
}

/* Account options */
static GList *nostr_account_options(void)
{
    GList *opts = NULL;
    PurpleAccountOption *opt;

    /* Relay list */
    opt = purple_account_option_string_new(
        "Relays (comma-separated)",
        NOSTR_OPT_RELAYS,
        NOSTR_DEFAULT_RELAYS);
    opts = g_list_append(opts, opt);

    /* Generate new keypair option */
    opt = purple_account_option_bool_new(
        "Generate new keypair (first login only)",
        NOSTR_OPT_GENERATE_KEY,
        FALSE);
    opts = g_list_append(opts, opt);

    /* Display nsec (read-only, populated after login) */
    opt = purple_account_option_string_new(
        "Your private key (nsec) - KEEP THIS SAFE!",
        NOSTR_OPT_DISPLAY_NSEC,
        "");
    opts = g_list_append(opts, opt);

    return opts;
}

/* Add buddy - set them as online since Nostr has no presence */
static void nostr_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
    PurpleAccount *account = purple_connection_get_account(gc);
    const char *name;

    (void)group;  /* unused */

    if (!buddy)
        return;

    name = purple_buddy_get_name(buddy);
    purple_debug_info("nostr", "Adding buddy: %s\n", name);

    /* Set buddy as online - Nostr doesn't have presence, everyone is "available" */
    purple_prpl_got_user_status(account, name, "available", NULL);
}

/* Remove buddy */
static void nostr_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
    (void)gc;     /* unused */
    (void)group;  /* unused */

    if (buddy) {
        purple_debug_info("nostr", "Removing buddy: %s\n", purple_buddy_get_name(buddy));
    }
}

/* Protocol info structure */
static PurplePluginProtocolInfo prpl_info = {
    .options = OPT_PROTO_PASSWORD_OPTIONAL,  /* Password field is used for nsec, but optional if generating */
    .icon_spec = NO_BUDDY_ICONS,
    .list_icon = nostr_list_icon,
    .status_types = nostr_status_types,
    .login = nostr_login,
    .close = nostr_close,
    .send_im = nostr_send_im,
    .set_status = nostr_set_status,
    .add_buddy = nostr_add_buddy,
    .remove_buddy = nostr_remove_buddy,
    .struct_size = sizeof(PurplePluginProtocolInfo),
};

/* Plugin load callback */
static gboolean plugin_load(PurplePlugin *plugin)
{
    PurpleAccountOption *option;

    (void)plugin;
    purple_debug_info("nostr", "Nostr plugin loaded\n");

    /* Add account options for the Advanced tab */
    
    /* History days (display only for now) */
    option = purple_account_option_int_new(
        "History window (days)",
        NOSTR_OPT_HISTORY_DAYS,
        NOSTR_DEFAULT_HISTORY_DAYS
    );
    prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

    /* History message limit (display only for now) */
    option = purple_account_option_int_new(
        "Max messages to fetch",
        NOSTR_OPT_HISTORY_LIMIT,
        NOSTR_DEFAULT_HISTORY_LIMIT
    );
    prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

    return TRUE;
}

/* Plugin unload callback */
static gboolean plugin_unload(PurplePlugin *plugin)
{
    (void)plugin;
    purple_debug_info("nostr", "Nostr plugin unloaded\n");
    return TRUE;
}

/* Plugin info structure */
static PurplePluginInfo info = {
    .magic = PURPLE_PLUGIN_MAGIC,
    .major_version = PURPLE_MAJOR_VERSION,
    .minor_version = PURPLE_MINOR_VERSION,
    .type = PURPLE_PLUGIN_PROTOCOL,
    .ui_requirement = NULL,
    .flags = 0,
    .dependencies = NULL,
    .priority = PURPLE_PRIORITY_DEFAULT,

    .id = NOSTR_PLUGIN_ID,
    .name = NOSTR_PLUGIN_NAME,
    .version = NOSTR_PLUGIN_VERSION,
    .summary = NOSTR_PLUGIN_SUMMARY,
    .description = NOSTR_PLUGIN_DESCRIPTION,
    .author = NOSTR_PLUGIN_AUTHOR,
    .homepage = NOSTR_PLUGIN_WEBSITE,

    .load = plugin_load,
    .unload = plugin_unload,
    .destroy = NULL,

    .ui_info = NULL,
    .extra_info = &prpl_info,
    .prefs_info = NULL,
    .actions = NULL,
};

/* Plugin initialization */
static void init_plugin(PurplePlugin *plugin)
{
    /* Add account options */
    prpl_info.protocol_options = nostr_account_options();

    /* The username is the npub - we'll auto-populate it on first login */
    (void)plugin;
}

PURPLE_INIT_PLUGIN(nostr, init_plugin, info)
