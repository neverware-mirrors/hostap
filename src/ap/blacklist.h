/*
 * hostapd / Interface station blacklist
 * Copyright (c) 2017 Google, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef BLACKLIST_STA_H
#define BLACKLIST_STA_H

#include "hostapd.h"

#ifdef CONFIG_BLACKLIST_STA

/* max blacklist count */
#define MAX_BLACKLIST_COUNT 32

/* Default blacklist timeout(secs) to be configured on initialization */
#define DEFAULT_BLACKLIST_TIMEOUT 2

/*
 * Max blacklist timeout(secs) i.e configurable over hostapd
 * control interface
 */
#define MAX_BLACKLIST_TIMEOUT 10

/*
 * Default number of connection attempts by blacklisted station configured
 * on initialization
 */
#define DEFAULT_BLACKLIST_CONNECTION_ATTEMPTS 2

/*
 * Max connection attempts by blacklisted sta i.e configurable over
 * hostapd control interface
 */
#define MAX_BLACKLIST_CONNECTION_ATTEMPTS 10

struct hapd_blacklist {
	struct sta_blacklist *head; /* sta black list */
	u32 bl_count; /* black list count */
	u16 blacklist_timeout; /* blacklist time in seconds */
	u16 blacklist_conn_attempts; /* blacklisted sta connection attempts */
};

Boolean sta_blacklist_add(struct hostapd_data *hapd, const u8 *sta);
Boolean sta_blacklist_should_reject(struct hostapd_data *hapd, const u8 *sta,
                                    Boolean connect);
void sta_blacklist_prune(void *eloop_ctx, void *timeout_ctx);

#else

static inline Boolean sta_blacklist_add(struct hostapd_data *hapd,
					const u8 *sta)
{
	return TRUE;
}

static inline Boolean sta_blacklist_present(struct hostapd_data *hapd,
					    const u8 *sta)
{
	return FALSE;
}

static inline void sta_blacklist_prune(void *eloop_ctx, void *timeout_ctx)
{
}

#endif /* CONFIG_BLACKLIST_STA */

#endif /* BLACKLIST_STA_H */

