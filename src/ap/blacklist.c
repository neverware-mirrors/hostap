/*
 * hostapd / Interface station blacklist
 * Copyright (c) 2017 Google, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifdef CONFIG_BLACKLIST_STA

#include "includes.h"
#include "common.h"
#include "utils/eloop.h"
#include "blacklist.h"

struct sta_blacklist {
	struct sta_blacklist *next; /* sta black list */
	struct os_reltime time; /* blacklist timestamp */
	uint16_t attempts; /* sta connect attempts */
	u8 sta[ETH_ALEN]; /* sta mac address */
};

/*
 * sta_blacklist_set_blacklist_timeout - set blacklist timeout
 * list: pointer to hapd_blacklist
 * duration: blacklist timeout in seconds
 * function set's the maximum duration of station blacklist
 * return: 0 - Success, -1 - Failure
 */
int sta_blacklist_set_blacklist_timeout(struct hapd_blacklist *list,
					u16 duration)
{
	if (!list || duration <= 0 || duration > MAX_BLACKLIST_TIMEOUT)
		return -1;

	list->blacklist_timeout = duration;
	return 0;
}

/*
 * sta_blacklist_set_connection_attempt - set station connection attempt
 * list: pointer to hapd_blacklist
 * attempts: station connection attempts
 * function set's the maximum number of connection attempts by blacklisted sta
 * return: 0 - Success, -1 - Failure
 */
int sta_blacklist_set_connection_attempts(struct hapd_blacklist *list,
					  u16 attempts)
{
	if (!list || attempts <= 0 ||
			attempts > MAX_BLACKLIST_CONNECTION_ATTEMPTS)
		return -1;

	list->blacklist_conn_attempts = attempts;
	return 0;
}

/*
 * sta_blacklist_get - obtain pointer to blacklisted station
 * list: pointer to hapd_blacklist
 * addr: mac address of station
 * function iterates through list to find station matching with addr
 * return: sta pointer - Success, NULL - Failure
 */
static struct sta_blacklist *sta_blacklist_get(struct hapd_blacklist *list,
					       const u8 *addr)
{
	struct sta_blacklist *sta = list->head;

	while (sta) {
		if (!os_memcmp(sta->sta, addr, ETH_ALEN))
			return sta;
		sta = sta->next;
	}

	return NULL;
}

/*
 * sta_blacklist_prune: remove expired station entries from the list
 * eloop_ctx: void pointer to eloop context
 * timeout_ctx: void pointer to timeout context
 * function remove expired station entries from blacklist on
 * expiring blacklist timeout
 * return: none
 */
void sta_blacklist_prune(void *eloop_ctx, void *timeout_ctx)
{
	struct hostapd_data *hapd = eloop_ctx;
	struct hapd_blacklist *blacklist = hapd->blacklist;
	struct sta_blacklist  *cur, *prev = NULL, *next = NULL;
	struct os_reltime now;

	os_get_reltime(&now);
	cur = blacklist->head;

	while (cur) {
		if (os_reltime_expired(&now, &cur->time,
				       blacklist->blacklist_timeout)) {
			hostapd_logger(hapd, cur->sta, HOSTAPD_MODULE_IEEE80211,
				       HOSTAPD_LEVEL_INFO, "Remove station "
				       MACSTR " from blacklist",
				       MAC2STR(cur->sta));
			next = cur->next;
			if (!prev)
				blacklist->head = cur->next;
			else
				prev->next = cur->next;

			os_free(cur);
			cur = next;

			blacklist->bl_count--;

			if (!blacklist->bl_count)
				break;
		} else {
			prev = cur;
			cur = cur->next;
		}
	}

	if (!blacklist->bl_count &&
		eloop_is_timeout_registered(sta_blacklist_prune,
					    eloop_ctx, NULL)) {
		eloop_cancel_timeout(sta_blacklist_prune, eloop_ctx, NULL);
		return;
	} else if (blacklist->bl_count > 0) {
		eloop_register_timeout(blacklist->blacklist_timeout, 0,
				       sta_blacklist_prune, eloop_ctx, NULL);
	}
}

/*
 * sta_blacklist_should_reject: check if station is black listed
 * hapd: pointer to hostapd data structure
 * addr: mac address of station
 * connect: is connect request in progress
 * function verifies if station is black listed and takes appropriate
 * action
 * return: TRUE - Success, FALSE - Failure
 */
Boolean sta_blacklist_should_reject(struct hostapd_data *hapd, const  u8 *addr,
				    Boolean connect)
{
	struct sta_blacklist *sta;
	u16 conn_attempts;

	if (!hapd || !hapd->blacklist)
		return FALSE;

	sta = sta_blacklist_get(hapd->blacklist, addr);
	if (!sta)
		return FALSE;

	if (connect) {
		conn_attempts = hapd->blacklist->blacklist_conn_attempts;
		sta->attempts++;
		return (sta->attempts > conn_attempts) ? FALSE : TRUE;
	}

	return TRUE;
}

/*
 * sta_blacklist_add - add station to blacklist
 * hapd: pointer to hostapd data structure
 * addr: mac address of station
 * function add's station to list of black list
 * return: TRUE - Success, FALSE - Failure
 */
Boolean sta_blacklist_add(struct hostapd_data *hapd, const u8 *addr)
{
	struct hapd_blacklist *local;
	struct sta_blacklist *sta;
	Boolean ret = FALSE;

	if (hapd->blacklist == NULL) {
		hapd->blacklist = os_zalloc(sizeof(struct hapd_blacklist));
		if (!hapd->blacklist) {
			hostapd_logger(hapd, NULL, HOSTAPD_MODULE_IEEE80211,
				       HOSTAPD_LEVEL_INFO,
				       "alloc for blacklist failed");
			goto done;
		}
		hapd->blacklist->blacklist_timeout = DEFAULT_BLACKLIST_TIMEOUT;
		hapd->blacklist->blacklist_conn_attempts =
					DEFAULT_BLACKLIST_CONNECTION_ATTEMPTS;
	}

	local = hapd->blacklist;

	sta = sta_blacklist_get(local, addr);
	if (sta) {
		os_get_reltime(&sta->time);
		sta->attempts = 0;
		ret = TRUE;
		goto done;
	}

	if (local->bl_count > MAX_BLACKLIST_COUNT) {
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_WARNING,
			       "reached max black list count of %d",
			       MAX_BLACKLIST_COUNT);
		return FALSE;
	}

	sta = os_zalloc(sizeof(*sta));
	if (!sta) {
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_INFO,
			       "alloc for blacklist sta failed");
		goto done;
	}

	os_memcpy(sta->sta, addr, ETH_ALEN);
	os_get_reltime(&sta->time);

	sta->next = local->head;
	local->head = sta;

	hostapd_logger(hapd, NULL, HOSTAPD_MODULE_IEEE80211,
		       HOSTAPD_LEVEL_INFO, "Added station " MACSTR
		       " to blacklist", MAC2STR(addr));

	local->bl_count++;

	if (local->bl_count == 1)
		eloop_register_timeout(local->blacklist_timeout, 0,
				       sta_blacklist_prune, hapd, NULL);
	ret = TRUE;
done:
	return ret;
}

#endif
