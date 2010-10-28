/*
 * WPA Supplicant - background scan and roaming interface
 * Copyright (c) 2009-2010, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "includes.h"

#include "common.h"
#include "wpa_supplicant_i.h"
#include "config_ssid.h"
#include "driver_i.h"
#include "bgscan.h"
#include "bgscan_i.h"

#ifdef CONFIG_BGSCAN_SIMPLE
extern const struct bgscan_ops bgscan_simple_ops;
#endif /* CONFIG_BGSCAN_SIMPLE */
#ifdef CONFIG_BGSCAN_LEARN
extern const struct bgscan_ops bgscan_learn_ops;
#endif /* CONFIG_BGSCAN_LEARN */

static const struct bgscan_ops * bgscan_modules[] = {
#ifdef CONFIG_BGSCAN_SIMPLE
	&bgscan_simple_ops,
#endif /* CONFIG_BGSCAN_SIMPLE */
#ifdef CONFIG_BGSCAN_LEARN
	&bgscan_learn_ops,
#endif /* CONFIG_BGSCAN_LEARN */
	NULL
};


int bgscan_init(struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid)
{
	const char *name = ssid->bgscan;
	const char *params;
	size_t nlen;
	int i;
	const struct bgscan_ops *ops = NULL;

	bgscan_deinit(wpa_s);
	if (name == NULL)
		return 0;

	params = os_strchr(name, ':');
	if (params == NULL) {
		params = "";
		nlen = os_strlen(name);
	} else {
		nlen = params - name;
		params++;
	}

	for (i = 0; bgscan_modules[i]; i++) {
		if (os_strncmp(name, bgscan_modules[i]->name, nlen) == 0) {
			ops = bgscan_modules[i];
			break;
		}
	}

	if (ops == NULL) {
		wpa_printf(MSG_ERROR, "bgscan: Could not find module "
			   "matching the parameter '%s'", name);
		return -1;
	}

	wpa_s->bgscan_priv = ops->init(wpa_s, params, ssid);
	if (wpa_s->bgscan_priv == NULL)
		return -1;
	wpa_s->bgscan = ops;
	wpa_printf(MSG_DEBUG, "bgscan: Initialized module '%s' with "
		   "parameters '%s'", ops->name, params);

	return 0;
}


void bgscan_deinit(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->bgscan && wpa_s->bgscan_priv) {
		wpa_printf(MSG_DEBUG, "bgscan: Deinitializing module '%s'",
			   wpa_s->bgscan->name);
		wpa_s->bgscan->deinit(wpa_s->bgscan_priv);
		wpa_s->bgscan = NULL;
		wpa_s->bgscan_priv = NULL;
	}
}


int bgscan_notify_scan(struct wpa_supplicant *wpa_s,
		       struct wpa_scan_results *scan_res)
{
	if (wpa_s->bgscan && wpa_s->bgscan_priv)
		return wpa_s->bgscan->notify_scan(wpa_s->bgscan_priv,
						  scan_res);
	return 0;
}


void bgscan_notify_beacon_loss(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->bgscan && wpa_s->bgscan_priv)
		wpa_s->bgscan->notify_beacon_loss(wpa_s->bgscan_priv);
}


void bgscan_notify_connection_change(struct wpa_supplicant *wpa_s,
				 struct wpa_connection_info *conninfo)
{
	if (wpa_s->bgscan && wpa_s->bgscan_priv)
		wpa_s->bgscan->notify_connection_change(wpa_s->bgscan_priv,
							conninfo);
}


static void bgscan_reset_signal_monitor(void *eloop_ctx, void *timeout_ctx)
{
	struct bgscan_signal_monitor_state *sm_state = eloop_ctx;

	wpa_drv_connection_monitor(sm_state->wpa_s, sm_state->rssi_threshold,
				   sm_state->hysteresis,
				   sm_state->txrate_threshold);
}


void bgscan_update_signal_monitor(struct bgscan_signal_monitor_state *sm_state,
				  struct wpa_connection_info *conni)
{
	struct os_time now;
	int threshold = conni->noise + sm_state->headroom;

	if (conni->noise == WPA_CONN_NOISE_UNKNOWN)
		return;

	if (threshold >= sm_state->rssi_threshold -
	        BGSCAN_NOISEFLOOR_TOLERANCE &&
	    threshold <= sm_state->rssi_threshold +
	        BGSCAN_NOISEFLOOR_TOLERANCE)
		return;

	wpa_printf(MSG_DEBUG, "%s: noisefloor update: %d -> %d",
		   __func__, sm_state->rssi_threshold - sm_state->headroom,
		   conni->noise);
	
	sm_state->rssi_threshold = threshold;
	
	/*
	 * Schedule a noisefloor adjustment.  Do this as a timeout callback,
	 * so it is implicitly throttled.
	 */
	eloop_cancel_timeout(bgscan_reset_signal_monitor, sm_state, NULL);
	eloop_register_timeout(BGSCAN_NOISEFLOOR_UPDATE_DELAY, 0,
			       bgscan_reset_signal_monitor, sm_state, NULL);
}


void bgscan_poll_signal_monitor(struct bgscan_signal_monitor_state *sm_state)
{
	struct wpa_connection_info conninfo;

	if (wpa_drv_connection_poll(sm_state->wpa_s, &conninfo) != 0)
		return;

	wpa_printf(MSG_DEBUG, "%s: bgscan poll noisefloor: %d ",
		   __func__, conninfo.noise);

	bgscan_update_signal_monitor(sm_state, &conninfo);
}


void bgscan_init_signal_monitor(struct bgscan_signal_monitor_state *sm_state,
				struct wpa_supplicant *wpa_s,
				int signal_threshold,
				int hysteresis,
				int txrate_threshold) {

	sm_state->wpa_s = wpa_s;
	sm_state->rssi_threshold = signal_threshold;
	sm_state->hysteresis = hysteresis;
	sm_state->txrate_threshold = txrate_threshold;
	sm_state->headroom = sm_state->rssi_threshold -
		BGSCAN_DEFAULT_NOISE_FLOOR; 

	if (wpa_drv_connection_monitor(wpa_s, signal_threshold, hysteresis,
				       txrate_threshold) < 0) {
		wpa_printf(MSG_ERROR, "bgscan simple: Failed to enable "
			   "signal strength monitoring");
	}
}


void bgscan_deinit_signal_monitor(struct bgscan_signal_monitor_state *sm_state)
{
	wpa_drv_connection_monitor(sm_state->wpa_s, 0, 0, 0);
	eloop_cancel_timeout(bgscan_reset_signal_monitor, sm_state, NULL);
}
