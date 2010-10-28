/*
 * WPA Supplicant - background scan and roaming module: delta
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
#include "eloop.h"
#include "drivers/driver.h"
#include "config_ssid.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "scan.h"
#include "bgscan.h"
#include "bgscan_i.h"

struct bgscan_delta_data {
	struct wpa_supplicant *wpa_s;
	const struct wpa_ssid *ssid;
	int scan_interval;
	int signal_threshold;
	int short_interval; /* use if signal < threshold */
	int long_interval; /* use if signal > threshold */
	struct os_time last_bgscan;
	struct bgscan_signal_monitor_state signal_monitor;
};


static void bgscan_delta_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct bgscan_delta_data *data = eloop_ctx;
	struct wpa_supplicant *wpa_s = data->wpa_s;
	struct wpa_driver_scan_params params;

	os_memset(&params, 0, sizeof(params));
	params.num_ssids = 1;
	params.ssids[0].ssid = data->ssid->ssid;
	params.ssids[0].ssid_len = data->ssid->ssid_len;
	params.freqs = data->ssid->scan_freq;

	/*
	 * A more advanced bgscan module would learn about most like channels
	 * over time and request scans only for some channels (probing others
	 * every now and then) to reduce effect on the data connection.
	 */

	wpa_printf(MSG_DEBUG, "bgscan delta: Request a background scan");
	if (wpa_supplicant_trigger_scan(wpa_s, &params)) {
		wpa_printf(MSG_DEBUG, "bgscan delta: Failed to trigger scan");
		eloop_register_timeout(data->scan_interval, 0,
				       bgscan_delta_timeout, data, NULL);
	} else
		os_get_time(&data->last_bgscan);
}


static int bgscan_delta_get_params(struct bgscan_delta_data *data,
				    const char *params)
{
	const char *pos;

	if (params == NULL)
		return 0;

	data->short_interval = atoi(params);

	pos = os_strchr(params, ':');
	if (pos == NULL)
		return 0;
	pos++;
	data->signal_threshold = atoi(pos);
	pos = os_strchr(pos, ':');
	if (pos == NULL) {
		wpa_printf(MSG_ERROR, "bgscan delta: Missing scan interval "
			   "for high signal");
		return -1;
	}
	pos++;
	data->long_interval = atoi(pos);

	return 0;
}


static void * bgscan_delta_init(struct wpa_supplicant *wpa_s,
				 const char *params,
				 const struct wpa_ssid *ssid)
{
	struct bgscan_delta_data *data;
	struct wpa_connection_info conninfo;

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->wpa_s = wpa_s;
	data->ssid = ssid;
	if (bgscan_delta_get_params(data, params) < 0) {
		os_free(data);
		return NULL;
	}
	if (data->short_interval <= 0)
		data->short_interval = 30;
	if (data->long_interval <= 0)
		data->long_interval = 30;

	wpa_printf(MSG_DEBUG, "bgscan delta: Signal strength threshold %d  "
		   "Short bgscan interval %d  Long bgscan interval %d",
		   data->signal_threshold, data->short_interval,
		   data->long_interval);

	/* Default to long scan interval */
	data->scan_interval = data->long_interval;
	if (data->signal_threshold) {
		bgscan_init_signal_monitor(&data->signal_monitor, wpa_s,
					   data->signal_threshold, 4, 0);

		/*
		 * We cannot assume that we'll be called by the signal
		 * monitor when we enable signal monitoring -- this is
		 * likely on our first association, but not when we are
		 * re-associating.  Therefore, we need to probe the driver
		 * directly to check our current status.
		 */
		if (wpa_drv_connection_poll(wpa_s, &conninfo) == 0) {
			bgscan_update_signal_monitor(&data->signal_monitor,
						     &conninfo);
			if (conninfo.signal <= data->signal_threshold)
				data->scan_interval = data->short_interval;
		}
	}

	wpa_printf(MSG_DEBUG, "bgscan delta: Init scan interval: %d",
		   data->scan_interval);
	eloop_register_timeout(data->scan_interval, 0, bgscan_delta_timeout,
			       data, NULL);

	/*
	 * This function is called immediately after an association, so it is
	 * reasonable to assume that a scan was completed recently. This makes
	 * us skip an immediate new scan in cases where the current signal
	 * level is below the bgscan threshold.
	 */
	os_get_time(&data->last_bgscan);

	return data;
}


static void bgscan_delta_deinit(void *priv)
{
	struct bgscan_delta_data *data = priv;
	eloop_cancel_timeout(bgscan_delta_timeout, data, NULL);
	if (data->signal_threshold)
		bgscan_deinit_signal_monitor(&data->signal_monitor);
	os_free(data);
}


static int bgscan_delta_notify_scan(void *priv,
				     struct wpa_scan_results *scan_res)
{
	struct bgscan_delta_data *data = priv;

	wpa_printf(MSG_DEBUG, "bgscan delta: scan result notification");

	bgscan_poll_signal_monitor(&data->signal_monitor);

	eloop_cancel_timeout(bgscan_delta_timeout, data, NULL);
	eloop_register_timeout(data->scan_interval, 0, bgscan_delta_timeout,
			       data, NULL);

	/*
	 * A more advanced bgscan could process scan results internally, select
	 * the BSS and request roam if needed. This sample uses the existing
	 * BSS/ESS selection routine. Change this to return 1 if selection is
	 * done inside the bgscan module.
	 */

	return 0;
}


static void bgscan_delta_notify_beacon_loss(void *priv)
{
	wpa_printf(MSG_DEBUG, "bgscan delta: beacon loss");
	/* TODO: speed up background scanning */
}


static void bgscan_delta_notify_connection_change(void *priv,
						   struct wpa_connection_info
						   *conninfo)
{
	struct bgscan_delta_data *data = priv;
	int scan = 0;
	struct os_time now;
	int above;

	bgscan_update_signal_monitor(&data->signal_monitor, conninfo);
	if (conninfo->event_type == CONN_RSSI_ABOVE) {
		above = 1;
	} else if (conninfo->event_type == CONN_RSSI_BELOW) {
		above = 0;
	} else
		return;

	if (data->short_interval == data->long_interval ||
	    data->signal_threshold == 0)
		return;

	wpa_printf(MSG_DEBUG, "bgscan delta: signal level changed "
		   "(above=%d current_signal=%d current_noise=%d "
		   "current_txrate=%d))", above, conninfo->signal,
		   conninfo->noise, conninfo->txrate);
	if (data->scan_interval == data->long_interval && !above) {
		wpa_printf(MSG_DEBUG, "bgscan delta: Start using short "
			   "bgscan interval");
		data->scan_interval = data->short_interval;
		os_get_time(&now);
		if (now.sec > data->last_bgscan.sec + 1)
			scan = 1;
	} else if (data->scan_interval == data->short_interval && above) {
		wpa_printf(MSG_DEBUG, "bgscan delta: Start using long bgscan "
			   "interval");
		data->scan_interval = data->long_interval;
		eloop_cancel_timeout(bgscan_delta_timeout, data, NULL);
		eloop_register_timeout(data->scan_interval, 0,
				       bgscan_delta_timeout, data, NULL);
	} else if (!above) {
		/*
		 * Signal dropped further 4 dB. Request a new scan if we have
		 * not yet scanned in a while.
		 */
		os_get_time(&now);
		if (now.sec > data->last_bgscan.sec + 10)
			scan = 1;
	}

	if (scan) {
		wpa_printf(MSG_DEBUG, "bgscan delta: Trigger immediate scan");
		eloop_cancel_timeout(bgscan_delta_timeout, data, NULL);
		eloop_register_timeout(0, 0, bgscan_delta_timeout, data,
				       NULL);
	}
}


const struct bgscan_ops bgscan_delta_ops = {
	.name = "delta",
	.init = bgscan_delta_init,
	.deinit = bgscan_delta_deinit,
	.notify_scan = bgscan_delta_notify_scan,
	.notify_beacon_loss = bgscan_delta_notify_beacon_loss,
	.notify_connection_change = bgscan_delta_notify_connection_change,
};
