/*
 * hostapd / Interface connection logging
 * Copyright (c) 2015 Google, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include "common.h"
#include "common/defs.h"
#include "common/ieee802_11_defs.h"
#include "common/wpa_ctrl.h"
#include "connect_log.h"
#include "steering.h"
#include "ap_drv_ops.h"


static int print_bitmap(char *buf, size_t buflen, u8 *bitmap, size_t bitmap_len)
{
	int i, ret, len = 0;
	ret = os_snprintf(buf + len, buflen - len, "0x");
	len += ret;
	for (i = 0; i < bitmap_len; ++i) {
		ret = os_snprintf(buf + len, buflen - len, "%02x", bitmap[i]);
		len += ret;
	}
	return len;
}

/**
 * convert disconnect events to readable format
 */
static const char *disconnect_log_event_str(connection_event_reason event)
{
	switch (event) {
		case REASON_NONE:
			return "none";
		case REASON_UNSPECIFIED_FAIILURE:
			return "unspecified";
		case REASON_AUTH_REJECT_UNSUPPORTED_ALG:
			return "unsupported_alg";
		case REASON_AUTH_REJECT_BLACKLISTED:
			return "sta_blacklisted";
		case REASON_AUTH_REJECT_MIC_FAIL:
			return "mic_fail";
		case REASON_AUTH_REJECT_UNKNOWN_TRANSACTION:
			return "unknown_transaction";
		case REASON_AUTH_REJECT_SUGGESTED_BSS_TRANSITION:
			return "suggested_bss_transition";
		case REASON_AUTH_REJECT_UNABLE_TO_HANDLE_NEW_STA:
			return "unable_to_handle_sta";
		case REASON_AUTH_REJECT_ALLOC_FAIL:
			return "alloc_fail";
		case REASON_ASSOC_REJECT_STEER:
			return "reject_steer";
		case REASON_ASSOC_REJECT_REACHED_MAX_AID:
			return "reached_max_aid";
		case REASON_ASSOC_REJECT_MIC_FAIL:
			return "mic_fail";
		case REASON_ASSOC_REJECT_LARGE_LISTEN_INTERVAL:
			return "large_listen_interval";
		case REASON_ASSOC_REJECT_INCORRECT_ELEMENTS:
			return "incorrect_elements";
		case REASON_ASSOC_REJECT_INCORRECT_SSID:
			return "incorrect_ssid";
		case REASON_ASSOC_REJECT_INCORRECT_WMM:
			return "incorrect_wmm";
		case REASON_ASSOC_REJECT_NO_SUPPORTED_RATES:
			return "no_supported_rates";
		case REASON_ASSOC_REJECT_INVALID_LENGTH:
			return "invalid_length";
		case REASON_ASSOC_REJECT_ALLOC_FAIL:
			return "alloc_fail";
		case REASON_ASSOC_REJECT_BLACKLISTED:
			return "sta_blacklisted";
		case REASON_FAILED_TO_ADD_STA:
			return "failed_to_add";
		case REASON_NO_ACK:
			return "no_ack";
		case REASON_DISCONNECT_FROM_CLIENT:
			return "from_client";
		case REASON_DISCONNECT_DISASSOC_CLI:
			return "disassoc_cli";
		case REASON_DISCONNECT_DEAUTH_CLI:
			return "deauth_cli";
		case REASON_DISCONNECT_BSS_TM_REQ_CLI:
			return "bss_tm_cli";
		case REASON_DISCONNECT_ASSOC_OTHER_BSS:
			return "other_bss";
		case REASON_DISCONNECT_IAPP_NOTIFY:
			return "iapp_notify";
		case REASON_DISCONNECT_LOW_ACK:
			return "low_ack";
		case REASON_DISCONNECT_INACTIVITY:
			return "inactivity";
		case REASON_DISCONNECT_WPA_AUTH:
			return "wpa_auth";
		case REASON_DISCONNECT_INSUFFICIENT_ENTROPY:
			return "insufficient_entropy";
		case REASON_DISCONNECT_INCORRECT_RSN_IE:
			return "incorrect_rsn_ie";
		case REASON_DISCONNECT_SET_KEY_FAILURE:
			return "setkey_failure";
		case REASON_DISCONNECT_EAPOL_M1_TIMEOUT:
			return "eapol_m1_timeout";
		case REASON_DISCONNECT_EAPOL_M3_TIMEOUT:
			return "eapol_m3_timeout";
		case REASON_DISCONNECT_GTK_M1_TIMEOUT:
			return "gtk_m1_timeout";
		case REASON_DISCONNECT_PSK_MISMATCH:
			return "psk_mismatch";
		default:
			return "unknown";
	}
}

static const char *connect_log_event_str(connection_event event)
{
	switch (event) {
	case CONNECTION_EVENT_AUTH:
		return AP_STA_AUTH;
		break;
	case CONNECTION_EVENT_AUTH_RESP:
		return AP_STA_AUTH_RESP;
		break;
	case CONNECTION_EVENT_ASSOC:
		return AP_STA_ASSOC;
		break;
	case CONNECTION_EVENT_ASSOC_RESP:
		return AP_STA_ASSOC_RESP;
		break;
	case CONNECTION_EVENT_CONNECT:
		return AP_STA_CONNECT;
		break;
	case CONNECTION_EVENT_DISCONNECT:
		return AP_STA_DISCONNECT;
		break;
	case CONNECTION_EVENT_DISASSOC_RESP:
		return AP_STA_DISASSOC_RESP;
	default:
		return NULL;
		break;
	}
}

static Boolean is_valid_delta_time(struct os_reltime *delta_time)
{
	if (!delta_time) {
		return FALSE;
	}
	if (delta_time->sec == 0 && delta_time->usec == 0) {
		return FALSE;
	}
	return TRUE;
}

/**
 * log connection specific event on to control socket.
 */
void connect_log_event(struct hostapd_data *hapd, const u8 *sta_addr,
		       connection_event c_event, int status,
		       connection_event_reason event_reason,
		       struct sta_info *sta, int frame_status,
		       int signal, int s_reason,
		       struct os_reltime *probe_delta_time,
		       struct os_reltime *steer_delta_time,
		       struct os_reltime *defer_delta_time,
		       int eapol_ack_bitmap)
{
	const char *event_str;
	char *buf;
	const int buflen = 1024;
	int len = 0, ret = 0;
	struct os_time tv;
	struct hostap_sta_driver_data sta_data;
	struct ieee80211_ht_capabilities *ht = NULL;
	struct ieee80211_vht_capabilities *vht = NULL;

	event_str = connect_log_event_str(c_event);
	if (!event_str) {
		hostapd_logger(hapd->msg_ctx, sta_addr, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_INFO,
			       "unknown connection event %d", c_event);
		return;
	}

	buf = os_malloc(buflen);
	if (buf == NULL) {
		hostapd_logger(hapd->msg_ctx, sta_addr, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_INFO,
			       "failed to alloc connection event buffer");
		return;
	}
	ret = os_snprintf(buf + len, buflen - len, "%s", event_str);
	len += ret;
	/* Remove any trailing space from event_str */
	if (len > 0 && buf[len-1] == ' ') {
		buf[--len] = '\0';
	}
	ret = os_snprintf(buf + len, buflen - len, " " MACSTR,
			  MAC2STR(sta_addr));
	len += ret;
	os_get_time(&tv);
        /*
         * To print timestamp in msec without 64-bit arithametic, append
         * 3 digit msec to the seconds field.
         */
	ret = os_snprintf(buf + len, buflen - len, " timestamp:%u%03u",
			  (unsigned long)tv.sec , (unsigned long)tv.usec/1000);
	len += ret;

	if (eapol_ack_bitmap > -1) {
		ret = os_snprintf(buf + len, buflen - len, " eapol_ack_bitmap:%d",
				  eapol_ack_bitmap);
		len += ret;
	}

	ret = os_snprintf(buf + len, buflen - len, " success:%d", status);
	len += ret;
	ret = os_snprintf(buf + len, buflen - len, " event_reason:%s",
			  disconnect_log_event_str(event_reason));
	len += ret;

	if (frame_status != INVALID_FRAME_STATUS) {
		ret = os_snprintf(buf + len, buflen - len, " frame_status:%d",
				  frame_status);
		len += ret;
	}

	/*
	 * read rssi and rate from driver only if sta structure is valid to
	 * avoid additional delay in fetching the rssi data from driver.
         */
	if (sta && !hostapd_drv_read_sta_data(hapd, &sta_data, sta_addr)) {
		ret = os_snprintf(buf + len, buflen - len,
				 " last_rx_rssi:%d",
				  sta_data.last_rssi);
		len += ret;
		ret = os_snprintf(buf + len, buflen - len,
				 " tx_rate_kbps:%ld",
				  sta_data.current_tx_rate * 100);
		len += ret;

		if (sta_data.tx_rate_info.mcs >= 0) {
			ret = os_snprintf(buf + len, buflen - len,
					  " tx_rate_mcs:%d",
					  sta_data.tx_rate_info.mcs);
			len += ret;
		}

		ret = os_snprintf(buf + len, buflen - len, " tx_rate_bw:%d",
				  sta_data.tx_rate_info.bw);
		len += ret;

		ret = os_snprintf(buf + len, buflen - len, " tx_rate_sgi:%d",
				  sta_data.tx_rate_info.sgi ? 1 : 0);
		len += ret;

		if (sta_data.tx_rate_info.vht_mcs >= 0) {
			ret = os_snprintf(buf + len, buflen - len,
					  " tx_rate_vht_mcs:%d",
					  sta_data.tx_rate_info.vht_mcs);
			len += ret;
		}

		if (sta_data.tx_rate_info.vht_nss > 0) {
			ret = os_snprintf(buf + len, buflen - len,
					  " tx_rate_vht_nss:%d",
					  sta_data.tx_rate_info.vht_nss);
			len += ret;
		}

		ret = os_snprintf(buf + len, buflen - len,
				  " sta_rx_info:rx_rate_kbps:%ld",
				  sta_data.current_rx_rate * 100);
		len += ret;

		if (sta_data.rx_rate_info.mcs >= 0) {
			ret = os_snprintf(buf + len, buflen - len,
					  " rx_rate_mcs:%d ",
					  sta_data.rx_rate_info.mcs);
			len += ret;
		}

		ret = os_snprintf(buf + len, buflen - len, " rx_rate_bw:%d",
				  sta_data.rx_rate_info.bw);
		len += ret;

		ret = os_snprintf(buf + len, buflen - len, " rx_rate_sgi:%d",
				  sta_data.rx_rate_info.sgi ? 1 : 0);
		len += ret;

		if (sta_data.rx_rate_info.vht_mcs >= 0) {
			ret = os_snprintf(buf + len, buflen - len,
					  " rx_rate_vht_mcs:%d",
					  sta_data.rx_rate_info.vht_mcs);
			len += ret;
		}

		if (sta_data.rx_rate_info.vht_nss > 0) {
			ret = os_snprintf(buf + len, buflen - len,
					  " rx_rate_vht_nss:%d",
					  sta_data.rx_rate_info.vht_nss);
			len += ret;
		}

		ret = os_snprintf(buf + len, buflen - len, " avg_rssi:%d",
				  sta_data.avg_rssi);
		len += ret;
	}

	if (sta && c_event == CONNECTION_EVENT_CONNECT) {
		if (sta->vht_capabilities)
			vht = sta->vht_capabilities;
		if (sta->ht_capabilities)
			ht = sta->ht_capabilities;

		ret = os_snprintf(buf + len, buflen - len, " nss:%d mode:%s",
				  vht ? ieee802_11_find_vht_nss(vht) :
				  ht ? ieee802_11_find_ht_nss(ht) : 1,
				  vht ? "vht" : ht ? "ht" : " legacy");
		len += ret;
	}

	if (signal != INVALID_SIGNAL) {
		ret = os_snprintf(buf + len, buflen - len, " frame_rssi:%d",
				  signal);
		len += ret;
	}
	if (s_reason != INVALID_STEERING_REASON) {
		ret = os_snprintf(buf + len, buflen - len, " steering_reason:%s",
				  steering_reason_str(s_reason));
		len += ret;
	}
	if (is_valid_delta_time(probe_delta_time)) {
		ret = os_snprintf(buf + len, buflen - len, " probe_delta_ms:%ld",
				  (probe_delta_time->sec * 1000 +
				   probe_delta_time->usec / 1000));
		len += ret;
	}
	if (is_valid_delta_time(steer_delta_time)) {
		ret = os_snprintf(buf + len, buflen - len, " steer_delta_ms:%ld",
				  (steer_delta_time->sec * 1000 +
				   steer_delta_time->usec / 1000));
		len += ret;
	}
	if (is_valid_delta_time(defer_delta_time)) {
		ret = os_snprintf(buf + len, buflen - len, " defer_delta_ms:%ld",
				  (defer_delta_time->sec * 1000 +
				   defer_delta_time->usec / 1000));
		len += ret;
	}
	if (sta && sta->ext_capab) {
		ret = os_snprintf(buf + len, buflen - len, " ext_capability:");
		len += ret;
		ret = print_bitmap(buf + len, buflen-len, sta->ext_capab,
				   sta->ext_capab_len);
		len += ret;
	}
	wpa_msg(hapd->msg_ctx, MSG_INFO, "%s", buf);
	hostapd_logger(hapd->msg_ctx, NULL,
	               HOSTAPD_MODULE_IEEE80211, HOSTAPD_LEVEL_INFO,
		       "%s", buf);
	os_free(buf);
}
