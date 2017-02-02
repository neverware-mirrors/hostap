/*
 * hostapd / Interface connection logging.
 * Copyright (c) 2015 Google, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef CONNECTION_LOG_H
#define CONNECTION_LOG_H

#include "hostapd.h"
#include "sta_info.h"

typedef enum {
	CONNECTION_EVENT_AUTH,
	CONNECTION_EVENT_AUTH_RESP,
	CONNECTION_EVENT_ASSOC,
	CONNECTION_EVENT_ASSOC_RESP,
	CONNECTION_EVENT_CONNECT,
	CONNECTION_EVENT_DISCONNECT,
	CONNECTION_EVENT_DISASSOC_RESP,
} connection_event;

/* reasons for the events */
typedef enum {
	REASON_NONE,
	REASON_ASSOC_REJECT_STEER,
	REASON_ASSOC_REJECT_REACHED_MAX_AID,
	REASON_ASSOC_REJECT_MIC_FAIL,
	REASON_ASSOC_REJECT_LARGE_LISTEN_INTERVAL,
	REASON_ASSOC_REJECT_INCORRECT_ELEMENTS,
	REASON_ASSOC_REJECT_INCORRECT_SSID,
	REASON_ASSOC_REJECT_INCORRECT_WMM,
	REASON_ASSOC_REJECT_NO_SUPPORTED_RATES,
	REASON_ASSOC_REJECT_INVALID_LENGTH,
	REASON_ASSOC_REJECT_ALLOC_FAIL,
	REASON_FAILED_TO_ADD_STA,
	REASON_NO_ACK,
	REASON_DISCONNECT_FROM_CLIENT,
	REASON_DISCONNECT_DISASSOC_CLI,
	REASON_DISCONNECT_DEAUTH_CLI,
	REASON_DISCONNECT_BSS_TM_REQ_CLI,
	REASON_DISCONNECT_ASSOC_OTHER_BSS,
	REASON_DISCONNECT_IAPP_NOTIFY,
	REASON_DISCONNECT_LOW_ACK,
	REASON_DISCONNECT_INACTIVITY,
	REASON_DISCONNECT_WPA_AUTH,
	REASON_DISCONNECT_INSUFFICIENT_ENTROPY,
	REASON_DISCONNECT_INCORRECT_RSN_IE,
	REASON_DISCONNECT_SET_KEY_FAILURE,
	REASON_DISCONNECT_EAPOL_M1_TIMEOUT,
	REASON_DISCONNECT_EAPOL_M3_TIMEOUT,
	REASON_DISCONNECT_GTK_M1_TIMEOUT,
	REASON_DISCONNECT_PSK_MISMATCH
} connection_event_reason;

#define INVALID_STEERING_REASON -1
#define INVALID_FRAME_STATUS -1
#define INVALID_SIGNAL 0xffff
/**
 * log connection specific event.
 */

#ifdef HOSTAPD
void connect_log_event(struct hostapd_data *hapd, const u8 *sta_addr,
		       connection_event c_event, int status,
		       connection_event_reason event_reason,
		       struct sta_info *sta, int frame_status,
		       int signal, int s_reason,
		       struct os_reltime *probe_delta_time,
		       struct os_reltime *steer_delta_time,
		       struct os_reltime *defer_delta_time);
#else  /* HOSTAPD */
#define connect_log_event(args...) do { } while (0)
#endif /* HOSTAPD */

#endif /* CONNECTION_LOG_H */
