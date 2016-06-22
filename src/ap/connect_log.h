/*
 * hostapd / Interface connection logging.
 * Copyright (c) 2015 Google, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef CONNECTION_LOG_H
#define CONNECTION_LOG_H

typedef enum {
	CONNECTION_EVENT_AUTH,
	CONNECTION_EVENT_AUTH_RESP,
	CONNECTION_EVENT_ASSOC,
	CONNECTION_EVENT_ASSOC_RESP,
	CONNECTION_EVENT_CONNECT,
	CONNECTION_EVENT_DISCONNECT,
} connection_event;

/* reasons for the events */
typedef enum {
	REASON_NONE,
	REASON_ASSOC_REJECT_STEER,
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
	REASON_DISCONNECT_WPA_AUTH
} connection_event_reason;

#define INVALID_STEERING_REASON -1
#define INVALID_FRAME_STATUS -1
#define INVALID_SIGNAL 0xffff
/**
 * log connection specific event.
 */

#ifdef HOSTAPD
void connect_log_event(struct hostapd_data *hapd, u8 *sta_addr,
		       connection_event c_event, int status,
		       connection_event_reason event_reason,
		       struct sta_info *sta, int frame_status,
		       int signal, int s_reason,
		       struct os_reltime *probe_delta_time,
		       struct os_reltime *steer_delta_time);
#else  /* HOSTAPD */
#define connect_log_event(args...) do { } while (0)
#endif /* HOSTAPD */

#endif /* CONNECTION_LOG_H */
