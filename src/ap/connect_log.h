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
	CONNECTION_EVENT_MESH_NEW_PEER,
	CONNECTION_EVENT_MESH_AUTH,
	CONNECTION_EVENT_MESH_CONNECT,
	CONNECTION_EVENT_MESH_DISCONNECT,
} connection_event;

/* reasons for the events */
typedef enum {
	REASON_NONE,
	REASON_UNSPECIFIED_FAIILURE,
	REASON_AUTH_REJECT_UNSUPPORTED_ALG,
	REASON_AUTH_REJECT_BLACKLISTED,
	REASON_AUTH_REJECT_MIC_FAIL,
	REASON_AUTH_REJECT_UNKNOWN_TRANSACTION,
	REASON_AUTH_REJECT_SUGGESTED_BSS_TRANSITION,
	REASON_AUTH_REJECT_UNABLE_TO_HANDLE_NEW_STA,
	REASON_AUTH_REJECT_ALLOC_FAIL,
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
	REASON_ASSOC_REJECT_BLACKLISTED,
	REASON_FAILED_TO_ADD_STA,
	REASON_NO_ACK,
	REASON_ASSOC_RESP_SEND_FAIL,
	REASON_ASSOC_RESP_STATUS_NOT_SUCCESS,
	REASON_DISASSOC_ACK,
	REASON_DISASSOC_NO_ACK,
	REASON_DISASSOC_NO_DRIVER_RESPONSE,
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
	REASON_DISCONNECT_PSK_MISMATCH,
	REASON_MESH_AUTH_SAE_FAIL,
	REASON_MESH_AUTH_SAE_BLOCK,
	REASON_MESH_DISCONNECT_CLOSE_RCVD,
	REASON_MESH_DISCONNECT_MAX_RETRIES,
	REASON_MESH_DISCONNECT_PEERING_CANCELLED,
	REASON_MESH_DISCONNECT_CONFIRM_TIMEOUT,
	REASON_MESH_DISCONNECT_CONFIG_POLICY_VIOLATION,
	REASON_MESH_DISCONNECT_INACTIVITY
} connection_event_reason;

#define INVALID_STEERING_REASON -1
#define INVALID_FRAME_STATUS -1
#define INVALID_SIGNAL 0xffff

/**
 * log connection specific event.
 */
void log_event(struct hostapd_data *hapd, const u8 *sta_addr,
		       connection_event c_event, int status,
		       connection_event_reason event_reason,
		       struct sta_info *sta, int frame_status,
		       int signal, int s_reason,
		       struct os_reltime *probe_delta_time,
		       struct os_reltime *steer_delta_time,
		       struct os_reltime *defer_delta_time,
		       int eapol_ack_bitmap);


#ifdef HOSTAPD
#define connect_log_event(args...) log_event(args)
#else  /* HOSTAPD */
#define connect_log_event(args...) do { } while (0)
#endif /* HOSTAPD */

#ifdef CONFIG_MESH
#define mesh_connect_log_event(args...) log_event(args)
#else
#define mesh_connect_log_event(args...) do { } while (0)
#endif

#endif /* CONNECTION_LOG_H */
