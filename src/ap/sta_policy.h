/*
 * hostapd / AP configuration knobs
 * Copyright(c) 2017 - Google Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef AP_CONFIG_KNOBS_H
#define AP_CONFIG_KNOBS_H

/* PATH where sta policy file resides */
#define STA_POLICY_DIR "/var/lib/ap/ap_wireless_policy/"
/* Prefix used for sta policy files name */
#define STA_POLICY_FILENAME "/sta_policy.conf"

/* Max STA Policy entry Size expected */
#define STA_POLICY_ENTRYSIZE 512
#define MAX_STA_POLICY_SIZE 4096

#define MAX_MPDU_SPACING       7
#define MAX_RATES_SUPPORTED    32

#define CONFIGURABLE_BITS_CAP 		WLAN_CAPABILITY_SHORT_PREAMBLE
#define CONFIGURABLE_BITS_HT_CAP 	HT_CAP_INFO_LDPC_CODING_CAP |\
					HT_CAP_INFO_SHORT_GI20MHZ |\
					HT_CAP_INFO_SHORT_GI40MHZ |\
					HT_CAP_INFO_MAX_AMSDU_SIZE |\
					HT_CAP_INFO_TX_STBC |\
					HT_CAP_INFO_SMPS_MASK
#define CONFIGURABLE_BITS_MPDU		0x1F
#define CONFIGURABLE_BITS_HT_OP_INFO	HT_INFO_HT_PARAM_RIFS_MODE
#define CONFIGURABLE_BITS_VHT_CAP	VHT_CAP_MAX_MPDU_LENGTH_MASK |\
					VHT_CAP_RXLDPC |\
					VHT_CAP_SHORT_GI_80 |\
					VHT_CAP_TXSTBC
#define RATE_MASK			0x7F

/* STA Policy Flags */
#define FLAG_AMPDU_SUBFRAME_COUNT 	0x01
#define FLAG_PSPOLL_STA_KO_ENABLED 	0x02

/* struct sta_policy
 */
struct sta_policy {
	struct 		sta_policy *next;
	uint8_t 	sta_id[ETH_ALEN];

	/* Params that would be exposed to user */
	uint16_t 	capability;

#define MAX_RATES_SUPPORTED 32
	uint16_t	num_sup_rates;
	uint8_t 	supp_rates[MAX_RATES_SUPPORTED];
	/* HT Capability */
	uint16_t 	ht_capab_info;
        uint8_t 	ht_ampdu_param;
	/* HT Operation mode */
	uint8_t 	ht_op_info;
	/* VHT Capability */
	uint32_t 	vht_capab_info;

	uint8_t		ampdu_subframe_count;
	uint8_t		pspoll_sta_ko_enabled;

	/* User Mask, to configure params */
	uint16_t 	capability_mask;
	uint16_t 	ht_capab_info_mask;
	uint8_t 	ht_ampdu_param_mask;
	uint8_t		ht_op_info_mask;
	uint32_t 	vht_capab_info_mask;
	uint16_t	flags;
};

/* struct per_interface_config
 */
struct per_interface_config {
	char 		iface_name[IFNAMSIZ + 1];
	char 		*cfg_file;

	/* Current associating STA's MAC address */
	uint8_t 	associating_sta[ETH_ALEN];

	/* Flag to update only the assoc_resp IE's */
	uint8_t 	assoc_resp;

	/* MASKS */
	uint16_t 	_capability_mask;
	uint16_t 	_ht_capab_info_mask;
	uint8_t 	_ht_ampdu_param_mask;
	uint8_t		_ht_op_info_mask;
	uint32_t 	_vht_capab_info_mask;

	struct sta_policy *l_sta_policy;
};

/* Enum for STA policy Parameters Supported */
typedef enum {
	POLICY_PARAM_STA_ID = 0,
	POLICY_PARAM_SUPP_RATES,
	POLICY_PARAM_SHORT_PREAMBLE,
	POLICY_PARAM_SGI20,
	POLICY_PARAM_SGI40,
	POLICY_PARAM_LDPC,
	POLICY_PARAM_SMPS,
	POLICY_PARAM_MAX_AMSDU_LEN,
	POLICY_PARAM_RIFS,
	POLICY_PARAM_MAX_AMPDU_LEN,
	POLICY_PARAM_RX_LDPC,
	POLICY_PARAM_SGI80,
	POLICY_PARAM_AMPDU_SUBFRAME_COUNT,
	POLICY_PARAM_PSPOLL_STA_KO_ENABLED,
	POLICY_PARAM_MIN_MPDU_SPACING,
	POLICY_PARAM_TXSTBC,
	POLICY_PARAM_MAX
} POLICY_PARAM_LIST;

/**
 * Initialization function for STA policy module.
 * Should be called for every hostapd_iface init.
 * This function allocates the required memory and reads
 * the sta policy file based on the interface being
 * initialized.
 *
 * Returns 0 - Success
 * 	  -1 - Failure
 */
int stapolicy_interface_init(struct hostapd_iface *iface);

/**
 * This function will initilalize the Dynamic Mask values of the
 * sta policy params for the given interface
 */
int stapolicy_cfg_init(struct hostapd_iface *iface);

/**
 * Deinitialization function for Config knob.
 * This function deallocates memory/resources allocated
 */
void stapolicy_interface_deinit(struct hostapd_iface *iface);

/**
 * Adds an entry into sta_policy file for the given interface
 * Retruns 0 on success,
 *        -1 on failure
 */
int sta_policy_add(struct hostapd_data *hapd, char *buf);

/**
 * Delete an Entry in sta_policy file on a given interface
 * Returns 0 on success,
 *        -1 on failure
 */
int sta_policy_del(struct hostapd_data *hapd, char *buf);

/**
 * Reply with the existing sta_policy setting for the given sta
 * sta_id=00:00:00:00:00:00 indicates for all STA setting request
 * Returns 0 on success,
 *        -1 on failure
 */
int sta_policy_get(struct hostapd_data *hapd, char *buf,
					char *reply, int reply_size);

/**
 * Create the Supported rates EID and Extended rates EID if there
 * is a sta_policy entry settings available for the given sta_addr
 * Return -1 if no EID added,
 *         0 incremented eid pointer if EID added
 */
u8 *sta_policy_copy_supp_rate(struct hostapd_data *hapd, u8 *sta_addr,
						u8 *eid, size_t *res);

/**
 * Copy the Existing Per STA supported rate to the buffer passed,
 * if the sta_id matched the list
 * Returns value <= 0 on Failure
 * 	   No of bytes copied on success
 */
int sta_policy_get_supp_rate(struct hostapd_data *hapd, u8 *sta_addr,
						u8 *rate);

/* Copy destination STA addr, and initmate assoc initiation*/
void sta_policy_begin_assoc_resp(struct hostapd_data *hapd, uint8_t *sta_addr);
void sta_policy_end_assoc_resp(struct hostapd_data *hapd);

/**
 * Update the Fixed capabilitie with configured sta policy
 */
void sta_policy_update_capab(struct hostapd_data *hapd,
				uint16_t *capability);

/**
 * Update the HT capabilitie with configured sta policy
 */
void sta_policy_update_ht_cap(struct hostapd_data *hapd,
			 struct ieee80211_ht_capabilities *cap);

/**
 * Update the VHT capabilitie with configured sta policy
 */
void sta_policy_update_vht_cap(struct hostapd_data *hapd,
			 struct ieee80211_vht_capabilities *cap);

/**
 * Send the STA_policy events
 */
void sta_policy_send_event(struct hostapd_data *, uint8_t *);

#endif /* AP_CONFIG_KNOBS_H */
