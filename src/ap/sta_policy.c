/*
 * hostapd / AP configuration knobs
 * Copyright(c) 2017 - Google Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "utils/wpa_debug.h"
#include "common/wpa_ctrl.h"
#include "common/ieee802_11_defs.h"
#include "hostapd.h"
#include "sta_info.h"
#include "ap/sta_policy.h"

#define STR_NCMP(str, cmpstr) os_strncmp(str, cmpstr, strlen(cmpstr))

static const char *config_params[] = {
	"sta_id=",
	"supp_rates=",
	"short_preamble=",
	"sgi20=",
	"sgi40=",
	"ldpc=",
	"smps=",
	"max_amsdu_len=",
	"rifs=",
	"max_ampdu_len=",
	"rx_ldpc=",
	"sgi80=",
	"ampdu_subframe_count=",
	"pspoll_sta_ko_enabled="
};

/**
 * Returns the interface name used for steering this BSS.  This corresponds to
 * the name of the first BSS on the interface.
 */
static inline char *get_iface_name(const struct hostapd_data *hapd)
{
	return hapd->iface->bss[0]->conf->iface;
}

void sta_policy_begin_assoc_resp(struct hostapd_data *hapd, uint8_t *sta_addr)
{
	struct per_interface_config *i_cfg = hapd->iface->i_cfg;

	if (!i_cfg)
		return;

	os_memcpy(i_cfg->associating_sta, sta_addr, ETH_ALEN);
	i_cfg->assoc_resp = 1;
}

void sta_policy_end_assoc_resp(struct hostapd_data *hapd)
{
	struct per_interface_config *i_cfg = hapd->iface->i_cfg;

	if (!i_cfg)
		return;

	os_memset(i_cfg->associating_sta, 0, ETH_ALEN);
	i_cfg->assoc_resp = 0;
}

static void sta_policy_dump(const struct sta_policy *cfg)
{
	if (cfg != NULL) {
		wpa_printf(MSG_INFO, "STA_ID: "MACSTR, MAC2STR(cfg->sta_id));
		wpa_printf(MSG_INFO, "num_sup_rates=%d", cfg->num_sup_rates);
		wpa_hexdump_ascii(MSG_INFO, "Supp Rates:", cfg->supp_rates,
							cfg->num_sup_rates);
		wpa_printf(MSG_INFO, "Param read:\n"
				"Capab=0x%x [Mask:0x%x]\n"
				"ht_capab_info=0x%x [Mask:0x%x]\n"
				"ht_ampdu_param=0x%x [Mask:0x%x]\n"
				"vht_capab_info=0x%x [Mask:0x%x]\n",
				cfg->capability, cfg->capability_mask,
				cfg->ht_capab_info, cfg->ht_capab_info_mask,
				cfg->ht_ampdu_param, cfg->ht_ampdu_param_mask,
				cfg->vht_capab_info, cfg->vht_capab_info_mask);
	}
}

static void sta_policy_list_dump(const struct sta_policy **head)
{
	struct sta_policy *cfg = *head;

	while (cfg != NULL) {
		sta_policy_dump(cfg);
		cfg = cfg->next;
	}
}

/**
 * Parse the sta policy rate params and update into sta policy structure
 */
static int parse_rate_string(struct hostapd_data *hapd,
				struct sta_policy *cfg, char *rate_str)
{
	char *rate, *context = NULL;
	int i, cnt = 0, flag = 0;
	struct hostapd_hw_modes *hw_features = hapd->iface->hw_features;

	if (rate_str) {
		while ((rate = str_token(rate_str, ",", &context)) != NULL &&
					cnt < MAX_RATES_SUPPORTED) {
			sscanf(rate, "%x", &cfg->supp_rates[cnt]);
			for (i= 0; i < hw_features->num_rates; i++) {
				if (((cfg->supp_rates[cnt] & RATE_MASK)*10)/2 ==
							hw_features->rates[i]) {
					flag = 1;
					break;
				}
			}

			if (!flag) {
				wpa_printf (MSG_ERROR, "Error parsing rate"
						" 0x%x", cfg->supp_rates[cnt]);
				os_memset(cfg->supp_rates, 0,
						MAX_RATES_SUPPORTED);
				cfg->num_sup_rates = 0;
				return -1;
			}

			flag = 0;
			cnt++;
		}
	}
	cfg->num_sup_rates = cnt;
	return 0;
}

static int get_param(const char *param)
{
	int i;

	for(i = 0; i < POLICY_PARAM_MAX; i++) {
		if(!STR_NCMP(param, config_params[i])) {
			return i;
		}
	}

	return -1;
}

static int populate_sta_policy(struct hostapd_data *hapd,
			       struct sta_policy *cfg,
			       char *param, char *value)
{
	int val;

	switch (get_param(param)) {
	case POLICY_PARAM_STA_ID:
		return 0;
	case POLICY_PARAM_SUPP_RATES:
		if (atoi(value) == -1) {
			os_memset(cfg->supp_rates, 0, sizeof(cfg->supp_rates));
			return 0;
		}

		if (parse_rate_string(hapd, cfg, value) != 0) {
			return -1;
		}

		break;
	case POLICY_PARAM_SHORT_PREAMBLE:
		val = atoi(value);
		cfg->capability_mask |= WLAN_CAPABILITY_SHORT_PREAMBLE;
		if (val == 1) {
			cfg->capability |= WLAN_CAPABILITY_SHORT_PREAMBLE;
		} else {
			cfg->capability &= ~WLAN_CAPABILITY_SHORT_PREAMBLE;
		}
		break;
	case POLICY_PARAM_SGI20:
		val = atoi(value);
		cfg->ht_capab_info_mask |= HT_CAP_INFO_SHORT_GI20MHZ;
		if (val == 1) {
			cfg->ht_capab_info |= HT_CAP_INFO_SHORT_GI20MHZ;
		} else {
			cfg->ht_capab_info &= ~HT_CAP_INFO_SHORT_GI20MHZ;
		}
		break;
	case POLICY_PARAM_SGI40:
		val = atoi(value);
		cfg->ht_capab_info_mask |= HT_CAP_INFO_SHORT_GI40MHZ;
		if (val == 1) {
			cfg->ht_capab_info |= HT_CAP_INFO_SHORT_GI40MHZ;
		} else {
			cfg->ht_capab_info &= ~HT_CAP_INFO_SHORT_GI40MHZ;
		}
		break;
	case POLICY_PARAM_LDPC:
		val = atoi(value);
		cfg->ht_capab_info_mask |= HT_CAP_INFO_LDPC_CODING_CAP;
		if (val == 1) {
			cfg->ht_capab_info |= HT_CAP_INFO_LDPC_CODING_CAP;
		} else {
			cfg->ht_capab_info &= ~HT_CAP_INFO_LDPC_CODING_CAP;
		}
		break;
	case POLICY_PARAM_SMPS:
		val = atoi(value);
		cfg->ht_capab_info_mask |= HT_CAP_INFO_SMPS_MASK;

		/* Clear current SMPS config */
		cfg->ht_capab_info &= ~HT_CAP_INFO_SMPS_MASK;
		switch (val) {
		case 0:
			cfg->ht_capab_info |= HT_CAP_INFO_SMPS_STATIC;
			break;
		case 1:
			cfg->ht_capab_info |= HT_CAP_INFO_SMPS_DYNAMIC;
			break;
		case 3:
			cfg->ht_capab_info |= HT_CAP_INFO_SMPS_MASK;
			break;
		default:
			cfg->ht_capab_info_mask &= ~HT_CAP_INFO_SMPS_MASK;
			cfg->ht_capab_info &= ~HT_CAP_INFO_SHORT_GI40MHZ;
		}
		break;
	case POLICY_PARAM_MAX_AMSDU_LEN:
		val = atoi(value);
		cfg->ht_capab_info_mask |= HT_CAP_INFO_MAX_AMSDU_SIZE;
		if (val == 1) {
			cfg->ht_capab_info |= HT_CAP_INFO_MAX_AMSDU_SIZE;
		} else {
			cfg->ht_capab_info &= ~HT_CAP_INFO_MAX_AMSDU_SIZE;
		}
		break;
	case POLICY_PARAM_RIFS:
		val = atoi(value);
		cfg->ht_op_info_mask |= HT_INFO_HT_PARAM_RIFS_MODE;
		if (val == 1) {
			cfg->ht_op_info |= HT_INFO_HT_PARAM_RIFS_MODE;
		} else {
			cfg->ht_op_info &= ~HT_INFO_HT_PARAM_RIFS_MODE;
		}
		break;
	case POLICY_PARAM_MAX_AMPDU_LEN:
		val = atoi(value);
		cfg->vht_capab_info_mask |= VHT_CAP_MAX_MPDU_LENGTH_MASK;
		cfg->vht_capab_info &= ~VHT_CAP_MAX_MPDU_LENGTH_MASK;
		switch(val) {
		case 0:
			break;
		case 1:
			cfg->vht_capab_info |= VHT_CAP_MAX_MPDU_LENGTH_7991;
			break;
		case 2:
			cfg->vht_capab_info |= VHT_CAP_MAX_MPDU_LENGTH_11454;
			break;
		default:
			cfg->vht_capab_info &= ~VHT_CAP_MAX_MPDU_LENGTH_MASK;
			cfg->vht_capab_info_mask &= ~VHT_CAP_MAX_MPDU_LENGTH_MASK;
		}
		break;
	case POLICY_PARAM_RX_LDPC:
		val = atoi(value);
		cfg->vht_capab_info_mask |= VHT_CAP_RXLDPC;
		if (val == 1) {
			cfg->vht_capab_info |= VHT_CAP_RXLDPC;
		} else {
			cfg->vht_capab_info &= ~VHT_CAP_RXLDPC;
		}
		break;
	case POLICY_PARAM_SGI80:
		val = atoi(value);
		cfg->vht_capab_info_mask |= VHT_CAP_SHORT_GI_80;
		if (val == 1) {
			cfg->vht_capab_info |= VHT_CAP_SHORT_GI_80;
		} else {
			cfg->vht_capab_info &= ~VHT_CAP_SHORT_GI_80;
		}
		break;
	case POLICY_PARAM_AMPDU_SUBFRAME_COUNT:
		val = atoi(value);
		cfg->flags |= FLAG_AMPDU_SUBFRAME_COUNT;
		if (val >= 0 || val <= 64) {
			cfg->ampdu_subframe_count = val;
		} else {
			wpa_printf (MSG_ERROR, "Wrong AMPDU_SUBFRAME_COUNT,"
				"Value ranges from [0-64]");
			return -1;
		}
		break;
	case POLICY_PARAM_PSPOLL_STA_KO_ENABLED:
		val = atoi(value);
		cfg->flags |= FLAG_PSPOLL_STA_KO_ENABLED;
		cfg->pspoll_sta_ko_enabled = (val) ? !!val : 0;
		break;
	default:
		wpa_printf(MSG_INFO, "Unknown param: %s\n", param);
		return -1;
	}

	return 0;
}

/**
 * DELETE an entry from the sta_policy list
 */
static int sta_policy_node_delete(struct sta_policy **head, uint8_t *sta_id)
{
	struct sta_policy *cfg, *tmp;

	cfg = tmp = *head;
	if (!cfg) {
		wpa_printf(MSG_ERROR, "Empty sta_policy list");
		return -1;
	}

	while (cfg != NULL) {
		if (os_memcmp(cfg->sta_id, sta_id, ETH_ALEN) == 0) {
			if (cfg == *head)
				*head = cfg->next;
			else
				tmp->next = cfg->next;
			os_free(cfg);
			return 0;
		}
		tmp = cfg;
		cfg = cfg->next;
	}

	wpa_printf(MSG_INFO, "No " MACSTR " entry present", MAC2STR(sta_id));
	return -1;
}

/**
 * GET an entry from the sta_policy list
 */
static struct sta_policy *sta_policy_node_get(struct sta_policy **head,
	       u8 *sta_id)
{
	struct sta_policy *cfg = *head;

	if (!cfg) {
		/* Return Null if sta_policy list is Empty*/
		return NULL;
	} else {
		while (cfg != NULL) {
			if (os_memcmp(cfg->sta_id, sta_id, ETH_ALEN) == 0) {
				return cfg;
			}
			cfg = cfg->next;
		}
	}

	return NULL;
}

/**
 * ADD an entry to sta_policy list at end
 */
static void sta_policy_node_add_end(struct sta_policy **head,
			      struct sta_policy *cfg)
{
	struct sta_policy *tmp = *head;

	if (*head == NULL) {
		cfg->next = NULL;
		*head = cfg;
	} else {
		while(tmp->next != NULL) {
			tmp = tmp->next;
		}

		tmp->next = cfg;
	}
}

/**
 * Free the list of sta_policy
 */
static void sta_policy_node_list_free(struct sta_policy **head)
{
	struct sta_policy *cfg;

	while ((cfg = (*head)) != NULL) {
		*head = (*head)->next;
		os_free(cfg);
	}
}

/**
 * Parse the sta policy string params and update into sta policy structure
 */
static int parse_and_add_sta_policy_entry(struct hostapd_data *hapd,
					 char *line)
{
	char *param, *val, *context = NULL;
	uint8_t sta_id[ETH_ALEN];
	struct sta_policy *cfg;
	struct per_interface_config *i_cfg = hapd->iface->i_cfg;

	if (STR_NCMP(line, "sta_id=")) {
		wpa_printf(MSG_ERROR, "No sta_id present as"
					" first arg in params");
		return -1;
	}

	if ((val = os_strstr(line, "="))) {
		if (hwaddr_aton(val+1, &sta_id[0])) {
			wpa_printf(MSG_ERROR, "Parsing sta_id failed");
			return -1;
		}
	}

	cfg = sta_policy_node_get(&i_cfg->l_sta_policy, sta_id);
	if (!cfg) {
		cfg = (struct sta_policy *)
			os_zalloc(sizeof(struct sta_policy));
		if (cfg == NULL) {
			wpa_printf(MSG_ERROR, "%s: Failed to alloc"
					" mem", __func__);
			return -1;
		}

		os_memcpy(&cfg->sta_id, &sta_id, ETH_ALEN);
		sta_policy_node_add_end(&i_cfg->l_sta_policy, cfg);
	}

	while ((param = str_token(line, " ", &context)) != NULL) {

		if (*param == '\n' || *param == '\r')
			break;

		val = os_strstr(param, "=");
		if (val == NULL) {
			return -1;
		}
		val++;

		if ((populate_sta_policy(hapd, cfg, param, val)) < 0) {
			return -1;
		}
	}

	if (ap_get_sta(hapd, cfg->sta_id))
		sta_policy_send_event(hapd, cfg->sta_id);

	sta_policy_dump(cfg);

	return 0;
}

static int sta_policy_load(struct hostapd_iface *iface)
{
	FILE  *fp;
	char  *line = NULL;
	size_t len = 0, ret = 0;
	struct per_interface_config *i_cfg = iface->i_cfg;

	fp = fopen(i_cfg->cfg_file, "r");
	if (fp == NULL) {
		wpa_printf(MSG_ERROR,"Failed to open file: %s",
					i_cfg->cfg_file);
		return -1;
	}

	while (getline(&line, &len, fp) != -1) {
		ret = parse_and_add_sta_policy_entry(iface->bss[0], line);
		if (ret != 0)
			wpa_printf(MSG_ERROR, "Error parsing the line: %s", line);
	}

	if (line)
		os_free(line);

	fclose(fp);
	return 0;
}

static int construct_supp_rates(struct sta_policy *cfg,
				char *rates, int arr_size)
{
	int i = 0;
	int pos = 0, len = 0;

	if (cfg->num_sup_rates == 0)
		return -1;

	while (cfg->supp_rates[i] && i < cfg->num_sup_rates) {
		len = os_snprintf(rates + pos, arr_size - pos,  "%02x,",
						cfg->supp_rates[i++]);
		if (os_snprintf_error(arr_size - pos, len))
			return -1;

		pos += len;
		if (pos >= arr_size) {
			wpa_printf(MSG_ERROR, "Insufficient memory");
			break;
		}
	}

	/* Remove the last ',' from the rate string */
	*(rates + pos - 1) = '\0';
	return pos;
}

static int construct_sta_policy(struct sta_policy *cfg,
				char *line, unsigned int size)
{
	char rates[64] = {0};
	int len, pos = 0;

	os_memset(line, 0, STA_POLICY_ENTRYSIZE);
	len = os_snprintf(line, size, "sta_id="MACSTR, MAC2STR(cfg->sta_id));
	if (os_snprintf_error(size - pos, len))
		return -1;

	pos += len;
	if (cfg->num_sup_rates > 0) {
		len = construct_supp_rates(cfg, rates, sizeof(rates));
		if (len <= 0) {
			return -1;
		}

		len = os_snprintf(line + pos, size - pos,
				" supp_rates=%s", rates);
		if (os_snprintf_error(size - pos, len))
			return -1;

		pos += len;
	}

	if (cfg->capability_mask & WLAN_CAPABILITY_SHORT_PREAMBLE) {
		len = os_snprintf(line + pos, size - pos,
			" short_preamble=%d",!!(cfg->capability
			& WLAN_CAPABILITY_SHORT_PREAMBLE));
		if (os_snprintf_error(size - pos, len))
			return -1;

		pos += len;
	}

	if (cfg->ht_capab_info_mask & HT_CAP_INFO_SHORT_GI20MHZ) {
		len = os_snprintf(line + pos, size - pos,
			" sgi20=%d", !!(cfg->ht_capab_info
			& HT_CAP_INFO_SHORT_GI20MHZ));
		if (os_snprintf_error(size - pos, len))
			return -1;

		pos += len;
	}

	if (cfg->ht_capab_info_mask & HT_CAP_INFO_SHORT_GI40MHZ) {
		len = os_snprintf(line + pos, size - pos,
			" sgi40=%d", !!(cfg->ht_capab_info
			& HT_CAP_INFO_SHORT_GI40MHZ));
		if (os_snprintf_error(size - pos, len))
			return -1;

		pos += len;
	}

	if (cfg->ht_capab_info_mask & HT_CAP_INFO_LDPC_CODING_CAP) {
		len = os_snprintf(line + pos, size - pos,
			" ldpc=%d", !!(cfg->ht_capab_info
			& HT_CAP_INFO_LDPC_CODING_CAP));
		if (os_snprintf_error(size - pos, len))
			return -1;

		pos += len;
	}

	if (cfg->ht_capab_info_mask & HT_CAP_INFO_SMPS_MASK) {
		len = os_snprintf(line + pos, size - pos,
			" smps=%d", (cfg->ht_capab_info
			& HT_CAP_INFO_SMPS_MASK) >> 2);
		if (os_snprintf_error(size - pos, len))
			return -1;

		pos += len;
	}

	if (cfg->ht_capab_info_mask & HT_CAP_INFO_MAX_AMSDU_SIZE) {
		len = os_snprintf(line + pos, size - pos,
			" max_amsdu_len=%d", !!(cfg->ht_capab_info
			& HT_CAP_INFO_MAX_AMSDU_SIZE));
		if (os_snprintf_error(size - pos, len))
			return -1;

		pos += len;
	}

	if (cfg->ht_op_info_mask & HT_INFO_HT_PARAM_RIFS_MODE) {
		len = os_snprintf(line + pos, size - pos,
			" rifs=%d", !!(cfg->ht_op_info
			& HT_INFO_HT_PARAM_RIFS_MODE));
		if (os_snprintf_error(size - pos, len))
			return -1;

		pos += len;

	}

	if (cfg->vht_capab_info_mask & VHT_CAP_MAX_MPDU_LENGTH_MASK) {
		len = os_snprintf(line + pos, size - pos,
			" max_ampdu_len=%d", cfg->vht_capab_info
			& VHT_CAP_MAX_MPDU_LENGTH_MASK);
		if (os_snprintf_error(size - pos, len))
			return -1;

		pos += len;
	}

	if (cfg->vht_capab_info_mask & VHT_CAP_RXLDPC) {
		len = os_snprintf(line + pos, size - pos,
			" rx_ldpc=%d", !!(cfg->vht_capab_info
			& VHT_CAP_RXLDPC));
		if (os_snprintf_error(size - pos, len))
			return -1;

		pos += len;
	}

	if (cfg->vht_capab_info_mask & VHT_CAP_SHORT_GI_80) {
		len = os_snprintf(line + pos, size - pos,
			" sgi80=%d", !!(cfg->vht_capab_info
			& VHT_CAP_SHORT_GI_80));
		if (os_snprintf_error(size - pos, len))
			return -1;

		pos += len;
	}

	if (cfg->flags & FLAG_AMPDU_SUBFRAME_COUNT) {
		len = os_snprintf(line + pos, size - pos,
			" ampdu_subframe_count=%d", cfg->ampdu_subframe_count);
		if (os_snprintf_error(size - pos, len))
			return -1;

		pos += len;
	}

	if (cfg->flags & FLAG_PSPOLL_STA_KO_ENABLED) {
		len = os_snprintf(line + pos, size - pos,
			" pspoll_sta_ko_enabled=%d", cfg->pspoll_sta_ko_enabled);
		if (os_snprintf_error(size - pos, len))
			return -1;

		pos += len;
	}

	strcat(line, "\n");
	return pos + 1;
}

/**
 * WRITE the sta policy to the file
 */
static int sta_policy_save(struct per_interface_config *i_cfg)
{
	struct sta_policy *ptr, *cfg = i_cfg->l_sta_policy;
	FILE *fp;
	char line_buf[STA_POLICY_ENTRYSIZE];
	char *temp = NULL;
	int len = 0, pos = 0;

	temp = (char *) os_zalloc (MAX_STA_POLICY_SIZE);
	if (!temp) {
		return -1;
	}

	while (cfg != NULL) {
		len = construct_sta_policy(cfg, line_buf, sizeof(line_buf));
		if (len < 0)
			return -1;

		pos += len;
		if (pos > MAX_STA_POLICY_SIZE - 1) {
			/* Free the last node added, if we reach the max
			 * buffer size */
			ptr->next = NULL;
			os_free(cfg);
			os_free(temp);
			return -1;
		}

		strcat(temp, line_buf);
		ptr = cfg;
		cfg = cfg->next;
	}

	fp = fopen(i_cfg->cfg_file, "w+");
	if (!fp) {
		wpa_printf(MSG_ERROR,"Failed to open file: %s",
					i_cfg->cfg_file);
		goto exit;
	}

	fwrite(temp, os_strlen(temp), 1, fp);
	fclose(fp);
	return 0;
exit:
	os_free(temp);
	return -1;
}

/**
 * Reply with the existing sta policy setting for the given sta
 * sta_id=00:00:00:00:00:00 indicates for all STA setting request
 * Returns 0 on success, -1 on failure
 */
int sta_policy_get(struct hostapd_data *hapd, char *buf,
		char *reply, int reply_size)
{
	uint8_t sta_id[ETH_ALEN];
	char line_buf[STA_POLICY_ENTRYSIZE];
	size_t len = 0, pos = 0;
	uint8_t zero_sta_id[] = "sta_id=00:00:00:00:00:00";
	char *ptr;
	struct sta_policy *cfg, *list;
	struct per_interface_config *i_cfg = hapd->iface->i_cfg;

	if (!i_cfg) {
		wpa_printf(MSG_ERROR, "sta_policy.conf does not exist");
		return -1;
	}

	os_memset(reply, 0, reply_size);
	ptr = os_strstr(buf, "sta_id=");
	if (ptr == NULL) {
		wpa_printf(MSG_ERROR, "No sta_id mentioned");
		return -1;
	}

	ptr = ptr + 7;
	if (hwaddr_aton(ptr, sta_id) != 0) {
		wpa_printf(MSG_INFO, "Could not parse MAC addr");
		return -1;
	}

	cfg = sta_policy_node_get(&i_cfg->l_sta_policy, sta_id);
	if (cfg) {
		construct_sta_policy(cfg, line_buf, sizeof(line_buf));
		len = os_snprintf(reply, reply_size, "%s", line_buf);
		if (os_snprintf_error(reply_size - pos, len))
			return -1;

		pos += len;
	} else if (!os_memcmp(buf, zero_sta_id, strlen(zero_sta_id))) {
		list = i_cfg->l_sta_policy;

		if (!list) {
			return -1;
		} else {
			while (list != NULL) {
				construct_sta_policy(list, line_buf,
							sizeof(line_buf));
				len = os_snprintf(reply + pos,
					reply_size - pos, "%s", line_buf);
				if (os_snprintf_error(reply_size - pos, len))
					return -1;

				pos += len;
				list = list->next;
			}
		}
	} else {
		wpa_printf(MSG_ERROR, "Error getting the entry");
		return -1;
	}

	return pos;
}

/**
 * Delete an Entry in sta_policy file on a given interface
 * Returns 0 on success, -1 on failure
 */
int sta_policy_del(struct hostapd_data *hapd, char *buf)
{
	int ret = 0;
	uint8_t sta_id[ETH_ALEN];
	struct sta_policy *cfg;
	char *ptr;
	struct per_interface_config *i_cfg = hapd->iface->i_cfg;

	if (!i_cfg) {
		wpa_printf(MSG_ERROR, "sta_policy.conf does not exist");
		return -1;
	}

	ptr = os_strstr(buf, "sta_id=");
	if (ptr == NULL) {
		wpa_printf(MSG_ERROR, "No sta_id mentioned");
		return -1;
	}

	ptr = ptr + 7;
	if (hwaddr_aton(ptr, sta_id) != 0) {
		wpa_printf(MSG_INFO, "Could not parse MAC addr");
		return -1;
	}

	/* Delete from the file and sta_policy DS */
	ret = sta_policy_node_delete(&i_cfg->l_sta_policy, sta_id);
	if (!ret)
		ret = sta_policy_save(i_cfg);

	return ret;
}

/**
 * Add supported rate and extended rate IE if sta policy rate settings exists
 */
static u8 *sta_policy_eid_rate(struct hostapd_data *hapd,
			struct sta_policy *cfg, u8 *eid)
{
	u8 *pos = eid;
	int num = (cfg->num_sup_rates > 8) ? 8 : cfg->num_sup_rates;

	if (!num)
		return NULL;

	// Create Supported rate IE
	*pos++ = WLAN_EID_SUPP_RATES;
	*pos++ = num;
	os_memcpy(pos, &cfg->supp_rates[0], num);
	pos += num;

	//Create extended rate IE
	if (cfg->num_sup_rates > 8) {
		*pos++ = WLAN_EID_EXT_SUPP_RATES;
		*pos++ = (cfg->num_sup_rates - 8);
		os_memcpy(pos, &cfg->supp_rates[8], cfg->num_sup_rates - 8);
		pos += cfg->num_sup_rates - 8;
	}

	return pos;
}

/**
 * Copy the Existing STA policy supported rate to the buffer passed,
 * if the sta_id matched the list
 * Returns value <= 0 on Failure
 * 	   No of bytes copied on success
 */
int sta_policy_get_supp_rate(struct hostapd_data *hapd, u8 *sta_addr, u8 *rate)
{
	struct per_interface_config *i_cfg = hapd->iface->i_cfg;
	struct sta_policy *cfg;

	if (!i_cfg)
		return -1;

	cfg = sta_policy_node_get(&i_cfg->l_sta_policy, sta_addr);
	if (!cfg) {
		return -1;
	}

	if (!cfg->num_sup_rates)
		return -1;

	os_memcpy(rate, cfg->supp_rates, cfg->num_sup_rates);

	return cfg->num_sup_rates;
}

/**
 * Create the Supported rates EID and Extended rates EID if there
 * is a sta policy entry settings available for the given sta_addr
 * Return -1 if no EID added,
 *         0 incremented eid pointer if EID added
 */
u8 *sta_policy_copy_supp_rate(struct hostapd_data *hapd, u8 *sta_addr,
						u8 *eid, size_t *res)
{
	struct per_interface_config *i_cfg = hapd->iface->i_cfg;
	struct sta_policy *cfg;
	u8 *pos;

	if (!i_cfg)
		goto fail;

	cfg = sta_policy_node_get(&i_cfg->l_sta_policy, sta_addr);
	if (!cfg) {
		goto fail;
	}

	pos = sta_policy_eid_rate(hapd, cfg, eid);
	if (pos == NULL) {
		goto fail;
	}

	return pos;
fail:
	*res = -1;
	return eid;
}

/**
 *  Update the capabilities, only if the current associating
 *  STA mac addr is part of the sta policy list
 */
void sta_policy_update_capab(struct hostapd_data *hapd,
				uint16_t *capability)
{
	struct per_interface_config *i_cfg = hapd->iface->i_cfg;
	struct sta_policy *cfg;

	if (!i_cfg)
		return;

	if (!i_cfg->assoc_resp)
		return;

	cfg = sta_policy_node_get(&i_cfg->l_sta_policy,
				i_cfg->associating_sta);
	if (!cfg) {
		return;
	}

	*capability &= ~(cfg->capability_mask & i_cfg->_capability_mask);
	*capability |= (cfg->capability & (cfg->capability_mask &
				i_cfg->_capability_mask));
}

/**
 *  Update the HT cap, only if the associating STA mac addr
 *  is part of the sta policy list
 */
void sta_policy_update_ht_cap(struct hostapd_data *hapd,
			 struct ieee80211_ht_capabilities *cap)
{
	struct per_interface_config *i_cfg = hapd->iface->i_cfg;
	struct sta_policy *cfg;

	if (!i_cfg)
		return;

	if (!i_cfg->assoc_resp)
		return;

	cfg = sta_policy_node_get(&i_cfg->l_sta_policy,
				i_cfg->associating_sta);
	if (!cfg) {
		return;
	}

	/* Update HT CAP INFO */
	cap->ht_capabilities_info &= ~(cfg->ht_capab_info_mask &
					i_cfg->_ht_capab_info_mask);
	cap->ht_capabilities_info |= (cfg->ht_capab_info &
		(cfg->ht_capab_info_mask & i_cfg->_ht_capab_info_mask));
}

/**
 *  Update the HT Operation Info, only if the associating STA mac addr
 *  is part of the sta policy list
 */
void sta_policy_update_ht_op_info(struct hostapd_data *hapd,
			 struct ieee80211_ht_operation *op)
{
	struct per_interface_config *i_cfg = hapd->iface->i_cfg;
	struct sta_policy *cfg;

	if (!i_cfg)
		return;

	if (!i_cfg->assoc_resp)
		return;

	cfg = sta_policy_node_get(&i_cfg->l_sta_policy,
				i_cfg->associating_sta);
	if (!cfg) {
		return;
	}

	/* Update HT Operation Info */
	op->ht_param &= ~(cfg->ht_op_info_mask &
					i_cfg->_ht_op_info_mask);
	op->ht_param |= (cfg->ht_op_info &
		(cfg->ht_op_info_mask & i_cfg->_ht_op_info_mask));
}

/**
 *  Update the VHT cap, only if the associating STA mac addr
 *  is part of the sta policy list
 */
void sta_policy_update_vht_cap(struct hostapd_data *hapd,
			 struct ieee80211_vht_capabilities *cap)
{
	struct per_interface_config *i_cfg = hapd->iface->i_cfg;
	struct sta_policy *cfg;

	if (!i_cfg)
		return;

	if (!i_cfg->assoc_resp)
		return;

	cfg = sta_policy_node_get(&i_cfg->l_sta_policy,
				i_cfg->associating_sta);
	if (!cfg) {
		return;
	}

	/* Update HT CAP INFO */
	cap->vht_capabilities_info &= ~(cfg->vht_capab_info_mask &
					i_cfg->_vht_capab_info_mask);
	cap->vht_capabilities_info |= (cfg->vht_capab_info &
		      (cfg->vht_capab_info_mask & i_cfg->_vht_capab_info_mask));

}

/**
 * Adds an entry into sta policy file for the given interface
 * Retruns 0 if success, -1 if fails
 */
int sta_policy_add(struct hostapd_data *hapd, char *buf)
{
	int len;
	struct per_interface_config *i_cfg = hapd->iface->i_cfg;

	if (!i_cfg) {
		wpa_printf(MSG_ERROR, "sta_policy.conf does not exist, "
				" cannot add policy");
		goto fail;
	}

	len = strlen(buf);
	if (len > STA_POLICY_ENTRYSIZE) {
		wpa_printf(MSG_ERROR, "Entry size (%d) > %d",
				len, STA_POLICY_ENTRYSIZE);
		goto fail;
	}

	if (parse_and_add_sta_policy_entry(hapd, buf) != 0) {
		goto fail;
	}

	/* Write to file */
	if (sta_policy_save(i_cfg)) {
		goto fail;
	}

	return 0;
fail:
	return -1;
}

void sta_policy_send_event(struct hostapd_data *hapd, uint8_t *sta_addr)
{
	struct per_interface_config *i_cfg = hapd->iface->i_cfg;
	struct sta_policy *cfg;

	cfg = sta_policy_node_get(&i_cfg->l_sta_policy, sta_addr);
	if (!cfg) {
		return;
	}

	if (cfg->flags & FLAG_AMPDU_SUBFRAME_COUNT) {
		wpa_msg(hapd->msg_ctx, MSG_INFO, STA_POLICY_AMPDU_SUBFRAME_COUNT
				MACSTR " %d", MAC2STR(cfg->sta_id),
				cfg->ampdu_subframe_count);
	}

	if (cfg->flags & FLAG_PSPOLL_STA_KO_ENABLED) {
		wpa_msg(hapd->msg_ctx, MSG_INFO, STA_POLICY_PSPOLL_STA_KO_ENABLED
				MACSTR " %d", MAC2STR(cfg->sta_id),
				cfg->pspoll_sta_ko_enabled);
	}
}

/**
 * This function will initilalize the Dynamic Mask values of the
 * sta policy params for the given interface
 */
int stapolicy_cfg_init(struct hostapd_iface *iface)
{
	struct per_interface_config *i_cfg = iface->i_cfg;

	/* read file and load the params */
	if (sta_policy_load(iface)) {
		os_free(i_cfg->cfg_file);
		os_free(i_cfg);
		iface->i_cfg = NULL;
		return 0;
	}

	sta_policy_list_dump(&i_cfg->l_sta_policy);

	/* Dynamic MASK Values, based on driver/hw capabilities */
	i_cfg->_capability_mask = CONFIGURABLE_BITS_CAP;
	i_cfg->_ht_capab_info_mask = iface->hw_features->ht_capab &
					CONFIGURABLE_BITS_HT_CAP;
	i_cfg->_ht_ampdu_param_mask = iface->hw_features->a_mpdu_params &
					CONFIGURABLE_BITS_MPDU;
	i_cfg->_ht_op_info_mask = CONFIGURABLE_BITS_HT_OP_INFO;
	i_cfg->_vht_capab_info_mask = iface->hw_features->vht_capab &
					CONFIGURABLE_BITS_VHT_CAP;

	return 0;
}

/**
 * Initialization function for STA policy module.
 * Should be called for every hostapd_iface init.
 * This function allocates the required memory and reads
 * the sta policy file based on the interface being
 * initialized.
 *
 * Returns 0 - Success
 * 	   1 - Failure
 */
int stapolicy_interface_init(struct hostapd_iface *iface)
{
	struct per_interface_config *i_cfg;
	struct hostapd_data *hapd = iface->bss[0];
	int file_len;

	iface->i_cfg = NULL;
	/* Allocate memory for the interface */
	i_cfg = (struct per_interface_config *) os_zalloc
			(sizeof(struct per_interface_config));
	if (!i_cfg)
		return -1;

	iface->i_cfg = i_cfg;

	/* Generate persta config file name */
	if (get_iface_name(hapd))
		strncpy(i_cfg->iface_name, get_iface_name(hapd), IFNAMSIZ);

	file_len = os_strlen(STA_POLICY_DIR) +
		   os_strlen(i_cfg->iface_name) +
		   os_strlen(STA_POLICY_FILENAME) + 1;
	i_cfg->cfg_file = (char *) os_zalloc(file_len);
	if (!i_cfg->cfg_file) {
		os_free(i_cfg);
		iface->i_cfg = NULL;
		return -1;
	}

	/* Create config file name */
	os_snprintf(i_cfg->cfg_file, STA_POLICY_ENTRYSIZE, "%s%s%s",
		STA_POLICY_DIR, i_cfg->iface_name, STA_POLICY_FILENAME);

	return 0;
}

/**
 * Deinitialization function for STA Policy.
 * This function deallocates memory/resources allocated
 */
void stapolicy_interface_deinit(struct hostapd_iface *iface)
{
	struct per_interface_config *i_cfg = iface->i_cfg;

	if (!i_cfg)
		return;

	/* Delete STA policy, list */
	sta_policy_node_list_free(&i_cfg->l_sta_policy);

	os_free(i_cfg->cfg_file);
	os_free(i_cfg);
	iface->i_cfg = NULL;
}
