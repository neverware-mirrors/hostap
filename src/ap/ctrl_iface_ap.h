/*
 * Control interface for shared AP commands
 * Copyright (c) 2004-2013, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef CTRL_IFACE_AP_H
#define CTRL_IFACE_AP_H

int hostapd_ctrl_iface_sta_first(struct hostapd_data *hapd,
				 char *buf, size_t buflen);
int hostapd_ctrl_iface_sta(struct hostapd_data *hapd, const char *txtaddr,
			   char *buf, size_t buflen);
int hostapd_ctrl_iface_sta_next(struct hostapd_data *hapd, const char *txtaddr,
				char *buf, size_t buflen);
int hostapd_ctrl_iface_deauthenticate(struct hostapd_data *hapd,
				      const char *txtaddr);
int hostapd_ctrl_iface_disassociate(struct hostapd_data *hapd,
				    const char *txtaddr);
int hostapd_ctrl_iface_poll_sta(struct hostapd_data *hapd,
				    const char *txtaddr);
int hostapd_ctrl_iface_status(struct hostapd_data *hapd, char *buf,
			      size_t buflen);
int hostapd_parse_csa_settings(struct hostapd_data *hapd, const char *pos,
			       struct csa_settings *settings);
int hostapd_ctrl_iface_stop_ap(struct hostapd_data *hapd);
int hostapd_ctrl_iface_acl_add_mac(struct mac_acl_entry **acl, int *num,
				   const char *cmd);
int hostapd_ctrl_iface_acl_show_mac(struct mac_acl_entry *acl, int num,
				    char *buf, size_t buflen);
void hostapd_ctrl_iface_acl_clear_list(struct mac_acl_entry **acl,
				       int *num);
int hostapd_ctrl_iface_acl_del_mac(struct mac_acl_entry **acl, int *num,
				   const char *txtaddr);
int hostapd_disassoc_accept_mac(struct hostapd_data *hapd);
int hostapd_disassoc_deny_mac(struct hostapd_data *hapd);

#endif /* CTRL_IFACE_AP_H */
