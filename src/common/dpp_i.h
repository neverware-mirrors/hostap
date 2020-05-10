/*
 * DPP module internal definitions
 * Copyright (c) 2017, Qualcomm Atheros, Inc.
 * Copyright (c) 2018-2020, The Linux Foundation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef DPP_I_H
#define DPP_I_H

#ifdef CONFIG_DPP

struct dpp_global {
	void *msg_ctx;
	struct dl_list bootstrap; /* struct dpp_bootstrap_info */
	struct dl_list configurator; /* struct dpp_configurator */
#ifdef CONFIG_DPP2
	struct dl_list controllers; /* struct dpp_relay_controller */
	struct dpp_controller *controller;
	struct dl_list tcp_init; /* struct dpp_connection */
	void *cb_ctx;
	int (*process_conf_obj)(void *ctx, struct dpp_authentication *auth);
	void (*remove_bi)(void *ctx, struct dpp_bootstrap_info *bi);
#endif /* CONFIG_DPP2 */
};

/* dpp.c */

void dpp_build_attr_status(struct wpabuf *msg, enum dpp_status_error status);
unsigned int dpp_next_id(struct dpp_global *dpp);
struct wpabuf * dpp_build_conn_status(enum dpp_status_error result,
				      const u8 *ssid, size_t ssid_len,
				      const char *channel_list);
struct json_token * dpp_parse_own_connector(const char *own_connector);
int dpp_connector_match_groups(struct json_token *own_root,
			       struct json_token *peer_root, bool reconfig);
int dpp_build_jwk(struct wpabuf *buf, const char *name, EVP_PKEY *key,
		  const char *kid, const struct dpp_curve_params *curve);
EVP_PKEY * dpp_parse_jwk(struct json_token *jwk,
			 const struct dpp_curve_params **key_curve);
int dpp_prepare_channel_list(struct dpp_authentication *auth,
			     unsigned int neg_freq,
			     struct hostapd_hw_modes *own_modes, u16 num_modes);
void dpp_auth_fail(struct dpp_authentication *auth, const char *txt);

/* dpp_crypto.c */

struct dpp_signed_connector_info {
	unsigned char *payload;
	size_t payload_len;
};

enum dpp_status_error
dpp_process_signed_connector(struct dpp_signed_connector_info *info,
			     EVP_PKEY *csign_pub, const char *connector);
enum dpp_status_error
dpp_check_signed_connector(struct dpp_signed_connector_info *info,
			   const u8 *csign_key, size_t csign_key_len,
			   const u8 *peer_connector, size_t peer_connector_len);
const struct dpp_curve_params * dpp_get_curve_name(const char *name);
const struct dpp_curve_params * dpp_get_curve_jwk_crv(const char *name);
const struct dpp_curve_params * dpp_get_curve_oid(const ASN1_OBJECT *poid);
const struct dpp_curve_params * dpp_get_curve_nid(int nid);
int dpp_bi_pubkey_hash(struct dpp_bootstrap_info *bi,
		       const u8 *data, size_t data_len);
struct wpabuf * dpp_get_pubkey_point(EVP_PKEY *pkey, int prefix);
EVP_PKEY * dpp_set_pubkey_point_group(const EC_GROUP *group,
				      const u8 *buf_x, const u8 *buf_y,
				      size_t len);
EVP_PKEY * dpp_set_pubkey_point(EVP_PKEY *group_key, const u8 *buf, size_t len);
int dpp_bn2bin_pad(const BIGNUM *bn, u8 *pos, size_t len);
int dpp_hash_vector(const struct dpp_curve_params *curve, size_t num_elem,
		    const u8 *addr[], const size_t *len, u8 *mac);
int dpp_hkdf_expand(size_t hash_len, const u8 *secret, size_t secret_len,
		    const char *label, u8 *out, size_t outlen);
int dpp_hmac(size_t hash_len, const u8 *key, size_t key_len,
	     const u8 *data, size_t data_len, u8 *mac);
int dpp_hmac_vector(size_t hash_len, const u8 *key, size_t key_len,
		    size_t num_elem, const u8 *addr[], const size_t *len,
		    u8 *mac);
int dpp_ecdh(EVP_PKEY *own, EVP_PKEY *peer, u8 *secret, size_t *secret_len);
void dpp_debug_print_point(const char *title, const EC_GROUP *group,
			   const EC_POINT *point);
void dpp_debug_print_key(const char *title, EVP_PKEY *key);
int dpp_pbkdf2(size_t hash_len, const u8 *password, size_t password_len,
	       const u8 *salt, size_t salt_len, unsigned int iterations,
	       u8 *buf, size_t buflen);
int dpp_get_subject_public_key(struct dpp_bootstrap_info *bi,
			       const u8 *data, size_t data_len);
int dpp_bootstrap_key_hash(struct dpp_bootstrap_info *bi);
int dpp_keygen(struct dpp_bootstrap_info *bi, const char *curve,
	       const u8 *privkey, size_t privkey_len);
EVP_PKEY * dpp_set_keypair(const struct dpp_curve_params **curve,
			   const u8 *privkey, size_t privkey_len);
EVP_PKEY * dpp_gen_keypair(const struct dpp_curve_params *curve);
int dpp_derive_k1(const u8 *Mx, size_t Mx_len, u8 *k1, unsigned int hash_len);
int dpp_derive_k2(const u8 *Nx, size_t Nx_len, u8 *k2, unsigned int hash_len);
int dpp_derive_bk_ke(struct dpp_authentication *auth);
int dpp_gen_r_auth(struct dpp_authentication *auth, u8 *r_auth);
int dpp_gen_i_auth(struct dpp_authentication *auth, u8 *i_auth);
int dpp_auth_derive_l_responder(struct dpp_authentication *auth);
int dpp_auth_derive_l_initiator(struct dpp_authentication *auth);
int dpp_derive_pmk(const u8 *Nx, size_t Nx_len, u8 *pmk, unsigned int hash_len);
int dpp_derive_pmkid(const struct dpp_curve_params *curve,
		     EVP_PKEY *own_key, EVP_PKEY *peer_key, u8 *pmkid);
EC_POINT * dpp_pkex_derive_Qi(const struct dpp_curve_params *curve,
			      const u8 *mac_init, const char *code,
			      const char *identifier, BN_CTX *bnctx,
			      EC_GROUP **ret_group);
EC_POINT * dpp_pkex_derive_Qr(const struct dpp_curve_params *curve,
			      const u8 *mac_resp, const char *code,
			      const char *identifier, BN_CTX *bnctx,
			      EC_GROUP **ret_group);
int dpp_pkex_derive_z(const u8 *mac_init, const u8 *mac_resp,
		      const u8 *Mx, size_t Mx_len,
		      const u8 *Nx, size_t Nx_len,
		      const char *code,
		      const u8 *Kx, size_t Kx_len,
		      u8 *z, unsigned int hash_len);
int dpp_reconfig_derive_ke_responder(struct dpp_authentication *auth,
				     const u8 *net_access_key,
				     size_t net_access_key_len,
				     struct json_token *peer_net_access_key);
int dpp_reconfig_derive_ke_initiator(struct dpp_authentication *auth,
				     const u8 *r_proto, u16 r_proto_len,
				     struct json_token *net_access_key);
char * dpp_sign_connector(struct dpp_configurator *conf,
			  const struct wpabuf *dppcon);
int dpp_test_gen_invalid_key(struct wpabuf *msg,
			     const struct dpp_curve_params *curve);

#endif /* CONFIG_DPP */
#endif /* DPP_I_H */