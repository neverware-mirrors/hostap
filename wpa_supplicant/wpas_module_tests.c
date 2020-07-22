/*
 * wpa_supplicant module tests
 * Copyright (c) 2014, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/module_tests.h"
#include "wpa_supplicant_i.h"
#include "blacklist.h"
#ifndef CONFIG_NO_ROAMING
#include "bss.h"
#include "config.h"
#include "scan.h"


enum roam_type {
	ROAM_SAME_BAND,
	ROAM_TO_5,
	ROAM_TO_2,
};
#endif /* CONFIG_NO_ROAMING */


static int wpas_blacklist_module_tests(void)
{
	struct wpa_supplicant wpa_s;
	int ret = -1;

	os_memset(&wpa_s, 0, sizeof(wpa_s));

	wpa_blacklist_clear(&wpa_s);

	if (wpa_blacklist_get(NULL, NULL) != NULL ||
	    wpa_blacklist_get(NULL, (u8 *) "123456") != NULL ||
	    wpa_blacklist_get(&wpa_s, NULL) != NULL ||
	    wpa_blacklist_get(&wpa_s, (u8 *) "123456") != NULL)
		goto fail;

	if (wpa_blacklist_add(NULL, NULL) == 0 ||
	    wpa_blacklist_add(NULL, (u8 *) "123456") == 0 ||
	    wpa_blacklist_add(&wpa_s, NULL) == 0)
		goto fail;

	if (wpa_blacklist_del(NULL, NULL) == 0 ||
	    wpa_blacklist_del(NULL, (u8 *) "123456") == 0 ||
	    wpa_blacklist_del(&wpa_s, NULL) == 0 ||
	    wpa_blacklist_del(&wpa_s, (u8 *) "123456") == 0)
		goto fail;

	if (wpa_blacklist_add(&wpa_s, (u8 *) "111111") < 0 ||
	    wpa_blacklist_add(&wpa_s, (u8 *) "111111") < 0 ||
	    wpa_blacklist_add(&wpa_s, (u8 *) "222222") < 0 ||
	    wpa_blacklist_add(&wpa_s, (u8 *) "333333") < 0 ||
	    wpa_blacklist_add(&wpa_s, (u8 *) "444444") < 0 ||
	    wpa_blacklist_del(&wpa_s, (u8 *) "333333") < 0 ||
	    wpa_blacklist_del(&wpa_s, (u8 *) "xxxxxx") == 0 ||
	    wpa_blacklist_get(&wpa_s, (u8 *) "xxxxxx") != NULL ||
	    wpa_blacklist_get(&wpa_s, (u8 *) "111111") == NULL ||
	    wpa_blacklist_get(&wpa_s, (u8 *) "222222") == NULL ||
	    wpa_blacklist_get(&wpa_s, (u8 *) "444444") == NULL ||
	    wpa_blacklist_del(&wpa_s, (u8 *) "111111") < 0 ||
	    wpa_blacklist_del(&wpa_s, (u8 *) "222222") < 0 ||
	    wpa_blacklist_del(&wpa_s, (u8 *) "444444") < 0 ||
	    wpa_blacklist_add(&wpa_s, (u8 *) "111111") < 0 ||
	    wpa_blacklist_add(&wpa_s, (u8 *) "222222") < 0 ||
	    wpa_blacklist_add(&wpa_s, (u8 *) "333333") < 0)
		goto fail;

	wpa_blacklist_clear(&wpa_s);

	if (wpa_blacklist_add(&wpa_s, (u8 *) "111111") < 0 ||
	    wpa_blacklist_add(&wpa_s, (u8 *) "222222") < 0 ||
	    wpa_blacklist_add(&wpa_s, (u8 *) "333333") < 0 ||
	    wpa_blacklist_add(&wpa_s, (u8 *) "444444") < 0 ||
	    !wpa_blacklist_is_blacklisted(&wpa_s, (u8 *) "111111") ||
	    wpa_blacklist_del(&wpa_s, (u8 *) "111111") < 0 ||
	    wpa_blacklist_is_blacklisted(&wpa_s, (u8 *) "111111") ||
	    wpa_blacklist_add(&wpa_s, (u8 *) "111111") < 0)
		goto fail;

	wpa_blacklist_update(&wpa_s);

	if (!wpa_blacklist_is_blacklisted(&wpa_s, (u8 *) "111111"))
		goto fail;

	ret = 0;
fail:
	wpa_blacklist_clear(&wpa_s);

	if (ret)
		wpa_printf(MSG_ERROR, "blacklist module test failure");

	return ret;
}


#ifndef CONFIG_NO_ROAMING
static int check_roam(struct wpa_supplicant *wpa_s, struct wpa_bss *curr,
		      struct wpa_bss *sel, enum roam_type type, int cur_level,
		      int sel_level, int cur_est, int sel_est)
{
	if (type == ROAM_TO_5) {
		curr->freq = 2412;
		sel->freq = 5180;
	} else if (type == ROAM_TO_2) {
		curr->freq = 5180;
		sel->freq = 2412;
	} else {
		curr->freq = 2412;
		sel->freq = 2417;
	}
	curr->level = cur_level;
	sel->level = sel_level;
	curr->snr = curr->level - (IS_5GHZ(curr->freq) ?
				   DEFAULT_NOISE_FLOOR_5GHZ :
				   DEFAULT_NOISE_FLOOR_2GHZ);
	sel->snr = sel->level - (IS_5GHZ(sel->freq) ?
				 DEFAULT_NOISE_FLOOR_5GHZ :
				 DEFAULT_NOISE_FLOOR_2GHZ);
	curr->est_throughput = cur_est;
	sel->est_throughput = sel_est;
	return wpa_supplicant_need_to_roam_within_ess(wpa_s, curr, sel);
}


static int wpas_need_to_roam_module_tests()
{
	wpa_printf(MSG_INFO, "need_to_roam module tests");
	struct wpa_supplicant wpa_s;
	struct wpa_global global;
	struct wpa_bss curr, sel;
	struct wpa_ssid ssid;
	struct wpa_driver_ops dummy_driver;

	/* Initialize both BSSes. */
	os_memset(&curr, 0, sizeof(curr));
	curr.bssid[0] = 1;
	os_memset(&sel, 0, sizeof(sel));
	sel.bssid[0] = 2;

	/* Initialize the SSID. */
	os_memset(&ssid, 0, sizeof(ssid));
	ssid.bssid_set = 0;

	/* Initialize wpa_supplicant. We don't call *_init() functions because
	 * we'd like to do the bare minimum amount of setup necessary to test
	 * the wpa_supplicant_need_to_roam_within_ess() logic.
	 */
	os_memset(&wpa_s, 0, sizeof(wpa_s));
	os_memset(&dummy_driver, 0, sizeof(dummy_driver));
	os_memset(&global, 0, sizeof(global));
	os_memcpy(&wpa_s.ifname, "roam0", 5);
	wpa_s.global = &global;
	wpa_s.driver = &dummy_driver;
	wpa_s.current_ssid = &ssid;
	if (check_roam(&wpa_s, &curr, &sel, ROAM_TO_5,
		       -50, -80, 65000, 175500) ||
	    !check_roam(&wpa_s, &curr, &sel, ROAM_TO_2,
			-80, -50, 175500, 65000) ||
	    check_roam(&wpa_s, &curr, &sel, ROAM_SAME_BAND,
		       -80, -80, 19500, 19500) ||
	    !check_roam(&wpa_s, &curr, &sel, ROAM_TO_5,
			-40, -50, 65000, 390000)) {
		wpa_printf(MSG_ERROR, "need_to_roam module test failure");
		return -1;
	}
	return 0;
}
#endif /* CONFIG_NO_ROAMING */


int wpas_module_tests(void)
{
	int ret = 0;

	wpa_printf(MSG_INFO, "wpa_supplicant module tests");

	if (wpas_blacklist_module_tests() < 0)
		ret = -1;

#ifndef CONFIG_NO_ROAMING
	if (wpas_need_to_roam_module_tests() < 0)
		ret = -1;
#endif /* CONFIG_NO_ROAMING */

#ifdef CONFIG_WPS
	if (wps_module_tests() < 0)
		ret = -1;
#endif /* CONFIG_WPS */

	if (utils_module_tests() < 0)
		ret = -1;

	if (common_module_tests() < 0)
		ret = -1;

	if (crypto_module_tests() < 0)
		ret = -1;

	return ret;
}
