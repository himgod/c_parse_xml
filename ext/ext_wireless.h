#ifndef _EXT_WIRELESS_H_
#define _EXT_WIRELESS_H_
#include "wid_ac.h"

void ext_wireless_handle(int argc, zval ***argv, zval *return_value);

EXT_FUNCTION(ext_set_user_default_wireless_network);
EXT_FUNCTION(ext_set_guest_default_wireless_network);
EXT_FUNCTION(ext_delete_wireless_network);
EXT_FUNCTION(ext_add_wireless_network);
EXT_FUNCTION(ext_modify_wireless_network);
EXT_FUNCTION(ext_show_wireless_network_list);
EXT_FUNCTION(ext_get_one_wireless_network);

int add_modify_wlan_save_config(WLANWEBINFO * wlaninfo);
int delete_wlan_save_config(unsigned int wlan_id);

enum security_type {OPEN,SHARED,IEEE8021X,WPA_P,WPA2_P,WPA_E,WPA2_E};
enum wpa_mode{AUTO, WPA1, WPA2};

enum encryption_type {NONE,WEP,AES,TKIP,SMS4};

enum security_policy {OPEN_SERCUR,WEP_SERCUR,WPAP_TKIP,
						WPAP_AES, WPA2P_TKIP, WPA2P_AES,
						WPAE_TKIP, WPAE_AES,WPA2E_TKIP,
						WPA2E_AES,__MAX_SERCUR};
#endif
