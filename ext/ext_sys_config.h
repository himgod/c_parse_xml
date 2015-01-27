#ifndef _PHP_EXT_SYS_CONFIG_H_
#define _PHP_EXT_SYS_CONFIG_H_
#include "afc_conf.h"

#define PRODUCT_NAME_PATH     			"/devinfo/product_name"
#define PRODUCT_SN_PATH 	  			"/devinfo/sn"
#define PRODUCT_BASE_MAC_PATH 	  		"/devinfo/base_mac"
#define PRODUCT_SW_VERSION_PATH			"/etc/version/verstring"
#define MAX_SLOT_NUM 16


void ext_sys_manage_handle(int argc, zval ***argv, zval *return_value);

EXT_FUNCTION(ext_get_idle_timeout_threshold);
EXT_FUNCTION(ext_set_idle_timeout_threshold);
EXT_FUNCTION(ext_set_afi_version_update_value);
EXT_FUNCTION(ext_get_afi_version_update_value);
EXT_FUNCTION(ext_set_afi_net_adaption_value);
EXT_FUNCTION(ext_get_afi_net_adaption_value);
EXT_FUNCTION(ext_set_afi_access_control_value);
EXT_FUNCTION(ext_get_afi_access_control_value);
EXT_FUNCTION(ext_get_wireless_global_country_code);
EXT_FUNCTION(ext_set_wireless_global_country_code);
EXT_FUNCTION(ext_get_wireless_global_auto_optim_policy);
EXT_FUNCTION(ext_set_wireless_global_auto_optim_policy);
EXT_FUNCTION(ext_load_wireless_config);
EXT_FUNCTION(ext_load_system_config);

int load_system_node_config(struct system_conf *system_node);
int load_all_system_config();
int load_all_wireless_config();
int load_afi_policy_config(struct afi_policy_conf * afi_policy);

int config_one_wlan(struct wlan_conf * wlan_node);
int config_one_wtp(struct wtp_conf * wtp_node);

#endif /* _PHP_EXT_SYS_CONFIG_H_ */


