#ifndef _PHP_EXT_WTP_H_
#define _PHP_EXT_WTP_H_
#include "wcpss/wid/WID.h"
#include "wid_ac.h"

#define MAX_WTP_ID 10

#define FUNC_LINE_FORMAT "%s-%d"
#define FUNC_LINE_VALUE __func__,__LINE__

enum ext_wtp_state{
	EXT_WTP_ADMITING = WID_REJOIN+1,
	EXT_WTP_UPGRADING = EXT_WTP_ADMITING+1,
};

void ext_wtp_handle(int argc, zval ***argv, zval *return_value);

EXT_FUNCTION(ext_sta_list);
EXT_FUNCTION(ext_wtp_list);
EXT_FUNCTION(ext_get_wtp_ip_list);
EXT_FUNCTION(ext_restart_wtp);
EXT_FUNCTION(ext_delete_wtp);
EXT_FUNCTION(ext_adopt_new_wtp);
EXT_FUNCTION(ext_set_wtp_name);
EXT_FUNCTION(ext_set_sta_name);
EXT_FUNCTION(ext_get_neighbor_ap_list);
EXT_FUNCTION(ext_get_aps_list);
EXT_FUNCTION(ext_get_country_code);
EXT_FUNCTION(ext_set_country_code);
EXT_FUNCTION(ext_dynamic_select_radio_channel);
EXT_FUNCTION(ext_set_radio_channel);
EXT_FUNCTION(ext_set_radio_txpower);
EXT_FUNCTION(ext_set_radio_cwmode);
EXT_FUNCTION(ext_set_radio_mode);
EXT_FUNCTION(ext_set_wtp_ip_network);
EXT_FUNCTION(ext_set_radio_wlan_overrides);

int add_modify_wtp_save_config(NEW_WTP_ARG * new_wtp);
int remove_wtp_save_config(unsigned int wtp_id);

#endif /* _PHP_EXT_WTP_H_ */

