#include <stdlib.h>
#include <string.h>
#include <grp.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <dbus/dbus.h>
#include <syslog.h>
#include <time.h>
#include "php.h"
#include "ext_public.h"
#include "ext_funcpublic.h"
//#include "wcpss/wid/WID.h"
#include "ext_wtp.h"
#include "wid_ac.h"
#include "wid_wtp.h"
#include "ext_dbus.h"
#include "dbop.h"
#include "afc_conf.h"

#define WTP_DEBUG_ENABLE 1
ext_func_handle_t wtp_func_list[] = {
    {"wtp_list", 1, (php_func_t)ext_wtp_list},
    {"get_wtp_ip_list", 1, (php_func_t)ext_get_wtp_ip_list},
    {"restart_wtp", 4, (php_func_t)ext_restart_wtp},
    {"delete_wtp", 4, (php_func_t)ext_delete_wtp},
    {"adopt_new_wtp", 5, (php_func_t)ext_adopt_new_wtp},
    {"set_wtp_name", 3, (php_func_t)ext_set_wtp_name},
    {"sta_list", 1, (php_func_t)ext_sta_list},
	{"set_sta_name", 6, (php_func_t)ext_set_sta_name},
	{"get_neighbor_ap_list", 1, (php_func_t)ext_get_neighbor_ap_list},
	{"get_aps_list", 1, (php_func_t)ext_get_aps_list},
	{"get_country_code", 1, (php_func_t)ext_get_country_code},
	{"set_country_code", 2, (php_func_t)ext_set_country_code},
	{"dynamic_select_radio_channel", 3, (php_func_t)ext_dynamic_select_radio_channel},
	{"set_radio_channel", 4, (php_func_t)ext_set_radio_channel},
	{"set_radio_txpower", 5, (php_func_t)ext_set_radio_txpower},
	{"set_radio_cwmode", 4, (php_func_t)ext_set_radio_cwmode},
	{"set_radio_mode", 4, (php_func_t)ext_set_radio_mode},
	{"set_wtp_ip_mask", 8, (php_func_t)ext_set_wtp_ip_network},
	{"set_radio_wlan_overrides", 10, (php_func_t)ext_set_radio_wlan_overrides},
};

void ext_wtp_handle(int argc, zval ***argv, zval *return_value)
{
    int count = sizeof(wtp_func_list)/sizeof(wtp_func_list[0]);
    ext_function_handle(argc, argv, return_value, count, wtp_func_list);
}

int add_modify_wtp_save_config(NEW_WTP_ARG * new_wtp)
{/*when add new wtp or set wtp name call this function */
	afc_config_s * afcconf = NULL;
	struct wtp_conf * wtp_tmpnode = NULL;
	unsigned int wtpid = 0;
	int ret = -1;

	if(!new_wtp || !(new_wtp->WTPID >= START_WTPID && new_wtp->WTPID <= MAX_WTP_ID))
	{
	    return -1;
	}
    afcconf = get_config_info();

    if(afcconf)
    {
        wtpid = new_wtp->WTPID;
        
        if(NULL == (afcconf->wtps[wtpid]))
        {
            afcconf->wtps[wtpid] = (struct wtp_conf *)malloc(sizeof(struct wtp_conf));
            if(afcconf->wtps[wtpid ])
            {
                memset(afcconf->wtps[wtpid], 0, sizeof(struct wtp_conf));
            }
            else
            {
                syslog(LOG_ERR, FUNC_LINE_FORMAT" malloc wtp node failed!", FUNC_LINE_VALUE);
                return -1;
            }
        }
        
        wtp_tmpnode = afcconf->wtps[wtpid];
        wtp_tmpnode->wtp_id = wtpid;
        memset(wtp_tmpnode->wtp_name, 0, MID_STRING_LEN);
        memset(wtp_tmpnode->wtp_mac, 0, SHORT_STRING_LEN);
        memset(wtp_tmpnode->wtp_model, 0, MID_STRING_LEN);
        
        strncpy(wtp_tmpnode->wtp_name, new_wtp->WTPNAME, MID_STRING_LEN-1);
        snprintf(wtp_tmpnode->wtp_mac, SHORT_STRING_LEN-1, MACSTR, MAC2STR(new_wtp->WTPMAC));
        strncpy(wtp_tmpnode->wtp_model, new_wtp->WTPModel, SHORT_STRING_LEN-1);
        
        ret = save_config_info(afcconf);
    }
    else
    {
        syslog(LOG_ERR, FUNC_LINE_FORMAT" failed to get config info !", FUNC_LINE_VALUE);
        return -1;
    }
    return ret;
}

int remove_wtp_save_config(unsigned int wtp_id)
{
    /* remove ap */
	afc_config_s * afcconf = NULL;

	int ret = -1;
	
    if(!(wtp_id >= START_WTPID && wtp_id <= MAX_WTP_ID))
	{
	    return -1;
	}
	
    afcconf = get_config_info();

    if(afcconf)
    {
        ret = 0;
        if(afcconf->wtps[wtp_id])
        {
            destroy_wtp_node(afcconf->wtps[wtp_id]);
            afcconf->wtps[wtp_id] = NULL;
            ret = save_config_info(afcconf);
        }
    }
    else
    {
        syslog(LOG_ERR, FUNC_LINE_FORMAT" failed to get config info !", FUNC_LINE_VALUE);
        return -1;
    }
    return ret;
}

char * get_radio_type_str(int radio_type)
{/*
	Radio_none = 0,
	Radio_11b = 1,
	Radio_11a = 2,
	Radio_11g = 4,
	Radio_11bg = 5,
	Radio_11n = 8,
	Radio_11an = 10,
	Radio_11gn = 12,
	Radio_11bgn = 13,
	Radio_11a_11an = 26,
	Radio_11g_11gn = 44,
	Radio_11ac = 64,
    Radio_11an_11ac = 74,
    Radio_11a_11an_11ac = 90,*/
	switch(radio_type)
	{
		case 0:
			return "";
		case 1:
			//return "b";
		case 4:
			//return "g";
		case 5:
			//return "b/g";
		case 8:
			//return "n"
		case 12:
			//return "g/n";
		case 13:
			//return "b/g/n";
		case 44:
			//return "g/gn";
			return "ng";
		case 2:
			//return "a";;
		case 10:
			//return "a/n";
		case 26:
			//return "a/an";
			return "na";
		case 74:
			//return "an/ac";
		case 90:
			//return "a/an/ac";
		case 64:
			return "ac";
		default:
			return "";
	}
}


EXT_FUNCTION(ext_sta_list)
{
    DBusConnection *connection = NULL;
	
	int ret = -1;
	int i = 0;
	STA_TO_WEB STALIST;
	struct stainfo_to_web *stainfo = NULL;
	char tmpMacStr[WTP_NAME_LEN] = {0};
	
	zval *iter = NULL, *iter_array = NULL;
	MAKE_STD_ZVAL(iter);
	array_init(iter);
	zval *iter_len;
	MAKE_STD_ZVAL(iter_len);
	array_init(iter_len);
	
	ret = dbus_connection_init(&connection);
	if (!connection)
	{
		syslog(LOG_ERR, "dbus connection init failed when get sta list ret %d", ret);
		RETURN_LONG(-1);
    }
    if (ret != 0)
    {
		syslog(LOG_ERR, "dbus connection init failed when get sta list ret %d", ret);
		uninit_dbus_connection(&connection);
		RETURN_LONG(-1);
    }

	memset(&STALIST, 0, sizeof(STA_TO_WEB));
	
	ret = show_network_sta_config(&STALIST, connection);
	
	stainfo = STALIST.stainfo;
	for (i = 0; i < STALIST.sta_num; i++)
	{
        MAKE_STD_ZVAL(iter_array);
        array_init(iter_array);

#if WTP_DEBUG_ENABLE
        
		syslog(LOG_DEBUG, "after call show sta list ret %d ip %s mac "MACSTR" wtp%d["MACSTR"] radio%d wlan%d ssid %s bssid "MACSTR"\n",
							ret, (stainfo[i].in_addr), MAC2STR(stainfo[i].addr), stainfo[i].wtpid, MAC2STR(stainfo[i].wtpmac),
							stainfo[i].l_radioid, stainfo[i].wlanid, stainfo[i].essid, MAC2STR(stainfo[i].bssid));
    
#endif

		char in_addr[32] = {0};
		sprintf(in_addr,"%s",(stainfo[i].in_addr));
        
		add_assoc_string(iter_array, "ip", in_addr, 1);
		snprintf(tmpMacStr, 31, MACSTR, MAC2STR(stainfo[i].addr));
		add_assoc_string(iter_array, "mac", (char *)tmpMacStr, 1);
		add_assoc_string(iter_array, "name", (char *)stainfo[i].sta_name, 1);
		snprintf(tmpMacStr, 31, "%s", WAI_STA_DEVTYPE_STR(stainfo[i].dev_type));
		add_assoc_string(iter_array, "device", (char *)tmpMacStr, 1);
		snprintf(tmpMacStr, 31, MACSTR, MAC2STR(stainfo[i].bssid));
		add_assoc_string(iter_array, "bssid", (char *)tmpMacStr, 1);
		snprintf(tmpMacStr, 31, MACSTR, MAC2STR(stainfo[i].wtpmac));
		add_assoc_string(iter_array, "ap_mac", (char *)tmpMacStr, 1);
		snprintf(tmpMacStr, 31, MACSTR, MAC2STR(stainfo[i].roam_ap));
		add_assoc_string(iter_array, "roam_ap", (char *)tmpMacStr, 1);
		add_assoc_string(iter_array, "essid", (char *)stainfo[i].essid, 1);
		add_assoc_string(iter_array, "radio", (char *)get_radio_type_str(stainfo[i].mode), 1);
		add_assoc_string(iter_array, "hostname", (char *)"MI2S-xiaomishouji", 1);
		add_assoc_string(iter_array, "t", (char *)"sta", 1);
		add_assoc_long(iter_array, "rssi", (long)stainfo[i].rssi);
		add_assoc_long(iter_array, "rx_retry_per", (long)stainfo[i].rx_retry_per);
		add_assoc_long(iter_array, "tx_retry_per", (long)stainfo[i].tx_retry_per);
		add_assoc_long(iter_array, "authorized", (long)stainfo[i].portal_status);
		add_assoc_long(iter_array, "state", (long)47);
		add_assoc_long(iter_array, "_id", (long)1);
		add_assoc_long(iter_array, "user_id", (long)1);
		add_assoc_long(iter_array, "usergroup_id", (long)1);
		add_assoc_long(iter_array, "first_seen", (long)stainfo[i].add_time);
		add_assoc_long(iter_array, "uptime", (long)stainfo[i].sta_online_time);
		add_assoc_long(iter_array, "is_guest", (long)stainfo[i].sta_type);
		add_assoc_long(iter_array, "roam", (long)stainfo[i].roam_type);
		add_assoc_long(iter_array, "sta_delay", (long)stainfo[i].sta_delay);
		add_assoc_long(iter_array, "rx-wifirate", (long)stainfo[i].nRate);
		add_assoc_long(iter_array, "tx-wifirate", (long)stainfo[i].txRate);
		add_assoc_double(iter_array, "rx_rate", (long long)stainfo[i].rr);
		add_assoc_double(iter_array, "tx_rate", (long long)stainfo[i].tr);
		add_assoc_double(iter_array, "rx_bytes", (long long)stainfo[i].rxbytes);
		add_assoc_double(iter_array, "tx_bytes", (long long)stainfo[i].txbytes);
		add_assoc_double(iter_array, "rx_packets", (long long)stainfo[i].rxpackets);
		add_assoc_double(iter_array, "tx_packets", (long long)stainfo[i].txpackets);
		add_next_index_zval(iter, iter_array);
	}
        
#if WTP_DEBUG_ENABLE
    syslog(LOG_DEBUG, "after for call show_network_stalist sta_num %d\n", STALIST.sta_num);
#endif
	if (connection)
	{
		uninit_dbus_connection(&connection);
	}
    
    CW_FREE_OBJECT(STALIST.stainfo);
    
	if (object_init(return_value) != SUCCESS)
    {
        RETURN_LONG(PHP_OBJ_INIT_FAIL);
    }
    
    add_assoc_long(iter_len, "sta_num", (long)STALIST.sta_num);
    add_property_zval(return_value, "stas", iter_len);
    add_property_zval(return_value, "value", iter); 
}

EXT_FUNCTION(ext_wtp_list)
{
	DBusConnection *connection = NULL;
	
	int ret = -1;
	int wtpid = 0;
	int wtp_num = 0;
	char wtpip[32] = {0};
	int i = 0, j = 0, k = 0;
	WID_WTP_TO_WEB wtpwebinfo;
	WID_ACCESS ACC_WTP_TO_WEB;
	struct wtp_access_info *wtpaccinfo = NULL;

	zval *iter, *iter_radio, *iter_wlan, *iter_delay, *iter_disturb, *iter_array;
	MAKE_STD_ZVAL(iter);
	array_init(iter);
	zval *iter_len;
	MAKE_STD_ZVAL(iter_len);
	array_init(iter_len);
	memset(&wtpwebinfo, 0, sizeof(WID_WTP_TO_WEB));
	ret = dbus_connection_init(&connection);
	if (!connection)
	{
		syslog(LOG_ERR, "dbus connection init failed when get wtp list ret %d", ret);
		RETURN_LONG(-1);
	}
	if (ret != 0)
	{
		syslog(LOG_ERR, "dbus connection init failed when get wtp list ret %d", ret);
		uninit_dbus_connection(&connection);
		RETURN_LONG(-1);
	}
	for (wtpid = 1; wtpid <= MAX_WTP_ID; wtpid++)
	{
		MAKE_STD_ZVAL(iter_array);
		array_init(iter_array);
		memset(&wtpwebinfo, 0, sizeof(WID_WTP_TO_WEB));
		wtpwebinfo.WTPID = wtpid;
#if WTP_DEBUG_ENABLE
//		syslog(LOG_DEBUG, "before call show_network_wtp_config wtpid %d", wtpid);
#endif
		ret = show_network_wtp_config(&wtpwebinfo, connection);
#if WTP_DEBUG_ENABLE
		if (wtpwebinfo.isused)
		{
			syslog(LOG_DEBUG, "after call show_network_wtp_config wtpid %d ret %d used %d ip %s name %s mac %s model %s state %d", 
				wtpid, ret, wtpwebinfo.isused, wtpwebinfo.WTPIP, wtpwebinfo.WTPNAME, wtpwebinfo.WTPMAC, wtpwebinfo.WTPModel, wtpwebinfo.WTPStat);
		}
#endif
		if (wtpwebinfo.isused)
		{
		    add_assoc_long(iter_array, "_id", (long)wtpid);
			memset(wtpip, 0, 32);
			if (wtpwebinfo.WTPIP)
			{
				strcpy(wtpip, wtpwebinfo.WTPIP);
			}
			strtok(wtpip, ":");
			add_assoc_string(iter_array, "ip", wtpip, 1);
			add_assoc_string(iter_array, "name", (char *)(wtpwebinfo.WTPNAME ? (char *)wtpwebinfo.WTPNAME : ""), 1);
			add_assoc_string(iter_array, "mac", (char *)(wtpwebinfo.WTPMAC ? (char *)wtpwebinfo.WTPMAC : ""), 1);
			add_assoc_string(iter_array, "model", wtpwebinfo.WTPModel?wtpwebinfo.WTPModel:"", 1);
			if (wtpwebinfo.WTPStat == WID_QUIT)
			{
#if WTP_DEBUG_ENABLE
				syslog(LOG_DEBUG, "afi%d stat %d quitreason %d", wtpid, wtpwebinfo.WTPStat, wtpwebinfo.quitreason);
#endif
				if (wtpwebinfo.quitreason == WTP_NORMAL)
				{
					add_assoc_long(iter_array, "state", (long)EXT_WTP_ADMITING);
				}
				//else if(wtpwebinfo.quitreason == WTP_UPGRADE)
				//{
				//	add_assoc_long(iter_array, "state", (long)EXT_WTP_UPGRADING);
				//}
				else
				{
					add_assoc_long(iter_array, "state", (long)WID_QUIT);
				}
			}
			else
			{
				add_assoc_long(iter_array, "state", (long)wtpwebinfo.WTPStat);
			}
			add_assoc_long(iter_array, "cpu_per", (long)wtpwebinfo.cpu_per);
			add_assoc_long(iter_array, "mem_per", (long)wtpwebinfo.mem_per);
			add_assoc_long(iter_array, "flash_per", (long)wtpwebinfo.flash_per);
			add_assoc_long(iter_array, "delay_num", (long)wtpwebinfo.apdelayinfo.delay_num);
			
			MAKE_STD_ZVAL(iter_delay);
			array_init(iter_delay);
			for (j = 0; j <= wtpwebinfo.apdelayinfo.delay_num; j++)
			{
				zval *iter_array_r;
				MAKE_STD_ZVAL(iter_array_r);
				array_init(iter_array_r);
				add_assoc_long(iter_array_r, "delay_type", (long)wtpwebinfo.apdelayinfo.ap_average_delay[j].delay_type);
				add_assoc_long(iter_array_r, "pkt_loss", (long)wtpwebinfo.apdelayinfo.ap_average_delay[j].pkt_loss);
				add_assoc_long(iter_array_r, "delay_time", (long)wtpwebinfo.apdelayinfo.ap_average_delay[j].delay_time);
				add_next_index_zval(iter_delay, iter_array_r);
			}
			add_assoc_long(iter_array, "num_sta", (long)wtpwebinfo.wtp_accessed_sta_num);
			add_assoc_long(iter_array, "user-num_sta", (long)wtpwebinfo.wtp_accessed_sta_num);
			add_assoc_long(iter_array, "uplink_bandwidth", (long)wtpwebinfo.uplink_bandwidth);
			add_assoc_long(iter_array, "downlink_bandwidth", (long)wtpwebinfo.downlink_bandwidth);
			add_assoc_long(iter_array, "tx_packets", (long)wtpwebinfo.tx_packets);
			add_assoc_long(iter_array, "rx_packets", (long)wtpwebinfo.rx_packets);
			add_assoc_double(iter_array, "tx_bytes", (long long)wtpwebinfo.tx_bytes);
			add_assoc_double(iter_array, "rx_bytes", (long long)wtpwebinfo.rx_bytes);
			add_assoc_string(iter_array, "version", wtpwebinfo.codever ? wtpwebinfo.codever : "", 1);
			add_assoc_long(iter_array, "uptime", (long)(wtpwebinfo.add_time ? (time(NULL)-wtpwebinfo.add_time):0));
			add_assoc_long(iter_array, "adopted", (long)1);
			
			MAKE_STD_ZVAL(iter_wlan);
			array_init(iter_wlan);
			j = 0;
			while (wtpwebinfo.wlans[j].WlanId)
			{
				zval *iter_array_r;
				MAKE_STD_ZVAL(iter_array_r);
				array_init(iter_array_r);
				add_assoc_long(iter_array_r, "wlanconf_id", (long)wtpwebinfo.wlans[j].WlanId);
				add_assoc_string(iter_array_r, "essid", (char *)wtpwebinfo.wlans[j].ssid, 1);
				add_assoc_string(iter_array_r, "state", (char *)(wtpwebinfo.wlans[j].isEnable ? "RUN":""), 1);
				add_assoc_long(iter_array_r, "wlan_sta", (long)wtpwebinfo.wtp_wlan_wifi.wlan_wifi[j].sta_num);
				add_assoc_long(iter_array_r, "wlan_upbw", (long)wtpwebinfo.wtp_wlan_wifi.wlan_wifi[j].uplink_bandwidth);
				add_assoc_long(iter_array_r, "wlan_downbw", (long)wtpwebinfo.wtp_wlan_wifi.wlan_wifi[j].downlink_bandwidth);
				add_assoc_long(iter_array_r, "wlan_txpkt", (long)wtpwebinfo.wtp_wlan_wifi.wlan_wifi[j].tx_packets);
				add_assoc_long(iter_array_r, "wlan_rxpkt", (long)wtpwebinfo.wtp_wlan_wifi.wlan_wifi[j].rx_packets);
				add_assoc_double(iter_array_r, "tx_bytes", (long long)wtpwebinfo.wtp_wlan_wifi.wlan_wifi[j].tx_bytes);
				add_assoc_double(iter_array_r, "rx_bytes", (long long)wtpwebinfo.wtp_wlan_wifi.wlan_wifi[j].rx_bytes);
				add_assoc_long(iter_array_r, "up", (long)1);
				add_next_index_zval(iter_wlan, iter_array_r);
				
				unsigned char ssidbuffer[DEFAULT_LEN] = {0};
				hand_hex_char_dump_essid((unsigned char *)wtpwebinfo.wlans[j].ssid, strlen(wtpwebinfo.wlans[j].ssid), ssidbuffer);
				syslog(LOG_DEBUG, "%s-%d wtp%d wlan%d ssid %s sta_num %u upbw %u downbw %u txpkt %u rxpkt %u tx_bytes %llu rx_bytes %llu\n", 
						__func__,__LINE__, wtpid, wtpwebinfo.wlans[j].WlanId, ssidbuffer,
						wtpwebinfo.wtp_wlan_wifi.wlan_wifi[j].sta_num,
						wtpwebinfo.wtp_wlan_wifi.wlan_wifi[j].uplink_bandwidth,
						wtpwebinfo.wtp_wlan_wifi.wlan_wifi[j].downlink_bandwidth,
						wtpwebinfo.wtp_wlan_wifi.wlan_wifi[j].tx_packets, wtpwebinfo.wtp_wlan_wifi.wlan_wifi[j].rx_packets,
						wtpwebinfo.wtp_wlan_wifi.wlan_wifi[j].tx_bytes, wtpwebinfo.wtp_wlan_wifi.wlan_wifi[j].rx_bytes);
				j++;
			}
			
			MAKE_STD_ZVAL(iter_radio);
			array_init(iter_radio);
			
			if (wtpwebinfo.RadioCount > 0)
			{
				for (j = 0; j < wtpwebinfo.RadioCount; j++)
				{
					zval *iter_array_r;
					MAKE_STD_ZVAL(iter_array_r);
					array_init(iter_array_r);
					add_assoc_long(iter_array_r, "rid", (long)wtpwebinfo.WTP_Radio[j].Radio_L_ID);
					add_assoc_string(iter_array_r, "radio", get_radio_type_str(wtpwebinfo.WTP_Radio[j].Radio_Type), 1);
					add_assoc_long(iter_array_r, "channel", (long)wtpwebinfo.WTP_Radio[j].Radio_Chan);
					add_assoc_long(iter_array_r, "chan_per", (long)wtpwebinfo.WTP_Radio[j].chan_per);
					add_assoc_long(iter_array_r, "wifi_snr", (long)wtpwebinfo.WTP_Radio[j].wifi_snr);
					add_assoc_long(iter_array_r, "disturb_num", (long)wtpwebinfo.WTP_Radio[j].disturbinfo.disturb_num);
					MAKE_STD_ZVAL(iter_disturb);
					array_init(iter_disturb);
					for (k = 0; k < wtpwebinfo.WTP_Radio[j].disturbinfo.disturb_num; k++)
					{
						zval *iter_struct;
						MAKE_STD_ZVAL(iter_struct);
						array_init(iter_struct);
						add_assoc_long(iter_struct, "disturb_type", (long)wtpwebinfo.WTP_Radio[j].disturbinfo.radio_disturb[k].disturb_type);
						add_assoc_long(iter_struct, "disturb_rssi", (long)wtpwebinfo.WTP_Radio[j].disturbinfo.radio_disturb[k].disturb_rssi);
						add_next_index_zval(iter_disturb, iter_struct);
					}
					
					add_assoc_long(iter_array_r, "txpower", (long)wtpwebinfo.WTP_Radio[j].Radio_TXP);
					add_assoc_long(iter_array_r, "cwmode", (long)wtpwebinfo.WTP_Radio[j].cwmode);
					add_assoc_zval(iter_array_r, "disturb_table", iter_disturb);
					add_next_index_zval(iter_radio, iter_array_r);
				}
			}
			add_assoc_zval(iter_array, "delay_table", iter_delay);
			add_assoc_zval(iter_array, "radio_table", iter_radio);
			add_assoc_zval(iter_array, "vap_table", iter_wlan);
		    add_next_index_zval(iter, iter_array);
		    wtp_num++;
		}
    }
#if WTP_DEBUG_ENABLE
    syslog(LOG_DEBUG, "after for call show_network_wtp_config wtp_num %d\n", wtp_num);
#endif

	memset(&ACC_WTP_TO_WEB, 0, sizeof(WID_ACCESS));
	
	ret = show_network_ac_access_wtplist(&ACC_WTP_TO_WEB, connection);
	
	wtpaccinfo = ACC_WTP_TO_WEB.wtp_list;
	for (i = 0; i < ACC_WTP_TO_WEB.num; i++)
	{
		MAKE_STD_ZVAL(iter_array);
		array_init(iter_array);
		
		struct in_addr ip_addr;
		char in_addr[32] = {0};
		ip_addr.s_addr = (wtpaccinfo[i].ip);
		snprintf(in_addr,32, "%s",inet_ntoa(ip_addr));

#if WTP_DEBUG_ENABLE
        
		syslog(LOG_DEBUG, "after call show access wtplist ret %d ip %s mac %s name %s model %s "
							"code %s sn %s version %s codever %s ifname %s\n", 
							ret, inet_ntoa(ip_addr), wtpaccinfo[i].WTPMAC, wtpaccinfo[i].WTPNAME,
							wtpaccinfo[i].model, wtpaccinfo[i].apcode, wtpaccinfo[i].sn,
							wtpaccinfo[i].version, wtpaccinfo[i].codever, wtpaccinfo[i].ifname);
    
#endif

		add_assoc_string(iter_array, "ip", in_addr, 1);
		add_assoc_string(iter_array, "name", (char *)(wtpaccinfo[i].WTPNAME ? (char *)wtpaccinfo[i].WTPNAME : ""), 1);
		add_assoc_string(iter_array, "mac", (char *)(wtpaccinfo[i].WTPMAC ? (char *)wtpaccinfo[i].WTPMAC : ""), 1);
		add_assoc_string(iter_array, "model", wtpaccinfo[i].model ? wtpaccinfo[i].model : "", 1);
		add_assoc_string(iter_array, "code", wtpaccinfo[i].apcode ? wtpaccinfo[i].apcode: "", 1);
		add_assoc_string(iter_array, "version", wtpaccinfo[i].codever ? wtpaccinfo[i].codever : "", 1);
		add_assoc_long(iter_array, "state", (long)WID_DISCOVERY);
		add_assoc_long(iter_array, "adopted", (long)0);
		add_assoc_long(iter_array, "default", (long)1);
		
		add_next_index_zval(iter, iter_array);
		wtp_num++;
	}
        
#if WTP_DEBUG_ENABLE
	syslog(LOG_DEBUG, "after for call show_network_ac_access_wtplist wtp_num %d ", ACC_WTP_TO_WEB.num);
#endif
	if (connection)
	{
		uninit_dbus_connection(&connection);
	}
	
	web_free_fun_access_wtp(&ACC_WTP_TO_WEB); 
	
	if (object_init(return_value) != SUCCESS)
	{
		RETURN_LONG(PHP_OBJ_INIT_FAIL);
	}
	
	add_assoc_long(iter_len, "wtp_num", (long)wtp_num);
	add_property_zval(return_value, "wtps", iter_len);
	add_property_zval(return_value, "value", iter); 
}

EXT_FUNCTION(ext_get_wtp_ip_list)
{
	DBusConnection *connection = NULL;
	
	int ret = -1;
	int wtpid = 0;
	int wtp_num = 0;
	WID_WTP wtpinfo;
	
	zval *iter, *iter_array;
	MAKE_STD_ZVAL(iter);
	array_init(iter);
	zval *iter_len;
	MAKE_STD_ZVAL(iter_len);
	array_init(iter_len);
	memset(&wtpinfo, 0, sizeof(WID_WTP));
	
    ret = dbus_connection_init(&connection);
    if(!connection)
    {
		syslog(LOG_ERR, "dbus connection init failed when get wtp list ret %d", ret);
		RETURN_LONG(-1);
    }
    if(ret != 0)
    {
		syslog(LOG_ERR, "dbus connection init failed when get wtp list ret %d", ret);
		uninit_dbus_connection(&connection);
		RETURN_LONG(-1);
    }
    for(wtpid = 1; wtpid <= MAX_WTP_ID; wtpid++)
    {
		MAKE_STD_ZVAL(iter_array);
		array_init(iter_array);
		memset(&wtpinfo, 0, sizeof(WID_WTP));
		wtpinfo.WTPID = wtpid;
#if WTP_DEBUG_ENABLE
//		syslog(LOG_DEBUG, "before call show_network_wtp_config wtpid %d", wtpid);
#endif
		ret = show_network_wtp_ip_list(&wtpinfo, connection);
#if WTP_DEBUG_ENABLE
		if(wtpinfo.isused)
		{
			syslog(LOG_DEBUG, "after call show_network_wtp_ip_list wtpid %d ret %d used %d ip %s", 
				wtpid, ret, wtpinfo.isused, wtpinfo.WTPIP);
		}
#endif
		if(wtpinfo.isused)
		{
		    add_assoc_long(iter_array, "_id", (long)wtpid);
		    add_assoc_string(iter_array, "ip_port", wtpinfo.WTPIP, 1);
		    add_next_index_zval(iter, iter_array);
		    wtp_num++;
		}
    }
#if WTP_DEBUG_ENABLE
    syslog(LOG_DEBUG, "after for call show_network_wtp_config wtp_num %d ", wtp_num);
#endif
	if(connection)
	{
		uninit_dbus_connection(&connection);
	}
    
	if(object_init(return_value) != SUCCESS)
    {
        RETURN_LONG(PHP_OBJ_INIT_FAIL);
    }
    add_assoc_long(iter_len, "wtp_num", (long)wtp_num);
    add_property_zval(return_value, "wtps", iter_len);
    add_property_zval(return_value, "value", iter); 
}

EXT_FUNCTION(ext_restart_wtp)
{
	long wtpid = 0;
	DBusConnection *connection = NULL;
	int ret = 0;
	char *wtpmac = NULL;
	char *admin = NULL;
	
	ext_para_get(argc, argv, EXT_TYPE_LONG, &wtpid, EXT_TYPE_STRING, &wtpmac, EXT_TYPE_STRING, &admin);
	
    ret = dbus_connection_init(&connection);
    if(!connection || 0 != ret)
    {
		syslog(LOG_ERR, "dbus connection init failed when restart wtp[%ld] ret %d", wtpid, ret);
		if(connection)
		{			
			uninit_dbus_connection(&connection);
		}
		RETURN_LONG(-1);
    }
	ret = handlib_restart_wtp_by_id((int)wtpid, connection);
	if(0 != ret)
	{
		syslog(LOG_ERR, "call handlib restart wtp[%ld] failed, ret %d ", wtpid, ret);
	}
	else if(wtpmac && admin)
	{
		active_ap_operated_by_admin(wtpmac, admin, AP_RESTARTED_BY_ADMIN);
	}
	if(connection)
	{
		uninit_dbus_connection(&connection);
	}

	RETURN_LONG(ret);    
}

EXT_FUNCTION(ext_delete_wtp)
{
	long wtpid = 0;
	DBusConnection *connection = NULL;
	int ret = 0;
	char *wtpmac = NULL;
	char * admin = NULL;
	
	ext_para_get(argc, argv, EXT_TYPE_LONG, &wtpid, EXT_TYPE_STRING, &wtpmac, EXT_TYPE_STRING, &admin);
	
    ret = dbus_connection_init(&connection);
    if(!connection || 0 != ret)
    {
		syslog(LOG_ERR, "dbus connection init failed when delete wtp[%ld] ret %d", wtpid, ret);
		if(connection)
		{			
			uninit_dbus_connection(&connection);
		}
		RETURN_LONG(-1);
    }
	ret = handlib_delete_wtp_by_id((int)wtpid, connection);
	if(0 != ret)
	{
		syslog(LOG_ERR, "call handlib delete wtp[%ld] failed, ret %d ", wtpid, ret);
	}
	else
	{
		ret = active_ap_operated_by_admin(wtpmac, admin, AP_FORGOTEN_BY_ADMIN);
        if(ret < 0)
        {
		    syslog(LOG_ERR, " record active afi %ld [%s] remove failed! ret %d", wtpid, wtpmac, ret);
		}
		ret = remove_wtp_save_config((unsigned int)wtpid);
		if(ret < 0)
		{
		    syslog(LOG_ERR, " remove afi %ld [%s] from config file failed! ret %d", wtpid, wtpmac, ret);
		}
	}
	if(connection)
	{
		uninit_dbus_connection(&connection);
	}

	RETURN_LONG(ret);    
}

EXT_FUNCTION(ext_adopt_new_wtp)
{
    DBusConnection *connection = NULL;
	int ret = 0;
	NEW_WTP_ARG new_wtp;
	char * macStr = NULL;
	char * tmpPtr = NULL;
	int i = 0;
	char * admin = NULL;
	char  tmpMacStr[32] = {0};
    zval *iter_array;
    MAKE_STD_ZVAL(iter_array);
    array_init(iter_array);
	memset(&new_wtp, 0, sizeof(NEW_WTP_ARG));
	
	ext_para_get(argc, argv, EXT_TYPE_STRING, &new_wtp.WTPNAME, 
		EXT_TYPE_STRING, &macStr, EXT_TYPE_STRING, &new_wtp.WTPModel, EXT_TYPE_STRING, &admin);

	if(!macStr || !new_wtp.WTPNAME || !new_wtp.WTPModel)
	{
		syslog(LOG_ERR, "%s line %d get bad parameter macStr %p wtpname %p wtpmodel %p ", 
			__func__, __LINE__, macStr, new_wtp.WTPNAME, new_wtp.WTPModel);
		RETURN_LONG(-1);
	}
	strncpy(tmpMacStr, macStr, 31);
	tmpPtr = strtok(tmpMacStr, ":");
	while(tmpPtr && i < MAC_LEN)
	{
		new_wtp.WTPMAC[i++] = (unsigned char)strtoul(tmpPtr, NULL, 16);
		tmpPtr = strtok(NULL, ":");
	}
    ret = dbus_connection_init(&connection);
    if(!connection || 0 != ret)
    {
		syslog(LOG_ERR, "dbus connection init failed when admit wtp[%02x:%02x:%02x:%02x:%02x:%02x] ret %d", 
						MAC2STR(new_wtp.WTPMAC), ret);
		if(connection)
		{			
			uninit_dbus_connection(&connection);
		}
		RETURN_LONG(-1);
    }
	
	ret = handlib_create_new_wtp(&new_wtp, connection);
	if(0 != ret || 0 == new_wtp.WTPID)
	{
		syslog(LOG_ERR, "call handlib admit wtp[%02x:%02x:%02x:%02x:%02x:%02x] failed, ret %d wtpid %d", 
						MAC2STR(new_wtp.WTPMAC), ret, new_wtp.WTPID);
	}
	else
	{
		ret = active_ap_operated_by_admin(macStr, admin, AP_ADMITED_BY_ADMIN);
		if(ret < 0)
		{
		    syslog(LOG_WARNING, FUNC_LINE_FORMAT" record active to database failed, event AP_AMITED_BY_ADMIN AP[%s] Admin[%s]!", 
		        FUNC_LINE_VALUE, macStr, admin);
		}
		ret = add_modify_wtp_save_config(&new_wtp);
		if(ret < 0)
		{
		    syslog(LOG_WARNING, FUNC_LINE_FORMAT" save config for add new wtp failed!", FUNC_LINE_VALUE);
		}
	}
	if(connection)
	{
		uninit_dbus_connection(&connection);
	}
	
	add_assoc_long(iter_array, "result", (long)ret);
	add_assoc_long(iter_array, "wtpid", (long)new_wtp.WTPID);
	
	if(object_init(return_value) != SUCCESS)
	{
		RETURN_LONG(PHP_OBJ_INIT_FAIL);
	}
	
	add_property_zval(return_value, "value", iter_array);
}

EXT_FUNCTION(ext_set_wtp_name)
{
	DBusConnection *connection = NULL;
	int ret = 0;
	long wtpid = 0;
	NEW_WTP_ARG new_wtp;
	zval *iter_array;
	MAKE_STD_ZVAL(iter_array);
	array_init(iter_array);
	memset(&new_wtp, 0, sizeof(NEW_WTP_ARG));
	
	ext_para_get(argc, argv, EXT_TYPE_LONG, &wtpid, EXT_TYPE_STRING, &new_wtp.WTPNAME);
	
	if(!new_wtp.WTPNAME)
	{
		syslog(LOG_ERR, "%s line %d get bad parameter wtpname %p", __func__, __LINE__, new_wtp.WTPNAME);
		RETURN_LONG(-1);
	}
	
	ret = dbus_connection_init(&connection);
	if(!connection || 0 != ret)
	{
		syslog(LOG_ERR, "dbus connection init failed when modify wtp[%ld] name %s ret %d", wtpid, new_wtp.WTPNAME, ret);
		if(connection)
		{
			uninit_dbus_connection(&connection);
		}
		RETURN_LONG(-1);
    }
	
	new_wtp.WTPID = (int)wtpid;
	ret = handlib_set_wtp_name(&new_wtp, connection);
	if(0 != ret)
	{
		syslog(LOG_ERR, "call handlib modify wtp%d name %s failed, ret %d", new_wtp.WTPID, new_wtp.WTPNAME, ret);
	}
	else
	{
		ret = add_modify_wtp_save_config(&new_wtp);
		if(ret < 0)
		{
			syslog(LOG_WARNING, FUNC_LINE_FORMAT" save config for add new wtp failed!", FUNC_LINE_VALUE);
		}
	}
	if(connection)
	{
		uninit_dbus_connection(&connection);
	}
	
	RETURN_LONG(ret); 
}

EXT_FUNCTION(ext_set_sta_name)
{
	DBusConnection *connection = NULL;
	int i = 0;
	int ret = 0;
	long wtpid = 0, l_radioid = 0, wlanid = 0;
	char tmpMacStr[32] = {0};
	char *tmpPtr = NULL;
	char *macStr = NULL;
	struct stainfo_to_web new_sta;
	zval *iter_array;
	MAKE_STD_ZVAL(iter_array);
	array_init(iter_array);
	memset(&new_sta, 0, sizeof(struct stainfo_to_web));
	
	ext_para_get(argc, argv, EXT_TYPE_LONG, &wtpid, EXT_TYPE_LONG, &l_radioid, EXT_TYPE_LONG, &wlanid,
				 EXT_TYPE_STRING, &new_sta.sta_name, EXT_TYPE_STRING, &macStr);
	
	if(!macStr || !new_sta.sta_name)
	{
		syslog(LOG_ERR, "%s line %d get bad parameter macStr %p staname %p", __func__, __LINE__, macStr, new_sta.sta_name);
		RETURN_LONG(-1);
	}
	
	strncpy(tmpMacStr, macStr, 31);
	tmpPtr = strtok(tmpMacStr, ":");
	while(tmpPtr && i < MAC_LEN)
	{
		new_sta.addr[i++] = (unsigned char)strtoul(tmpPtr, NULL, 16);
		tmpPtr = strtok(NULL, ":");
	}
	
	ret = dbus_connection_init(&connection);
	if(!connection || 0 != ret)
	{
		syslog(LOG_ERR, "dbus connection init failed when modify sta["MACSTR"] name %s ret %d", MAC2STR(new_sta.addr), new_sta.sta_name, ret);
		if(connection)
		{
			uninit_dbus_connection(&connection);
		}
		RETURN_LONG(-1);
	}
	
	new_sta.wtpid = (unsigned int)wtpid;
	new_sta.l_radioid = (unsigned char)l_radioid;
	new_sta.wlanid = (unsigned char)wlanid;
	ret = handlib_set_sta_name(&new_sta, connection);
	if(0 != ret)
	{
		syslog(LOG_ERR, "call handlib modify sta["MACSTR"] name %s failed, ret %d", MAC2STR(new_sta.addr), new_sta.sta_name, ret);
	}
	
	if(connection)
	{
		uninit_dbus_connection(&connection);
	}
	
    RETURN_LONG(ret); 
}


EXT_FUNCTION(ext_get_aps_list)
{
	DBusConnection *connection = NULL;
	
	int ret = -1;
	int ap_nums = 0;
	int i = 0, j = 0;
	char tmpMacStr[32] = {0};
	CLIENT_INFO_HANDLE client_info = NULL;

	zval *iter, *iter_sec_array, *iter_array, *iter_neighbors;
	MAKE_STD_ZVAL(iter);
	array_init(iter);
	zval *iter_len;
	MAKE_STD_ZVAL(iter_len);
	array_init(iter_len);
	
	ret = dbus_connection_init(&connection);
	
	if (!connection)
	{
		syslog(LOG_ERR, "dbus connection init failed when get wtp list ret %d", ret);
		RETURN_LONG(-1);
	}
	if (ret != 0)
	{
		syslog(LOG_ERR, "dbus connection init failed when get aps list ret %d", ret);
		uninit_dbus_connection(&connection);
		RETURN_LONG(-1);
	}
	
	client_info = get_neighbors_aps_info(connection, &ap_nums);
	
	for (i = 0; i < ap_nums; i++)
	{
		MAKE_STD_ZVAL(iter_array);
		array_init(iter_array);
		memset(tmpMacStr, 0, sizeof(tmpMacStr));
		snprintf(tmpMacStr, 31, MACSTR, MAC2STR(client_info[i].ap_mac));
		add_assoc_string(iter_array, "RadioMac", (char *)tmpMacStr, 1);
		add_assoc_long(iter_array, "Channel", (long)(client_info[i].channel));
		add_assoc_long(iter_array, "RadioType", (long)(client_info[i].type));
		add_assoc_long(iter_array, "TxPower", (long)(0));

		NEIGHBOR_LIST_HANDLE p = client_info[i].neighbor_link_head;
		MAKE_STD_ZVAL(iter_sec_array);
		array_init(iter_sec_array);
		for (j = 0; j < client_info[i].neighbor_cnt && p != NULL; j++)
		{
			MAKE_STD_ZVAL(iter_neighbors);
			array_init(iter_neighbors);
			memset(tmpMacStr, 0, sizeof(tmpMacStr));
			snprintf(tmpMacStr, 31, MACSTR, MAC2STR(p->mac));
			syslog(LOG_ERR, "NO.%d's neighbor MAC: %s", j+1, tmpMacStr);
			add_assoc_string(iter_neighbors, "NeighborRadioMac", (char *)(tmpMacStr), 1);
			add_assoc_long(iter_neighbors, "NeighborRadioChannel", (long)p->channel);
			add_assoc_long(iter_neighbors, "NeighborRadioRssi", (long)p->rssi);
			add_assoc_long(iter_neighbors, "NeighborFlag", (long)p->neighbor_flag);
			add_next_index_zval(iter_sec_array, iter_neighbors);
			p = p->next;
		}
		add_assoc_zval(iter_array, "Neighbors", iter_sec_array);
		add_next_index_zval(iter, iter_array);
	}
	
	free_all_neighbor_ap(client_info, ap_nums);
	
	if (connection)
	{
		uninit_dbus_connection(&connection);
	}
	
	if (object_init(return_value) != SUCCESS)
	{
		RETURN_LONG(PHP_OBJ_INIT_FAIL);
	}
	
	add_property_zval(return_value, "value", iter); 
}


EXT_FUNCTION(ext_get_neighbor_ap_list)
{
	DBusConnection *connection = NULL;
	
	int ret = -1;
	int wtp_num = 0;
	int i = 0, j = 0, k = 0;
	char tmpMacStr[32] = {0};
	struct allwtp_neighborap *neighbor_aplist = NULL;
	struct allwtp_neighborap *showneighborap = NULL;
	
	zval *iter, *iter_array;
	MAKE_STD_ZVAL(iter);
	array_init(iter);
	zval *iter_len;
	MAKE_STD_ZVAL(iter_len);
	array_init(iter_len);
	ret = dbus_connection_init(&connection);
	if(!connection)
	{
		syslog(LOG_ERR, "dbus connection init failed when get wtp list ret %d", ret);
		RETURN_LONG(-1);
	}
	if(ret != 0)
	{
		syslog(LOG_ERR, "dbus connection init failed when get wtp list ret %d", ret);
		uninit_dbus_connection(&connection);
		RETURN_LONG(-1);
	}
	
    neighbor_aplist = show_neighbor_ap_list_config(connection, &wtp_num, &ret);
	
	if((neighbor_aplist != NULL) && (0 == ret))
	{
		for (i = 0; i < wtp_num; i++)
		{
			MAKE_STD_ZVAL(iter_array);
			array_init(iter_array);
			
			if(showneighborap == NULL)
			{
				showneighborap = neighbor_aplist->allwtp_neighborap_list;
			}
			else 
			{
				showneighborap = showneighborap->next;
			}
			if(showneighborap == NULL)
			{
				break;
			}
			snprintf(tmpMacStr, 31, MACSTR, MAC2STR(showneighborap->WTPmac));
			add_assoc_string(iter_array, "mac", (char *)tmpMacStr, 1);

			struct allwtp_neighborap_radioinfo *radioshow = NULL;
			for(j = 0; j < showneighborap->radio_num;j++)
			{
				if(radioshow == NULL)
				{
					radioshow = showneighborap->radioinfo_head;
				}
				else
				{
					radioshow = radioshow->next;
				}
				if(radioshow == NULL)
				{
					break;
				}
				
				if((radioshow->failreason != 0)&&(radioshow->rouge_ap_count == 0))
				{
					syslog(LOG_ERR, "AP scanning disable or radio["MACSTR"] have no neighbroAP\n",MAC2STR(radioshow->radiomac));
				}
				else
				{
					struct Neighbor_AP_ELE *neighshow = NULL;
					for(k = 0; k < radioshow->rouge_ap_count; k++)
					{
						if(neighshow == NULL)
						{
							neighshow = radioshow->neighborapInfos_head;
						}
						else
						{
							neighshow = neighshow->next;
						}
						if(neighshow == NULL)
						{
							break;
						}
#if WTP_DEBUG_ENABLE
						syslog(LOG_DEBUG, MACSTR" %-4d %-4d %-4d %-4d %-12s\n",\
								MAC2STR(neighshow->BSSID),neighshow->Rate,neighshow->Channel,neighshow->RSSI,neighshow->NOISE,neighshow->ESSID);
#endif
					
					}
				}
			}
		}
	}
	dcli_free_allwtp_neighbor_ap(neighbor_aplist);
	
	if(connection)
	{
		uninit_dbus_connection(&connection);
	}
	
	if(object_init(return_value) != SUCCESS)
	{
		RETURN_LONG(PHP_OBJ_INIT_FAIL);
	}
	
	add_assoc_long(iter_len, "wtp_num", (long)wtp_num);
	add_property_zval(return_value, "neighboraps", iter_len);
	add_property_zval(return_value, "value", iter); 
}

EXT_FUNCTION(ext_set_country_code)
{
	DBusConnection *connection = NULL;
	int ret = 0;
	char *country_code = NULL;
	unsigned int countrycode = COUNTRY_USA_US;
	zval *iter_array;
	MAKE_STD_ZVAL(iter_array);
	array_init(iter_array);
	
	ext_para_get(argc, argv, EXT_TYPE_STRING, &country_code);
	
	ret = dbus_connection_init(&connection);
	if (!connection || 0 != ret)
	{
		syslog(LOG_ERR, "dbus connection init failed when set country code %s ret %d\n", country_code, ret);
		if(connection)
		{
			uninit_dbus_connection(&connection);
		}
		RETURN_LONG(-1);
	}
	
	countrycode = (unsigned int)parse_country_code((char *) country_code);	
	
	if (countrycode == COUNTRY_CODE_ERROR_SMALL_LETTERS)
	{
		syslog(LOG_ERR, "<error> input country code should be capital letters\n");
		if (connection)
		{
			uninit_dbus_connection(&connection);
		}
		RETURN_LONG(-1);
	}
	if (countrycode == COUNTRY_CODE_ERROR)
	{
		syslog(LOG_ERR, "<error> input country code error\n");
		if (connection)
		{
			uninit_dbus_connection(&connection);
		}
		RETURN_LONG(-1);
	}
	
	syslog(LOG_ERR, "%s: %d set country code %s(%d)\n", __func__, __LINE__, country_code, countrycode);
	
	ret = set_network_country_code(countrycode, connection);
	
	if(0 != ret)
	{
		syslog(LOG_ERR, "call handlib set country code %s(%d) failed, ret %d\n", country_code, countrycode, ret);
	}
	
	if(connection)
	{
		uninit_dbus_connection(&connection);
	}
	
	RETURN_LONG(ret);
}

EXT_FUNCTION(ext_get_country_code)
{
	DBusConnection *connection = NULL;
	
	int ret = -1;
	int country_code = 0;
	int country_list[] = { 156, /*China*/ 0, /*Europe_EU*/ 840, /*USA*/ 392, /*Japan*/
		250, /*France*/ 724, /* Spain*/ };
	
	zval *iter;
	MAKE_STD_ZVAL(iter);
	array_init(iter);
	zval *iter_len;
	MAKE_STD_ZVAL(iter_len);
	array_init(iter_len);
	
	ret = dbus_connection_init(&connection);
	if(!connection)
	{
		syslog(LOG_ERR, "dbus connection init failed when get country code ret %d\n", ret);
		RETURN_LONG(-1);
	}
	if(ret != 0)
	{
		syslog(LOG_ERR, "dbus connection init failed when get country code ret %d\n", ret);
		uninit_dbus_connection(&connection);
		RETURN_LONG(-1);
	}
	
	ret = show_network_country_code(&country_code, connection);
	
	if(connection)
	{
		uninit_dbus_connection(&connection);
	}
	
	if(object_init(return_value) != SUCCESS)
	{
		RETURN_LONG(PHP_OBJ_INIT_FAIL);
	}
	
	add_assoc_long(iter, "CountryCode", (long)country_list[country_code]);
	add_property_zval(return_value, "value", iter);
}

EXT_FUNCTION(ext_dynamic_select_radio_channel)
{
	DBusConnection *connection = NULL;
	int i = 0;
	int ret = 0;
	long channel = 0;
	char *macStr = NULL;
	char *tmpPtr = NULL;
	char tmpMacStr[32] = {0};
	NEW_RADIO_ARG new_radio;
	zval *iter_array;
	MAKE_STD_ZVAL(iter_array);
	array_init(iter_array);
	memset(&new_radio, 0, sizeof(NEW_RADIO_ARG));
	
	ext_para_get(argc, argv, EXT_TYPE_STRING, &macStr, EXT_TYPE_LONG, &channel);
	if(!macStr)
	{
		syslog(LOG_ERR, "%s line %d get bad parameter macStr %p\n", __func__, __LINE__, macStr);
		RETURN_LONG(-1);
	}
	strncpy(tmpMacStr, macStr, 31);
	tmpPtr = strtok(tmpMacStr, ":");
	while(tmpPtr && i < MAC_LEN)
	{
		new_radio.RADIOMAC[i++] = (unsigned char)strtoul(tmpPtr, NULL, 16);
		tmpPtr = strtok(NULL, ":");
	}
	
	ret = dbus_connection_init(&connection);
	if(!connection || 0 != ret)
	{
		syslog(LOG_ERR, "dbus connection init failed when set radio["MACSTR"] channel %ld ret %d", MAC2STR(new_radio.RADIOMAC), channel, ret);
		if(connection)
		{
			uninit_dbus_connection(&connection);
		}
		RETURN_LONG(-1);
	}
	
	new_radio.Radio_Chan = (unsigned char)channel;
	ret = handlib_dynamic_select_radio_channel(&new_radio, connection);
	
	if(0 != ret)
	{
		syslog(LOG_ERR, "call handlib set radio["MACSTR"] channel %u failed, ret %d", MAC2STR(new_radio.RADIOMAC), new_radio.Radio_Chan, ret);
	}
	
	if(connection)
	{
		uninit_dbus_connection(&connection);
	}
	
	RETURN_LONG(ret); 
}


EXT_FUNCTION(ext_set_radio_channel)
{
	DBusConnection *connection = NULL;
	int ret = 0;
	long wtpid = 0, l_radioid = 0, channel = 0;
	NEW_RADIO_ARG new_radio;
	zval *iter_array;
	MAKE_STD_ZVAL(iter_array);
	array_init(iter_array);
	memset(&new_radio, 0, sizeof(NEW_RADIO_ARG));
	
	ext_para_get(argc, argv, EXT_TYPE_LONG, &wtpid, EXT_TYPE_LONG, &l_radioid, EXT_TYPE_LONG, &channel);
	
	ret = dbus_connection_init(&connection);
	if(!connection || 0 != ret)
	{
		syslog(LOG_ERR, "dbus connection init failed when set radio%ld-%ld channel %ld ret %d", wtpid, l_radioid, channel, ret);
		if(connection)
		{
			uninit_dbus_connection(&connection);
		}
		RETURN_LONG(-1);
	}
	
	new_radio.WTPID = (unsigned int)wtpid;
	new_radio.Radio_L_ID = (unsigned char)l_radioid;
	new_radio.Radio_G_ID = new_radio.WTPID * L_RADIO_NUM + new_radio.Radio_L_ID;
	new_radio.Radio_Chan = (unsigned char)channel;
	syslog(LOG_ERR, "%s: %d set radio%d-%d channel %u", __func__, __LINE__, new_radio.WTPID, new_radio.Radio_L_ID, new_radio.Radio_Chan);
	
	ret = handlib_set_radio_channel(&new_radio, connection);
	
	if(0 != ret)
	{
		syslog(LOG_ERR, "call handlib set radio%d-%d channel %u failed, ret %d",  new_radio.WTPID, new_radio.Radio_L_ID, new_radio.Radio_Chan, ret);
	}
	
	if(connection)
	{
		uninit_dbus_connection(&connection);
	}
	
	RETURN_LONG(ret); 
}

EXT_FUNCTION(ext_set_radio_txpower)
{
	DBusConnection *connection = NULL;
	int ret = 0;
	long wtpid = 0, l_radioid = 0, txpower = 0;
	unsigned char *txpower_mode = 0;
	NEW_RADIO_ARG new_radio;
	zval *iter_array;
	MAKE_STD_ZVAL(iter_array);
	array_init(iter_array);
	memset(&new_radio, 0, sizeof(NEW_RADIO_ARG));
	
	ext_para_get(argc, argv, EXT_TYPE_LONG, &wtpid, EXT_TYPE_LONG, &l_radioid, EXT_TYPE_STRING, &txpower_mode, EXT_TYPE_LONG, &txpower);
	
	ret = dbus_connection_init(&connection);
	if(!connection || 0 != ret)
	{
		syslog(LOG_ERR, "dbus connection init failed when set radio%ld-%ld txpower_mode %s txpower %ld ret %d", wtpid, l_radioid, txpower_mode, txpower, ret);
		if(connection)
		{
			uninit_dbus_connection(&connection);
		}
		RETURN_LONG(-1);
	}
	
	if ((!strcmp((char *)txpower_mode,"high"))
		|| (!strcmp((char *)txpower_mode,"medium"))
		|| (!strcmp((char *)txpower_mode,"low"))
		|| (!strcmp((char *)txpower_mode,"auto")))
	{
		new_radio.Radio_TXP = 100;
	}
	else if (!strcmp((char *)txpower_mode,"custom"))
	{
		new_radio.Radio_TXP = (unsigned short)txpower;
	}
	else
	{
		new_radio.Radio_TXP = 100;
	}

	new_radio.WTPID = (unsigned int)wtpid;
	new_radio.Radio_L_ID = (unsigned char)l_radioid;
	new_radio.Radio_G_ID = new_radio.WTPID * L_RADIO_NUM + new_radio.Radio_L_ID;
	
	syslog(LOG_ERR, "%s: %d set radio%u-%u txpower_mode %s txpower %ld", __func__, __LINE__, new_radio.WTPID, new_radio.Radio_L_ID, txpower_mode, txpower);
	ret = handlib_set_radio_txpower(&new_radio, connection);
	
	if (0 != ret)
	{
		syslog(LOG_ERR, "call handlib set radio%u-%u txpower_mode %s txpower %ld failed, ret %d",  new_radio.WTPID, new_radio.Radio_L_ID, txpower_mode, txpower, ret);
	}
	
	if (connection)
	{
		uninit_dbus_connection(&connection);
	}
	
	RETURN_LONG(ret); 
}


EXT_FUNCTION(ext_set_radio_cwmode)
{
	DBusConnection *connection = NULL;
	int ret = 0;
	long wtpid = 0, l_radioid = 0;
	unsigned char *cwmode = 0;
	NEW_RADIO_ARG new_radio;
	zval *iter_array;
	MAKE_STD_ZVAL(iter_array);
	array_init(iter_array);
	memset(&new_radio, 0, sizeof(NEW_RADIO_ARG));
	
	ext_para_get(argc, argv, EXT_TYPE_LONG, &wtpid, EXT_TYPE_LONG, &l_radioid, EXT_TYPE_STRING, &cwmode);
	
	ret = dbus_connection_init(&connection);
	if (!connection || 0 != ret)
	{
		syslog(LOG_ERR, "dbus connection init failed when set radio%ld-%ld cwmode ht%s ret %d", wtpid, l_radioid, cwmode, ret);
		if(connection)
		{
			uninit_dbus_connection(&connection);
		}
		RETURN_LONG(-1);
	}
	if (!strcmp((char *)cwmode,"20"))
	{
		new_radio.cwmode = 0;
	}
	else if (!strcmp((char *)cwmode,"40"))
	{
		new_radio.cwmode = 2;
	}
	else
	{
		new_radio.cwmode = 1;
	}

	new_radio.WTPID = (unsigned int)wtpid;
	new_radio.Radio_L_ID = (unsigned char)l_radioid;
	new_radio.Radio_G_ID = new_radio.WTPID * L_RADIO_NUM + new_radio.Radio_L_ID;
	
	syslog(LOG_ERR, "%s: %d set radio%d-%d cwmode ht%s", __func__, __LINE__, new_radio.WTPID, new_radio.Radio_L_ID, cwmode);
	ret = handlib_set_radio_cwmode(&new_radio, connection);
	
	if (0 != ret)
	{
		syslog(LOG_ERR, "call handlib set radio%d-%d cwmode ht%s failed, ret %d",  new_radio.WTPID, new_radio.Radio_L_ID, cwmode, ret);
	}
	
	if (connection)
	{
		uninit_dbus_connection(&connection);
	}
	
	RETURN_LONG(ret); 
}


EXT_FUNCTION(ext_set_radio_mode)
{
	DBusConnection *connection = NULL;
	int ret = 0;
	long wtpid = 0, l_radioid = 0;
	unsigned char *radio_mode = 0;
	NEW_RADIO_ARG new_radio;
	zval *iter_array;
	MAKE_STD_ZVAL(iter_array);
	array_init(iter_array);
	memset(&new_radio, 0, sizeof(NEW_RADIO_ARG));
	
	ext_para_get(argc, argv, EXT_TYPE_LONG, &wtpid, EXT_TYPE_LONG, &l_radioid, EXT_TYPE_STRING, &radio_mode);
	
	ret = dbus_connection_init(&connection);
	if (!connection || 0 != ret)
	{
		syslog(LOG_ERR, "dbus connection init failed when set radio%ld-%ld type %s ret %d", wtpid, l_radioid, radio_mode, ret);
		if (connection)
		{           
			uninit_dbus_connection(&connection);
		}
		RETURN_LONG(-1);
	}
	
	new_radio.WTPID = (unsigned int)wtpid;
	new_radio.Radio_L_ID = (unsigned char)l_radioid;	
	new_radio.Radio_G_ID = new_radio.WTPID * L_RADIO_NUM + new_radio.Radio_L_ID;
	
	if (0 == new_radio.Radio_L_ID)
	{
		if (!strcmp((char *)radio_mode,"n_only"))
		{
			new_radio.Radio_Type = Radio_11gn;
		}
		else if (!strcmp((char *)radio_mode,"n_disabled"))
		{
			new_radio.Radio_Type = Radio_11g;
		}
		else if (!strcmp((char *)radio_mode,"b_disabled"))
		{
			new_radio.Radio_Type = Radio_11g_11gn;
		}
		else
		{
			new_radio.Radio_Type = Radio_11bgn;
		}
	}
	else
	{
		new_radio.Radio_Type = Radio_11a_11an;
	}
	
	syslog(LOG_ERR, "%s: %d set radio%d-%d type %s", __func__, __LINE__, new_radio.WTPID, new_radio.Radio_L_ID, radio_mode);
	ret = handlib_set_radio_mode(&new_radio, connection);
	
	if (0 != ret)
	{
		syslog(LOG_ERR, "call handlib set radio%d-%d type %s failed, ret %d",  new_radio.WTPID, new_radio.Radio_L_ID, radio_mode, ret);
	}
	
	if (connection)
	{
		uninit_dbus_connection(&connection);
	}
	
	RETURN_LONG(ret); 
}


EXT_FUNCTION(ext_set_wtp_ip_network)
{
	DBusConnection *connection = NULL;
	int ret = 0;
	long wtpid = 0;
	unsigned char *ip_type = 0;
	unsigned char *ip = 0;
	unsigned char *mask = 0;
	unsigned char *gateway = 0;
	unsigned char *fstdns = 0;
	unsigned char *snddns = 0;
	char addr_ip[IPv6_STR_LEN] = {0};
	char addr_mask[IPv6_STR_LEN] = {0};
	char addr_gateway[IPv6_STR_LEN] = {0};
	char addr_fstdns[IPv6_STR_LEN] = {0};
	char addr_snddns[IPv6_STR_LEN] = {0};
	
	IP_WIRE_ARG ip_config;	
	zval *iter_array;
	MAKE_STD_ZVAL(iter_array);
	array_init(iter_array);
	memset(&ip_config, 0, sizeof(IP_WIRE_ARG));
	
	ext_para_get(argc, argv, EXT_TYPE_LONG, &wtpid, EXT_TYPE_STRING, &ip_type, EXT_TYPE_STRING, &ip,
				 EXT_TYPE_STRING, &mask, EXT_TYPE_STRING, &gateway, EXT_TYPE_STRING, &fstdns, EXT_TYPE_STRING, &snddns);
	
	syslog(LOG_ERR, "%s:%d set wtp%ld ip_type: %s ip: %s mask: %s gateway: %s fstdns: %s snddns: %s\n",
					__func__, __LINE__, wtpid, ip_type, ip, mask, gateway, fstdns, snddns);
	
	ret = dbus_connection_init(&connection);
	if (!connection || 0 != ret)
	{
		syslog(LOG_ERR, "dbus connection init failed when set wtp%ld ip_type: %s ip: %s mask: %s gateway: %s fstdns: %s snddns: %s ret %d\n",
						wtpid, ip_type, ip, mask, gateway, fstdns, snddns, ret);
		if (connection)
		{
			uninit_dbus_connection(&connection);
		}
		RETURN_LONG(-1);
	}
	
	ret = WID_Check_IP_Format((char*)ip);
	if (ret != WID_DBUS_SUCCESS)
	{
		syslog(LOG_ERR, "%s:%d set wtp%ld type %s ip %s\n", __func__, __LINE__, wtpid, ip_type, ip);
		
		uninit_dbus_connection(&connection);
		RETURN_LONG(-1);
	}
	else
	{
		ip_config.ip = ntohl(wid_ip2ulong((char*)ip));
	}
	
	ret = WID_Check_Mask_Format((char*)mask);
	if (ret != WID_DBUS_SUCCESS)
	{
		syslog(LOG_ERR, "%s:%d set wtp%ld type %s mask %s\n", __func__, __LINE__, wtpid, ip_type, mask);
		uninit_dbus_connection(&connection);
		RETURN_LONG(-1);
	}
	else
	{
		ip_config.mask = ntohl(wid_ip2ulong((char*)mask));
	}
	
	ret = WID_Check_IP_Format((char*)gateway);
	if (ret != WID_DBUS_SUCCESS)
	{
		syslog(LOG_ERR, "%s:%d set wtp%ld type %s gateway %s\n", __func__, __LINE__, wtpid, ip_type, gateway);
		uninit_dbus_connection(&connection);
		RETURN_LONG(-1);
	}
	else
	{
		ip_config.gateway = ntohl(wid_ip2ulong((char*)gateway));
	}
	
	ret = WID_Check_IP_Format((char*)fstdns);
	if (ret != WID_DBUS_SUCCESS)
	{
		syslog(LOG_ERR, "%s:%d set wtp%ld type %s fstdns %s\n", __func__, __LINE__, wtpid, ip_type, fstdns);
		uninit_dbus_connection(&connection);
		RETURN_LONG(-1);
	}
	else
	{
		ip_config.fstdns = ntohl(wid_ip2ulong((char*)fstdns));
	}
	
	ret = WID_Check_IP_Format((char*)snddns);
	if (ret != WID_DBUS_SUCCESS)
	{
		syslog(LOG_ERR, "%s:%d set wtp%ld type %s snddns %s\n", __func__, __LINE__, wtpid, ip_type, snddns);
		uninit_dbus_connection(&connection);
		RETURN_LONG(-1);
	}
	else
	{
		ip_config.snddns = ntohl(wid_ip2ulong((char*)snddns));
	}
	
	ip_config.wtpid = (unsigned int)wtpid;
	if (!strcmp((char *)ip_type, "static"))
	{
		ip_config.type = 1;
	}
	else
	{
		ip_config.type = 0;
	}
		
	ret = handlib_modify_ip_network_config(&ip_config, connection);
	
	if (0 != ret)
	{
		syslog(LOG_ERR, "call handlib set wtp%ld ip_type: %s ip: %s(%u) mask: %s(%u) gateway: %s(%u) fstdns: %s(%u) snddns: %s(%u) failed, ret %d\n",
						wtpid, ip_type, wid_parse_inet_ntoa(ip_config.ip, addr_ip), ip_config.ip,
						wid_parse_inet_ntoa(ip_config.mask, addr_mask), ip_config.mask,
						wid_parse_inet_ntoa(ip_config.gateway, addr_gateway), ip_config.gateway,
						wid_parse_inet_ntoa(ip_config.fstdns, addr_fstdns), ip_config.fstdns,
						wid_parse_inet_ntoa(ip_config.snddns, addr_snddns), ip_config.snddns, ret);
	}
	
	if (connection)
	{
		uninit_dbus_connection(&connection);
	}
	
	RETURN_LONG(ret); 
}


EXT_FUNCTION(ext_set_radio_wlan_overrides)
{
	DBusConnection *connection = NULL;
	int ret = 0;
	long wtpid = 0, radioid = 0, wlanid = 0, vlanid = 0;
	long enabled = 0, vlan_enabled = 0;
	unsigned char *name = 0;
	unsigned char *security = 0;
	unsigned char *x_passphrase = 0;
	
	RADIO_WIRE_ARG bss_config;	
	zval *iter_array;
	MAKE_STD_ZVAL(iter_array);
	array_init(iter_array);
	memset(&bss_config, 0, sizeof(RADIO_WIRE_ARG));
	
	ext_para_get(argc, argv, EXT_TYPE_LONG, &wtpid, EXT_TYPE_LONG, &radioid, EXT_TYPE_LONG, &wlanid,
				 EXT_TYPE_STRING, &name, EXT_TYPE_LONG, &enabled, EXT_TYPE_LONG, &vlan_enabled, EXT_TYPE_LONG, &vlanid,
				 EXT_TYPE_STRING, &security, EXT_TYPE_STRING, &x_passphrase);
	
	syslog(LOG_ERR, "%s:%d set radio%ld-%ld wlan%ld name: %s %s vlan%ld %s security: %s x_passphrase: %s\n",
					__func__, __LINE__, wtpid, radioid, wlanid, name, (enabled)? "enable":"disable", vlanid,
					(vlan_enabled)? "enable":"disable", security, x_passphrase);
	
	ret = dbus_connection_init(&connection);
	if (!connection || 0 != ret)
	{
		syslog(LOG_ERR, "dbus connection init failed when set radio%ld-%ld wlan%ld name: %s %s vlan%ld %s security: %s x_passphrase: %s ret= %d\n",
						wtpid,radioid,wlanid,name,(enabled)? "enable":"disable",vlanid,(vlan_enabled)? "enable":"disable",security,x_passphrase,ret);
		if(connection)
		{
			uninit_dbus_connection(&connection);
		}
		RETURN_LONG(-1);
	}
	
	bss_config.wtpid = (unsigned int)wtpid;
	bss_config.radioid = (unsigned char)radioid;
	bss_config.wlanid = (unsigned char)wlanid;
	bss_config.wlan_enabled = (unsigned char)enabled;
	bss_config.vlan_enabled = (unsigned char)vlan_enabled;
	bss_config.vlanid = (unsigned int)vlanid;	
	if (strcmp((char *)name, ""))
	{
		memcpy(bss_config.ssid, name, strlen((char *)name));
	}
	if (strcmp((char *)security, ""))
	{
		memcpy(bss_config.security, security, strlen((char *)security));
	}
	if (strcmp((char *)x_passphrase, ""))
	{
		memcpy(bss_config.user_key, x_passphrase, strlen((char *)x_passphrase));
	}
	
	syslog(LOG_ERR, "%s:%d set radio%u-%u wlan%u name: %s %s vlan%u %s security: %s x_passphrase: %s\n",
					__func__, __LINE__, bss_config.wtpid, bss_config.radioid, bss_config.wlanid, bss_config.ssid,
					(bss_config.wlan_enabled)? "enable":"disable", bss_config.vlanid,
					(bss_config.vlan_enabled)? "enable":"disable", bss_config.security, bss_config.user_key);
	ret = handlib_overrides_radio_network_config(&bss_config, connection);
	
	if(0 != ret)
	{
		syslog(LOG_ERR, "call handlib set radio%ld-%ld wlan%ld name: %s %s vlan%ld %s security: %s x_passphrase: %s ret= %d\n",
						 wtpid, radioid, wlanid, name, (enabled)? "enable":"disable", vlanid,
						(vlan_enabled)? "enable":"disable",security,x_passphrase,ret);
	}
	
	if(connection)
	{
		uninit_dbus_connection(&connection);
	}
	
	RETURN_LONG(ret); 
}

int config_one_wtp(struct wtp_conf *wtp_node)
{
	int i = 0;
	int ret = 0;
	DBusConnection *connection = NULL;
	NEW_WTP_ARG new_wtp;
	char *macStr = NULL;
	char *tmpPtr = NULL;
	char tmpMacStr[32] = {0};
	memset(&new_wtp, 0, sizeof(NEW_WTP_ARG));
	
	if(!wtp_node)
	{
		return -1;
	}
	
	memset(&new_wtp, 0, sizeof(NEW_WTP_ARG));
	new_wtp.WTPID = (int)wtp_node->wtp_id;
	new_wtp.WTPNAME = wtp_node->wtp_name;
	macStr = wtp_node->wtp_mac;
	new_wtp.WTPModel = wtp_node->wtp_model;

	if(!macStr || !new_wtp.WTPNAME || !new_wtp.WTPModel)
	{
		syslog(LOG_ERR, "%s line %d get bad parameter macStr %p wtpname %p wtpmodel %p ", 
			__func__, __LINE__, macStr, new_wtp.WTPNAME, new_wtp.WTPModel);
		return (-1);
	}
	strncpy(tmpMacStr, macStr, 31);
	tmpPtr = strtok(tmpMacStr, ":");
	while(tmpPtr && i < MAC_LEN)
	{
		new_wtp.WTPMAC[i++] = (unsigned char)strtoul(tmpPtr, NULL, 16);
		tmpPtr = strtok(NULL, ":");
	}
    ret = dbus_connection_init(&connection);
    if(!connection || 0 != ret)
    {
		syslog(LOG_ERR, "dbus connection init failed when load wtp[%02x:%02x:%02x:%02x:%02x:%02x] ret %d", 
						MAC2STR(new_wtp.WTPMAC), ret);
		if(connection)
		{			
			uninit_dbus_connection(&connection);
		}
		return (-1);
    }
	
	ret = handlib_load_conf_new_wtp(&new_wtp, connection);
	if(0 != ret || 0 == new_wtp.WTPID)
	{
		syslog(LOG_ERR, "call handlib load wtp[%02x:%02x:%02x:%02x:%02x:%02x] failed, ret %d wtpid %d", 
						MAC2STR(new_wtp.WTPMAC), ret, new_wtp.WTPID);
	}
	else
	{
		active_ap_auto_readmited(new_wtp.WTPMAC);
		//config_wtp_radios(wtp_node);
		// no need load wtp network config, it saved on ap
	}
	if(connection)
	{
		uninit_dbus_connection(&connection);
	}

    return ret;
}

