#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <syslog.h>
#include <dbus/dbus.h>
#include "php.h"
#include "ext_public.h"
#include "ext_wireless.h"
#include "ext_funcpublic.h"
#include "wid_ac.h"
#include "ext_dbus.h"
#include "afc_conf.h"

#define WLAN_DEBUG_ENABLE 1

ext_func_handle_t wireless_func_list[] = {
    {"set_user_default_wireless_network",3,(php_func_t)ext_set_user_default_wireless_network},
    {"set_guest_default_wireless_network",2,(php_func_t)ext_set_guest_default_wireless_network},
    {"delete_wireless_network",2,(php_func_t)ext_delete_wireless_network},
    {"add_wireless_network",14,(php_func_t)ext_add_wireless_network},
    {"modify_wireless_network",15,(php_func_t)ext_modify_wireless_network},
    {"show_wireless_network_list",1,(php_func_t)ext_show_wireless_network_list},
    {"get_one_wireless_network", 2, (php_func_t)ext_get_one_wireless_network},
};

void ext_wireless_handle(int argc, zval ***argv, zval *return_value)
{
    int count = sizeof(wireless_func_list)/sizeof(wireless_func_list[0]);
    ext_function_handle(argc, argv, return_value, count, wireless_func_list);
}

int add_modify_wlan_save_config(WLANWEBINFO * wlaninfo)
{/*create one new wireless network or edit one */
	afc_config_s * afcconf = NULL;
	struct wlan_conf * wlan_node = NULL;
	unsigned int wlanid = 0;
	int ret = -1;

	if(!wlaninfo || !(wlaninfo->WlanId >= START_WLANID && wlaninfo->WlanId <= MAX_WLANID))
	{
	    return -1;
	}
    afcconf = get_config_info();
    wlanid = (unsigned int)wlaninfo->WlanId;

    if(afcconf)
    {
        if(NULL == (afcconf->wlans[wlanid]))
        {
            afcconf->wlans[wlanid] = (struct wlan_conf *)malloc(sizeof(struct wlan_conf));
            if(afcconf->wlans[wlanid])
            {
                memset(afcconf->wlans[wlanid], 0, sizeof(struct wlan_conf));
            }
            else
            {
                syslog(LOG_ERR, FUNC_LINE_FORMAT" malloc wlan node failed!", FUNC_LINE_VALUE);
                return -1;
            }
        }
        else
        {
            memset(wlan_node->wlan_ssid, 0, SHORT_STRING_LEN-1);
        }
        wlan_node = afcconf->wlans[wlanid];
        wlan_node->wlan_id = wlanid;
        strncpy(wlan_node->wlan_ssid, wlaninfo->ssid, SHORT_STRING_LEN-1);
        if(wlaninfo->EncryptionType == AES)
        {
            wlan_node->encry_type = ENC_TYPE_AES;
        }
        else
        {
            wlan_node->encry_type = ENC_TYPE_TKIP;
        }
        if(wlaninfo->securType == SHARED)
        {
            wlan_node->sec_type = SEC_TYPE_WEP;
            wlan_node->wep_index = wlaninfo->wepIndex;
            memset(wlan_node->wep_key, 0, SHORT_STRING_LEN-1);
            strncpy(wlan_node->wep_key, wlaninfo->user_key, LONG_STRING_LEN-1);
        }
        else if(wlaninfo->securType == WPA_P)
        {
            wlan_node->sec_type = SEC_TYPE_WPA_P;
            wlan_node->wpa_mode = WPA_MODE_WPA1;
            memset(wlan_node->passphrase, 0, SHORT_STRING_LEN-1);
            strncpy(wlan_node->passphrase, wlaninfo->user_key, LONG_STRING_LEN-1);
        }
        else if(wlaninfo->securType == WPA2_P)
        {
            wlan_node->sec_type = SEC_TYPE_WPA_P;
            wlan_node->wpa_mode = WPA_MODE_WPA2;
            memset(wlan_node->passphrase, 0, SHORT_STRING_LEN-1);
            strncpy(wlan_node->passphrase, wlaninfo->user_key, LONG_STRING_LEN-1);
        }
        else if(wlaninfo->securType == WPA_E)
        {
            wlan_node->sec_type = SEC_TYPE_WPA_E;
            wlan_node->wpa_mode = WPA_MODE_WPA1;
            memset(wlan_node->radius_secret, 0, SHORT_STRING_LEN-1);
            strncpy(wlan_node->radius_secret, wlaninfo->user_key, LONG_STRING_LEN-1);
            if(wlaninfo->Authip != 0xFFFFFFFF && wlaninfo->AuthPort > 0)
            {            
                wlan_node->radius_ip = wlaninfo->Authip;
                wlan_node->radius_port = wlaninfo->AuthPort;
            }
        }
        else if(wlaninfo->securType == WPA2_E)
        {
            wlan_node->sec_type = SEC_TYPE_WPA_E;
            wlan_node->wpa_mode = WPA_MODE_WPA2;
            memset(wlan_node->radius_secret, 0, SHORT_STRING_LEN-1);
            strncpy(wlan_node->radius_secret, wlaninfo->user_key, LONG_STRING_LEN-1);
            if(wlaninfo->Authip != 0xFFFFFFFF && wlaninfo->AuthPort > 0)
            {            
                wlan_node->radius_ip = wlaninfo->Authip;
                wlan_node->radius_port = wlaninfo->AuthPort;
            }
        }
        else
        {
            wlan_node->sec_type = SEC_TYPE_OPEN;
        }

        wlan_node->user_group_id = (unsigned int)wlaninfo->usrGid;
        wlan_node->hidden_ssid = (BOOL)wlaninfo->sHideflag;
        wlan_node->wlan_service = (BOOL)wlaninfo->isEnable;
        wlan_node->guest_enabled = (BOOL)wlaninfo->applyGflag;
        wlan_node->vlan_enabled = (BOOL)wlaninfo->vlanEnabled;
        wlan_node->vlan = (unsigned short)wlaninfo->vlanId;
        
        ret = save_config_info(afcconf);
    }
    else
    {
        syslog(LOG_ERR, FUNC_LINE_FORMAT" failed to get config info !", FUNC_LINE_VALUE);
        return -1;
    }
    return ret;
}

int delete_wlan_save_config(unsigned int wlan_id)
{/*delete one wireless network */
	afc_config_s * afcconf = NULL;
	int ret = -1;
	
    if(!(wlan_id >= START_WLANID && wlan_id <= MAX_WLANID))
	{
	    return -1;
	}
	
    afcconf = get_config_info();

    if(afcconf)
    {
        ret = 0;
        if(afcconf->wlans[wlan_id])
        {
            destroy_wlan_node(afcconf->wlans[wlan_id]);
            afcconf->wlans[wlan_id] = NULL;
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

EXT_FUNCTION(ext_set_user_default_wireless_network)/*返回-1表示失败*/
{
	char *ssid = NULL; 	
	char * key = NULL;	
    int ret = 0;
	DBusConnection * hand_dbus_connection = NULL;
	ext_para_get(argc, argv, EXT_TYPE_STRING, &ssid, EXT_TYPE_STRING, &key);
	if (!hand_dbus_connection)
	{
		dbus_connection_init(&hand_dbus_connection);
	}	
	if (!hand_dbus_connection || !ssid || !key)
	{
		if (hand_dbus_connection)
		{
			uninit_dbus_connection(&hand_dbus_connection);
		}
		RETURN_LONG(-1);
	}
	ret = hand_add_user_default_network(ssid, key, hand_dbus_connection);
	if(ret)
	{
		//
	}	
	uninit_dbus_connection(&hand_dbus_connection);
	RETURN_LONG(ret);
}

EXT_FUNCTION(ext_set_guest_default_wireless_network)/*返回-1表示失败*/
{
	char *ssid = NULL; 	
    	int ret = 0;
	DBusConnection * hand_dbus_connection = NULL;
	ext_para_get(argc, argv, EXT_TYPE_STRING, &ssid);
	if (!hand_dbus_connection)
	{
		dbus_connection_init(&hand_dbus_connection);
	}	
	if (!hand_dbus_connection)
	{
		RETURN_LONG(-1);
	}
	if (!ssid)
	{
		uninit_dbus_connection(&hand_dbus_connection);
		RETURN_LONG(-1);
	}
	ret = hand_add_guest_default_network(ssid, hand_dbus_connection);
	if (ret)
	{
		//
	}	
	uninit_dbus_connection(&hand_dbus_connection);
	RETURN_LONG(ret);
}

EXT_FUNCTION(ext_delete_wireless_network)/*返回-1表示失败*/
{
	long wlanid = 0; 	
  	int ret = 0;
	DBusConnection * hand_dbus_connection = NULL;
	ext_para_get(argc, argv, EXT_TYPE_LONG, &wlanid);
	if (!hand_dbus_connection)
	{
		dbus_connection_init(&hand_dbus_connection);
	}	
	if (!hand_dbus_connection)
	{
		RETURN_LONG(-1);
	}
	if (wlanid <= 0)
	{
		syslog(LOG_ERR, "argument illegal wlanid %ld ", wlanid);
		uninit_dbus_connection(&hand_dbus_connection);
		RETURN_LONG(-1);
	}
	
	ret = hand_del_softAc_network((int)wlanid, hand_dbus_connection);
	if (ret)
	{
		syslog(LOG_ERR, "after call function hand_del_softAc_network ret %#x ", ret);
	}
	else
	{
	    delete_wlan_save_config((unsigned int)wlanid);
	}
	uninit_dbus_connection(&hand_dbus_connection);
	RETURN_LONG(ret);
}

EXT_FUNCTION(ext_add_wireless_network)/*返回-1表示失败*/
{
	int wlanid = 0;
	char *ssid = NULL;
	char *user_key = NULL;
	char *securTypeStr = NULL;
	char *encryptionTypeStr = NULL;
	char *authipStr = NULL;
	int securType = 0;
	long secur_arg = 0;
	int wep_index = 0;
	long sHideflag = 0;
	long isEnable = 0;
	long applyGuest = 0;
	long vlanId = 0;
	long usrGroupid = 0;
	long vlanEnabled = 0;
	int encryptionType = 0;
	unsigned int authip = 0;
	long authport = 0;
	int ret = 0;
	DBusConnection * hand_dbus_connection = NULL;
	WLANWEBINFO wlaninfo;
	zval *iter_array;
	MAKE_STD_ZVAL(iter_array);
	array_init(iter_array);
	memset(&wlaninfo, 0, sizeof(wlaninfo));
    
	ext_para_get(argc, argv, EXT_TYPE_STRING, &ssid, EXT_TYPE_STRING, &user_key, EXT_TYPE_STRING, &securTypeStr,
							EXT_TYPE_LONG, &secur_arg, EXT_TYPE_LONG, &isEnable, EXT_TYPE_LONG, &applyGuest,
							EXT_TYPE_LONG, &sHideflag, EXT_TYPE_LONG, &vlanEnabled, EXT_TYPE_LONG, &vlanId, 
							EXT_TYPE_STRING, &encryptionTypeStr, EXT_TYPE_STRING, &authipStr,
							EXT_TYPE_LONG, &authport, EXT_TYPE_LONG, &usrGroupid);

	if (!hand_dbus_connection)
	{
		ret = dbus_connection_init(&hand_dbus_connection);
	}

	if (!hand_dbus_connection )
	{
		syslog(LOG_ERR,"dbus connection init failed, hand_dbus_connection %p ret %d ", hand_dbus_connection, ret);
		RETURN_LONG(-1);
	}
	
	if (ssid == NULL || securTypeStr == NULL || !strcmp(securTypeStr, "")
		|| (strcmp(securTypeStr, "open") && (user_key == NULL || !strcmp(user_key, ""))))
	{
		syslog(LOG_ERR, "input arguments illegal ssid %s securTypeStr %s user_key %s", ssid ? ssid:"<null>", securTypeStr ? :"<null>", user_key?:"<null>");
		uninit_dbus_connection(&hand_dbus_connection);
		RETURN_LONG(-1);
	}
	
	if (strlen(ssid) > 64)
	{		
		syslog(LOG_ERR, "<error> essid is too long, out of the limit of 64\n");
		uninit_dbus_connection(&hand_dbus_connection);
		RETURN_LONG(-1);
	}
	
	if (!strcmp(encryptionTypeStr, "ccmp"))
	{
		wlaninfo.EncryptionType = AES;
	}
	else
	{
		wlaninfo.EncryptionType = TKIP;
	}
	
	if (!strcmp(securTypeStr, "wep"))
	{
		wep_index = secur_arg;
		wlaninfo.securType = SHARED;
		wlaninfo.EncryptionType = WEP;
	}
	else if (!strcmp(securTypeStr, "wpapsk"))
	{
		if (secur_arg == WPA1)
		{
			securType = WPA_P;
			wlaninfo.securType = WPA_P;
		}
		else
		{// 0 - auto , 2 - wpa2
			securType = WPA2_P;
			wlaninfo.securType = WPA2_P;
		}
	}
	else if (!strcmp(securTypeStr, "wpaeap"))
	{		
		if (secur_arg == WPA1)
		{
			wlaninfo.securType = WPA_E;
		}
		else
		{// 0 - auto , 2 - wpa2
			wlaninfo.securType = WPA2_E;
		}
	}
	else
	{//open
		wlaninfo.securType = OPEN;
		wlaninfo.EncryptionType = NONE;
	}
	
	if (authipStr && strcmp(authipStr, ""))
	{
		wlaninfo.Authip   = ntohl(inet_addr(authipStr));// 10.0.0.1 => 0x0a000001 
		
		wlaninfo.AuthPort = (unsigned short)authport;
	}
	else
	{
		wlaninfo.Authip = 0xFFFFFFFF;
	}
	usrGroupid = 1;// for test
	wlaninfo.usrGid = (int)usrGroupid;
	wlaninfo.sHideflag = (int)sHideflag;
	wlaninfo.isEnable = (int)isEnable;
	wlaninfo.applyGflag = (int)applyGuest;
	wlaninfo.vlanEnabled = (int)vlanEnabled;
	wlaninfo.vlanId = (int)vlanId;
	wlaninfo.wepIndex = wep_index;
	
	strncpy(wlaninfo.user_key, user_key, USER_KEY_LEN-1);
	strncpy(wlaninfo.ssid, ssid, ESSID_DEFAULT_LEN-1);
	unsigned char ssidbuffer[DEFAULT_LEN] = {0};
	hand_hex_dump_essid((unsigned char *)ssid, strlen(ssid), ssidbuffer);
#if WLAN_DEBUG_ENABLE
	syslog(LOG_DEBUG, "before call function hand_add_softAc_network ssid %s user_key %s securType %d wep_index %d sHideflag %ld "
		"isEnable %ld applyGuest %ld vlanEnabled %ld vlanId %ld userGroupid %ld encryptionType %d auth ip %#x authport %ld ", 
		ssidbuffer, user_key, securType, wep_index, sHideflag, isEnable, applyGuest, vlanEnabled, vlanId, usrGroupid, encryptionType, authip, authport);
#endif
	ret = hand_add_softAc_network(&wlaninfo, hand_dbus_connection);
	
#if WLAN_DEBUG_ENABLE
	syslog(LOG_DEBUG, "after call function hand_add_softAc_network ret %d wlanid %d\n", ret, wlanid);
#endif
	if (ret)
	{
		syslog(LOG_ERR, "after call function hand_add_softAc_network ret %#x\n", ret);
	}
	else
	{
	    add_modify_wlan_save_config(&wlaninfo);
	    if (ret < 0)
	    {
		    syslog(LOG_WARNING, "save wlan %d info when add failed! ret %d\n", wlaninfo.WlanId, ret);
		}
	}
	
	uninit_dbus_connection(&hand_dbus_connection);
	
	if (object_init(return_value) != SUCCESS)
    {
        RETURN_LONG(PHP_OBJ_INIT_FAIL);
    }
	add_assoc_long(iter_array, "ret", ret);
	add_assoc_long(iter_array, "wlanid", wlanid);
	add_property_zval(return_value, "value", iter_array);
}

EXT_FUNCTION(ext_modify_wireless_network)/*返回-1表示失败*/
{
	long wlanid = 0;	
	char *ssid = NULL;
	char *user_key = NULL;
	char *securTypeStr = NULL;
	char *encryptionTypeStr = NULL;
	char *authipStr = NULL;
	int securType = 0;
	long secur_arg = 0;
	int wep_index = 0;
	long sHideflag = 0;
	long isEnable = 0;
	long applyGuest = 0;
	long vlanId = 0;
	long usrGroupid = 0; 	
	int encryptionType = 0;
	unsigned int authip = 0;
	long authport = 0;
	long vlanEnabled = 0;
	int ret = 0;
	DBusConnection * hand_dbus_connection = NULL;
	
	WLANWEBINFO wlaninfo;
	
	memset(&wlaninfo, 0, sizeof(wlaninfo));
	
	ext_para_get(argc, argv, EXT_TYPE_LONG, &wlanid, EXT_TYPE_STRING, &ssid, EXT_TYPE_STRING, &user_key, EXT_TYPE_STRING, &securTypeStr, EXT_TYPE_LONG, &secur_arg, 
		EXT_TYPE_LONG, &isEnable, EXT_TYPE_LONG, &applyGuest, EXT_TYPE_LONG, &sHideflag, EXT_TYPE_LONG, &vlanEnabled, EXT_TYPE_LONG, &vlanId, 
		EXT_TYPE_STRING, &encryptionTypeStr, EXT_TYPE_STRING, &authipStr, EXT_TYPE_LONG, &authport, EXT_TYPE_LONG, &usrGroupid);
	if (!hand_dbus_connection)
	{
		dbus_connection_init(&hand_dbus_connection);
	}	
	if (!hand_dbus_connection)
	{
		RETURN_LONG(-1);
	}	
	if (wlanid <= 0 || ssid == NULL || securTypeStr == NULL || !strcmp(securTypeStr, "")
		|| (strcmp(securTypeStr, "open") && (user_key == NULL || !strcmp(user_key, ""))))
	{
		syslog(LOG_ERR,"input arguments illegal wlanid %ld ssid %s securTypeStr %s user_key %s", wlanid, ssid ? ssid:"<null>", securTypeStr ? :"<null>", user_key?:"<null>");
		uninit_dbus_connection(&hand_dbus_connection);
		RETURN_LONG(-1);
	}
	strncpy(wlaninfo.ssid, ssid, ESSID_DEFAULT_LEN-1);
	strncpy(wlaninfo.user_key, user_key, USER_KEY_LEN-1);
	if (!strcmp(encryptionTypeStr, "ccmp"))
	{
		wlaninfo.EncryptionType = AES;
	}
	else
	{
		wlaninfo.EncryptionType = TKIP;
	}
	if (!strcmp(securTypeStr, "wep"))
	{
		wep_index = secur_arg;
		wlaninfo.securType = SHARED;
		wlaninfo.EncryptionType = WEP;
	}
	else if (!strcmp(securTypeStr, "wpapsk"))
	{
		if (secur_arg == WPA1)
		{
			securType = WPA_P;
			wlaninfo.securType = WPA_P;
		}
		else
		{// 0 - auto , 2 - wpa2
			securType = WPA2_P;
			wlaninfo.securType = WPA2_P;
		}
	}
	else if (!strcmp(securTypeStr, "wpaeap"))
	{		
		if (secur_arg == WPA1)
		{
			wlaninfo.securType = WPA_E;
		}
		else
		{// 0 - auto , 2 - wpa2
			wlaninfo.securType = WPA2_E;
		}
	}
	else
	{//open
		wlaninfo.securType = OPEN;
		wlaninfo.EncryptionType = NONE;
	}
	if (authipStr && strcmp(authipStr, ""))
	{
		wlaninfo.Authip   = ntohl(inet_addr(authipStr));// 10.0.0.1 => 0x0a000001 
		
		wlaninfo.AuthPort = (unsigned short)authport;
	}
	else
	{
		wlaninfo.Authip = 0xFFFFFFFF;
	}
	
	wlaninfo.usrGid = (int)usrGroupid;
	wlaninfo.sHideflag = (int)sHideflag;
	wlaninfo.isEnable = (int)isEnable;
	wlaninfo.applyGflag = (int)applyGuest;
	wlaninfo.vlanEnabled = (int)vlanEnabled;
	wlaninfo.vlanId = (int)vlanId;
	wlaninfo.wepIndex = wep_index;
	wlaninfo.WlanId = (int)wlanid;
	
#if WLAN_DEBUG_ENABLE
	syslog(LOG_DEBUG, "before call function  hand_modify_softAc_network wlanid %ld ssid %s user_key %s securType %d wep_index %d sHideflag "
	    "%ld isEnable %ld applyGuest %ld vlanEnabled %ld vlanId %ld userGroupid %ld encryptionType %d auth ip %#x authport %ld ",
	    wlanid , ssid, user_key, securType, wep_index, sHideflag, isEnable, applyGuest, vlanEnabled, vlanId, usrGroupid, encryptionType, authip, authport);
#endif	
	ret = hand_modify_softAc_network_config(&wlaninfo, hand_dbus_connection);
	if (ret)
	{
		syslog(LOG_WARNING, "after  call function hand_modify_softAc_network ret %#x ", ret);//
	}
	else
	{
	    ret = add_modify_wlan_save_config(&wlaninfo);
	    if (ret < 0)
	    {
		    syslog(LOG_WARNING, "save wlan %ld info when modify failed! ret %d", wlanid, ret);
		}
	}
	
	uninit_dbus_connection(&hand_dbus_connection);
	RETURN_LONG(ret);
}

EXT_FUNCTION(ext_show_wireless_network_list)
{
	int i = 0;
	int ret = 0;
	int wlanid = 0;
	WLANWEBINFO wlaninfo;
	int wlan_num = 0;
	char *x_passphrase = "";
	char *x_wep = "";
	char *x_radius_secret_1 = "";
	char *wpa_mode = "";
	char *wpa_enc = "";
	char *security = "";
	char *authip = "";
	struct in_addr auth_addr;
	DBusConnection *hand_dbus_connection = NULL;
	zval *iter, *iter_array, *iter_wlan;
    MAKE_STD_ZVAL(iter);
    array_init(iter);
	
	ret = dbus_connection_init(&hand_dbus_connection);
		
	if (!hand_dbus_connection)
	{
		RETURN_LONG(-1);
	}
	
	if (ret != 0)
	{
		syslog(LOG_ERR, "dbus connection init failed when get wlan list ret %d\n", ret);
		uninit_dbus_connection(&hand_dbus_connection);
		RETURN_LONG(-1);
	}
	
	for (wlanid = 1; wlanid <= MAX_WLANID; wlanid++)
	{
#if WLAN_DEBUG_ENABLE
		//syslog(LOG_DEBUG, "before call function  show_network_wlan_config wlanid %d for show list ",wlanid);
#endif
		memset(&wlaninfo, 0, sizeof(WLANWEBINFO));
		wlaninfo.WlanId = wlanid;
		ret = show_network_wlan_config(&wlaninfo, hand_dbus_connection);

#if WLAN_DEBUG_ENABLE		
		//syslog(LOG_DEBUG, "after call function show_network_wlan_config wlanid %d isExist %d ret %#x  for show list ", wlanid, wlaninfo.isExist, ret);
#endif
		if (ret)
		{
			syslog(LOG_ERR, "after call function show_network_wlan_config wlanid %d ret %#x for show list\n", wlanid, ret);
		}
		else if (wlaninfo.isExist)
		{
			MAKE_STD_ZVAL(iter_array);
			array_init(iter_array);
						
			if (wlaninfo.EncryptionType == AES)
			{
				wpa_enc = "ccmp";
			}
			else
			{
				wpa_enc = "tkip";
			}
			//security = "open";
			if (wlaninfo.securType == SHARED)
			{
				x_wep = wlaninfo.user_key;
				x_passphrase = "";
				x_radius_secret_1 = "";
				wpa_mode = "";
				wpa_enc = "";
				security = "wep";
			}
			else if (wlaninfo.securType == WPA_P)
			{
				x_passphrase = wlaninfo.user_key;
				x_wep = "";
				x_radius_secret_1 = "";
				wpa_mode = "wpa1";
				security = "wpapsk";
			}
			else if (wlaninfo.securType == WPA_E)
			{
				x_radius_secret_1 = wlaninfo.user_key;
				x_passphrase = "";
				x_wep = "";
				wpa_mode = "wpa1";	
				security = "wpaeap";			
			}
			else if (wlaninfo.securType == WPA2_P)
			{
				x_passphrase = wlaninfo.user_key;
				x_wep = "";
				x_radius_secret_1 = "";
				wpa_mode = "wpa2";
				security = "wpapsk";
			}
			else if (wlaninfo.securType == WPA2_E)
			{
				x_radius_secret_1 = wlaninfo.user_key;
				x_passphrase = "";
				x_wep = "";
				wpa_mode = "wpa2";	
				security = "wpaeap";
			}
			else
			{//open
				x_wep = "";
				x_passphrase = "";
				x_radius_secret_1 = "";
				wpa_mode = "";
				wpa_enc = "";
				security = "open";
			}
			
			//strcpy(wlaninfo.ssid, "中文SSID");
			add_assoc_long(iter_array, "_id", (long)wlaninfo.WlanId);
			add_assoc_string(iter_array, "name", wlaninfo.ssid, 1);
			add_assoc_string(iter_array, "security", security, 1);
			add_assoc_string(iter_array, "x_wep", x_wep, 1);
			add_assoc_string(iter_array, "x_passphrase", x_passphrase, 1);
			add_assoc_string(iter_array, "x_radius_secret_1", x_radius_secret_1, 1);
			add_assoc_string(iter_array, "wpa_mode", wpa_mode, 1);
			add_assoc_string(iter_array, "wpa_enc", wpa_enc, 1);
			add_assoc_long(iter_array, "wep_idx", (long)wlaninfo.wepIndex);
			add_assoc_long(iter_array, "hide_ssid", (long)wlaninfo.sHideflag);
			add_assoc_long(iter_array, "enabled", (long)wlaninfo.isEnable);
			add_assoc_long(iter_array, "is_guest", (long)wlaninfo.applyGflag);
			add_assoc_long(iter_array, "vlan_enabled", (long)(wlaninfo.vlanId != 0));
			add_assoc_long(iter_array, "vlan", (long)wlaninfo.vlanId);
			add_assoc_long(iter_array, "usrgroup_id", (long)wlaninfo.usrGid);
			add_assoc_long(iter_array, "uplink_bandwidth", (long)wlaninfo.uplink_bandwidth);
			add_assoc_long(iter_array, "downlink_bandwidth", (long)wlaninfo.downlink_bandwidth);
			add_assoc_long(iter_array, "tx_packets", (long)wlaninfo.tx_packets);
			add_assoc_long(iter_array, "rx_packets", (long)wlaninfo.rx_packets);
			add_assoc_double(iter_array, "tx_bytes", (long long)wlaninfo.tx_bytes);
			add_assoc_double(iter_array, "rx_bytes", (long long)wlaninfo.rx_bytes);
			add_assoc_long(iter_array, "wlan_wtp_num", (long)wlaninfo.wlan_wtp_wifi.num);
			
			MAKE_STD_ZVAL(iter_wlan);
			array_init(iter_wlan);
			for (i = 0; i < wlaninfo.wlan_wtp_wifi.num; i++)
			{
				zval *iter_array_r;
				MAKE_STD_ZVAL(iter_array_r);
				array_init(iter_array_r);
				add_assoc_long(iter_array_r, "wlanwtp_id", (long)wlaninfo.wlan_wtp_wifi.wtp_wifi[i].wtpid);
				add_assoc_string(iter_array_r, "wtp_name", (char *)(wlaninfo.wlan_wtp_wifi.wtp_wifi[i].wtpname ? (char *)wlaninfo.wlan_wtp_wifi.wtp_wifi[i].wtpname : ""), 1);
				add_assoc_long(iter_array_r, "wtp_sta", (long)wlaninfo.wlan_wtp_wifi.wtp_wifi[i].sta_num);
				add_assoc_long(iter_array_r, "ap_upbw", (long)wlaninfo.wlan_wtp_wifi.wtp_wifi[i].uplink_bandwidth);
				add_assoc_long(iter_array_r, "ap_downbw", (long)wlaninfo.wlan_wtp_wifi.wtp_wifi[i].downlink_bandwidth);
				add_assoc_long(iter_array_r, "ap_txpkt", (long)wlaninfo.wlan_wtp_wifi.wtp_wifi[i].tx_packets);
				add_assoc_long(iter_array_r, "ap_rxpkt", (long)wlaninfo.wlan_wtp_wifi.wtp_wifi[i].rx_packets);
				add_assoc_double(iter_array_r, "ap_tx_bytes", (long long)wlaninfo.wlan_wtp_wifi.wtp_wifi[i].tx_bytes);
				add_assoc_double(iter_array_r, "ap_rx_bytes", (long long)wlaninfo.wlan_wtp_wifi.wtp_wifi[i].rx_bytes);
				add_next_index_zval(iter_wlan, iter_array_r);
			}
			
			if (wlaninfo.Authip != 0)
			{
				auth_addr.s_addr = htonl(wlaninfo.Authip);
				authip = inet_ntoa(auth_addr);
			}
			
			add_assoc_string(iter_array, "radius_ip_1", authip, 1);
			add_assoc_long(iter_array, "radius_port_1", (long)wlaninfo.AuthPort);
			
			add_assoc_zval(iter_array, "wifi_ap_table", iter_wlan);
			add_next_index_zval(iter, iter_array);
			wlan_num++;
			
#if WLAN_DEBUG_ENABLE
			syslog(LOG_DEBUG, "after call function show_network_wlan_config "
					"wlan_num %d wlanid %d ssid \"%s\" securType %d x_wep \"%s\" x_passphrase \"%s\" x_radius_secret_1 \"%s\" "
					"wpa_mode \"%s\" wpa_enc \"%s\" wep_idx %d sHideflag %d isEnable %d applyGuest %d vlanId %d "
					"userGroupid %d encryptionType %d auth ip %#x authport %d  for show list ", 
					wlan_num, wlanid, wlaninfo.ssid, wlaninfo.securType, x_wep, x_passphrase, x_radius_secret_1, 
					wpa_mode, wpa_enc,wlaninfo.wepIndex, wlaninfo.sHideflag, wlaninfo.isEnable, wlaninfo.applyGflag, wlaninfo.vlanId, 
					wlaninfo.usrGid, wlaninfo.EncryptionType, wlaninfo.Authip, wlaninfo.AuthPort);//
#endif
		
		}
	}
#if WLAN_DEBUG_ENABLE
	syslog(LOG_DEBUG, "after call function show_network_wlan_config wlan_num %d for show list ", wlan_num);
#endif
	uninit_dbus_connection(&hand_dbus_connection);	
	
	if (object_init(return_value) != SUCCESS)
	{
		syslog(LOG_ERR, "init return_value failed !");
		RETURN_LONG(PHP_OBJ_INIT_FAIL);
	}
	
	zval *iter_len;
	MAKE_STD_ZVAL(iter_len);
	array_init(iter_len);
	add_assoc_long(iter_len, "wlan_num", (long)wlan_num);
	
	add_property_zval(return_value, "wlans", iter_len);
	add_property_zval(return_value, "value", iter);
	//RETURN_LONG(ret);
}

EXT_FUNCTION(ext_get_one_wireless_network)
{
	int i = 0;
	int ret = 0;
	long wlanid = 0;
	WLANWEBINFO wlaninfo;
	int wlan_num = 0;
	char * x_passphrase = "";
	char * x_wep = "";
	char * x_radius_secret_1 = "";
	char * wpa_mode = "";
	char * wpa_enc = "";
	char * security = "";
	char * authip = "";
	struct in_addr auth_addr;
	DBusConnection * hand_dbus_connection = NULL;
	//zval *iter;
	zval *iter_array, *iter_wlan;
	MAKE_STD_ZVAL(iter_array);
	array_init(iter_array);
	
	memset(&wlaninfo, 0, sizeof(WLANWEBINFO));
	
	ext_para_get(argc, argv, EXT_TYPE_LONG, &wlanid);
	
	if (!hand_dbus_connection)
	{
		dbus_connection_init(&hand_dbus_connection);
	}	
	if (!hand_dbus_connection)
	{
		RETURN_LONG(-1);
	}
#if WLAN_DEBUG_ENABLE
	syslog(LOG_DEBUG, "before call function  show_network_wlan_config wlanid %ld for show one wlan ", wlanid);
#endif
	wlaninfo.WlanId = (int)wlanid;
	ret = show_network_wlan_config(&wlaninfo, hand_dbus_connection);
	
#if WLAN_DEBUG_ENABLE
	syslog(LOG_DEBUG, "after call function show_network_wlan_config wlanid %ld isExist %d ret %#x  for show one wlan ", wlanid, wlaninfo.isExist, ret);
#endif
	if (ret)
	{
		syslog(LOG_ERR, "after call function show_network_wlan_config wlanid %ld ret %#x  for show one wlan ", wlanid, ret);//
	}
	else if (wlaninfo.isExist)
	{			
		MAKE_STD_ZVAL(iter_array);
		array_init(iter_array);
					
		if(wlaninfo.EncryptionType == AES)
		{
			wpa_enc = "ccmp";
		}
		else
		{
			wpa_enc = "tkip";
		}
		//security = "open";
		if (wlaninfo.securType == SHARED)
		{
			x_wep = wlaninfo.user_key;
			x_passphrase = "";
			x_radius_secret_1 = "";
			wpa_mode = "";
			wpa_enc = "";
			security = "wep";
		}
		else if (wlaninfo.securType == WPA_P)
		{
			x_passphrase = wlaninfo.user_key;
			x_wep = "";
			x_radius_secret_1 = "";
			wpa_mode = "wpa1";
			security = "wpapsk";
		}
		else if (wlaninfo.securType == WPA_E)
		{
			x_radius_secret_1 = wlaninfo.user_key;
			x_passphrase = "";
			x_wep = "";
			wpa_mode = "wpa1";	
			security = "wpaeap";			
		}
		else if (wlaninfo.securType == WPA2_P)
		{
			x_passphrase = wlaninfo.user_key;
			x_wep = "";
			x_radius_secret_1 = "";
			wpa_mode = "wpa2";
			security = "wpapsk";
		}
		else if (wlaninfo.securType == WPA2_E)
		{
			x_radius_secret_1 = wlaninfo.user_key;
			x_passphrase = "";
			x_wep = "";
			wpa_mode = "wpa2";	
			security = "wpaeap";
		}
		else
		{//open
			x_wep = "";
			x_passphrase = "";
			x_radius_secret_1 = "";
			wpa_mode = "";
			wpa_enc = "";
			security = "open";
		}
		
		//strcpy(wlaninfo.ssid, "中文SSID");
		add_assoc_long(iter_array, "_id", (long)wlaninfo.WlanId);
		add_assoc_string(iter_array, "name", wlaninfo.ssid, 1);
		add_assoc_string(iter_array, "security", security, 1);
		add_assoc_string(iter_array, "x_wep", x_wep, 1);
		add_assoc_string(iter_array, "x_passphrase", x_passphrase, 1);
		add_assoc_string(iter_array, "x_radius_secret_1", x_radius_secret_1, 1);
		add_assoc_string(iter_array, "wpa_mode", wpa_mode, 1);
		add_assoc_string(iter_array, "wpa_enc", wpa_enc, 1);
		add_assoc_long(iter_array, "wep_idx", (long)wlaninfo.wepIndex);
		add_assoc_long(iter_array, "hide_ssid", (long)wlaninfo.sHideflag);
		add_assoc_long(iter_array, "enabled", (long)wlaninfo.isEnable);
		add_assoc_long(iter_array, "is_guest", (long)wlaninfo.applyGflag);
		add_assoc_long(iter_array, "vlan_enabled", (long)(wlaninfo.vlanId != 0));
		add_assoc_long(iter_array, "vlan", (long)wlaninfo.vlanId);
		add_assoc_long(iter_array, "usrgroup_id", (long)wlaninfo.usrGid);
		add_assoc_long(iter_array, "uplink_bandwidth", (long)wlaninfo.uplink_bandwidth);
		add_assoc_long(iter_array, "downlink_bandwidth", (long)wlaninfo.downlink_bandwidth);
		add_assoc_long(iter_array, "tx_packets", (long)wlaninfo.tx_packets);
		add_assoc_long(iter_array, "rx_packets", (long)wlaninfo.rx_packets);
		add_assoc_double(iter_array, "tx_bytes", (long long)wlaninfo.tx_bytes);
		add_assoc_double(iter_array, "rx_bytes", (long long)wlaninfo.rx_bytes);
		add_assoc_long(iter_array, "wlan_wtp_num", (long)wlaninfo.wlan_wtp_wifi.num);
		MAKE_STD_ZVAL(iter_wlan);
		array_init(iter_wlan);
		for (i = 0; i < wlaninfo.wlan_wtp_wifi.num; i++)
		{
			zval *iter_array_r;
			MAKE_STD_ZVAL(iter_array_r);
			array_init(iter_array_r);
			add_assoc_long(iter_array_r, "wlanwtp_id", (long)wlaninfo.wlan_wtp_wifi.wtp_wifi[i].wtpid);
			add_assoc_long(iter_array_r, "wtp_sta", (long)wlaninfo.wlan_wtp_wifi.wtp_wifi[i].sta_num);
			add_assoc_long(iter_array_r, "ap_upbw", (long)wlaninfo.wlan_wtp_wifi.wtp_wifi[i].uplink_bandwidth);
			add_assoc_long(iter_array_r, "ap_downbw", (long)wlaninfo.wlan_wtp_wifi.wtp_wifi[i].downlink_bandwidth);
			add_assoc_long(iter_array_r, "ap_txpkt", (long)wlaninfo.wlan_wtp_wifi.wtp_wifi[i].tx_packets);
			add_assoc_long(iter_array_r, "ap_rxpkt", (long)wlaninfo.wlan_wtp_wifi.wtp_wifi[i].rx_packets);
			add_assoc_double(iter_array_r, "ap_tx_bytes", (long long)wlaninfo.wlan_wtp_wifi.wtp_wifi[i].tx_bytes);
			add_assoc_double(iter_array_r, "ap_rx_bytes", (long long)wlaninfo.wlan_wtp_wifi.wtp_wifi[i].rx_bytes);
			add_next_index_zval(iter_wlan, iter_array_r);
		}
		
		if (wlaninfo.Authip != 0)
		{
			auth_addr.s_addr = htonl(wlaninfo.Authip);
			authip = inet_ntoa(auth_addr);
		}
		
		add_assoc_string(iter_array, "radius_ip_1", authip, 1);
		add_assoc_long(iter_array, "radius_port_1", (long)wlaninfo.AuthPort);
		
		add_assoc_zval(iter_array, "wifi_ap_table", iter_wlan);
		//add_next_index_zval(iter, iter_array);
		wlan_num++;
#if WLAN_DEBUG_ENABLE
		syslog(LOG_DEBUG, "after call function show_network_wlan_config "
				"wlan_num %d wlanid %ld ssid \"%s\" securType %d x_wep \"%s\" x_passphrase \"%s\" x_radius_secret_1 \"%s\" "
				"wpa_mode \"%s\" wpa_enc \"%s\" wep_idx %d sHideflag %d isEnable %d applyGuest %d vlanId %d "
				"userGroupid %d encryptionType %d auth ip %#x authport %d  for show one wlan ", 
				wlan_num, wlanid, wlaninfo.ssid, wlaninfo.securType, x_wep, x_passphrase, x_radius_secret_1, 
				wpa_mode, wpa_enc,wlaninfo.wepIndex, wlaninfo.sHideflag, wlaninfo.isEnable, wlaninfo.applyGflag, wlaninfo.vlanId, 
				wlaninfo.usrGid, wlaninfo.EncryptionType, wlaninfo.Authip, wlaninfo.AuthPort);//
#endif
	
	}
#if WLAN_DEBUG_ENABLE
	syslog(LOG_DEBUG, "after call function show_network_wlan_config wlan_num %d  for show one wlan ", wlan_num);
#endif
	if (hand_dbus_connection)
	{
		uninit_dbus_connection(&hand_dbus_connection);
	}
	
	if (object_init(return_value) != SUCCESS)
    {
        RETURN_LONG(PHP_OBJ_INIT_FAIL);
    }
	
	add_property_zval(return_value, "value", iter_array);
	//RETURN_LONG(ret);
}

int config_one_wlan(struct wlan_conf * wlan_node)
{
	int ret = 0;
	DBusConnection * hand_dbus_connection = NULL;
	WLANWEBINFO wlaninfo;
	
	memset(&wlaninfo, 0, sizeof(wlaninfo));

	if (!wlan_node)
	{
		return -1;
	}

	wlaninfo.WlanId = (int)wlan_node->wlan_id;
	strncpy(wlaninfo.ssid, wlan_node->wlan_ssid, ESSID_DEFAULT_LEN-1);
	wlaninfo.isEnable = (int)wlan_node->wlan_service;
	wlaninfo.applyGflag = (int)wlan_node->guest_enabled;
	wlaninfo.vlanEnabled = (int)wlan_node->vlan_enabled;
	if (wlaninfo.vlanEnabled && wlan_node->vlan > 0)
	{
	    wlaninfo.vlanId = (int)wlan_node->vlan;
	}
	wlaninfo.usrGid = (int)wlan_node->user_group_id;
	wlaninfo.sHideflag = (int)wlan_node->hidden_ssid;

	//if(!strcmp(ENC_TYPE_STR(wlan_conf->encry_type), "ccmp"))
	if (wlan_node->encry_type == ENC_TYPE_AES)
	{
		wlaninfo.EncryptionType= AES;
	}
	else
	{// "auto" or "tkip" 
		wlaninfo.EncryptionType= TKIP;
	}
	//if(!strcmp(SEC_TYPE_STR(wlan_conf->sec_type), "wep"))
	if(wlan_node->sec_type == SEC_TYPE_WEP)
	{
		wlaninfo.wepIndex = wlan_node->wep_index;
		wlaninfo.EncryptionType = WEP;
		wlaninfo.securType = SHARED;
		strncpy(wlaninfo.user_key, wlan_node->wep_key, USER_KEY_LEN-1);
	}
	//else if(!strcmp(SEC_TYPE_STR(wlan_conf->sec_type), "wpapsk"))
	else if (wlan_node->sec_type == SEC_TYPE_WPA_P)
	{
		//if(secur_arg == WPA1)
		if (wlan_node->wpa_mode == WPA_MODE_WPA1)
		{
			wlaninfo.securType = WPA_P;
		}
		else
		{// 0 - auto , 2 - wpa2
			wlaninfo.securType = WPA2_P;
		}
		
		strncpy(wlaninfo.user_key, wlan_node->passphrase, USER_KEY_LEN-1);
	}
	//else if(!strcmp(SEC_TYPE_STR(wlan_conf->sec_type), "wpaeap"))
	else if (wlan_node->sec_type == SEC_TYPE_WPA_E)
	{		
		//if(secur_arg == WPA1)
		if (wlan_node->wpa_mode == WPA_MODE_WPA1)
		{
			wlaninfo.securType = WPA_E;
		}
		else
		{// 0 - auto , 2 - wpa2
			wlaninfo.securType = WPA2_E;
		}
		
		strncpy(wlaninfo.user_key, wlan_node->radius_secret, USER_KEY_LEN-1);
	}
	else
	{//open
		wlaninfo.EncryptionType = NONE;
	}
	if (wlan_node->radius_ip && wlan_node->radius_port)
	{
	    wlaninfo.Authip = wlan_node->radius_ip;
	    wlaninfo.AuthPort = wlan_node->radius_port;
	}
	else
	{
	    wlaninfo.Authip = 0xFFFFFFFF;
	}
	
	if (!hand_dbus_connection)
	{
		dbus_connection_init(&hand_dbus_connection);
	}	
	if (!hand_dbus_connection)
	{
		return (-1);
	}	
	if (wlaninfo.WlanId == 0 || (wlan_node->sec_type > SEC_TYPE_TYPE)
		|| ((wlan_node->sec_type != SEC_TYPE_OPEN) && (!strcmp(wlaninfo.user_key, ""))))
	{
		syslog(LOG_ERR,"input arguments illegal wlanid %d ssid %s securType %d user_key %s", wlaninfo.WlanId, wlaninfo.ssid, wlaninfo.securType, wlaninfo.user_key);
		uninit_dbus_connection(&hand_dbus_connection);
		return (-1);
	}
	
#if WLAN_DEBUG_ENABLE
	syslog(LOG_DEBUG, "before call function  hand_config_softAc_network_config wlanid %d ssid %s user_key %s securType %d wep_index %d sHideflag %d isEnable %d applyGuest %d vlanId %d userGroupid %d encryptionType %d auth ip %#x authport %d ",
	    wlaninfo.WlanId, wlaninfo.ssid, wlaninfo.user_key, wlaninfo.securType, wlaninfo.wepIndex, 
	    wlaninfo.sHideflag, wlaninfo.isEnable, wlaninfo.applyGflag, wlaninfo.vlanId, wlaninfo.usrGid, 
	    wlaninfo.EncryptionType, wlaninfo.Authip, wlaninfo.AuthPort);
#endif	
	ret = hand_load_conf_softAc_network_config(&wlaninfo, hand_dbus_connection);
	if (ret)
	{
		syslog(LOG_ERR, "after  call function hand_config_softAc_network_config ret %#x ", ret);//
	}
	uninit_dbus_connection(&hand_dbus_connection);
	return (ret);
}

