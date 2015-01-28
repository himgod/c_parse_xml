#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include "php.h"
#include "ext_public.h"
#include "ext_sys_config.h"
#include "ext_funcpublic.h"
#include <signal.h>
#include <libxml/xpathInternals.h>
#include <time.h>
#include <syslog.h>
#include "afc_conf.h"

#define DEFAULT_IDLE_TIME  1234

int global_idle_timeout = 0;

ext_func_handle_t sys_manage_func_list[] = {
    {"get_idle_timeout_threshold",1,(php_func_t)ext_get_idle_timeout_threshold},
    {"set_idle_timeout_threshold",2,(php_func_t)ext_set_idle_timeout_threshold},
    {"get_afi_version_update_value",1,(php_func_t)ext_get_afi_version_update_value},
    {"set_afi_version_update_value",2,(php_func_t)ext_set_afi_version_update_value},
    {"get_afi_net_adaption_value",1,(php_func_t)ext_get_afi_net_adaption_value},
    {"set_afi_net_adaption_value",2,(php_func_t)ext_set_afi_net_adaption_value},
    {"get_afi_access_control_value",1,(php_func_t)ext_get_afi_access_control_value},
    {"set_afi_access_control_value",2,(php_func_t)ext_set_afi_access_control_value},
    {"get_wireless_global_country_code",1,(php_func_t)ext_get_wireless_global_country_code},
    {"set_wireless_global_country_code",2,(php_func_t)ext_set_wireless_global_country_code},
    {"get_wireless_global_auto_optim_policy",1,(php_func_t)ext_get_wireless_global_auto_optim_policy},
    {"set_wireless_global_auto_optim_policy",2,(php_func_t)ext_set_wireless_global_auto_optim_policy},
    {"get_user_policy_auto_optim_policy",1,(php_func_t)ext_get_user_policy_auto_optim_policy},
    {"set_user_policy_auto_optim_policy",2,(php_func_t)ext_set_user_policy_auto_optim_policy},
    {"get_afi_blacklist_node",1,(php_func_t)ext_get_afi_blacklist_node},
    {"set_afi_blacklist_node",2,(php_func_t)ext_get_afi_blacklist_node},
    {"get_user_blacklist_node",1,(php_func_t)ext_get_afi_blacklist_node},
    {"set_user_blacklist_node",2,(php_func_t)ext_get_afi_blacklist_node},
    {"load_wireless_config",1,(php_func_t)ext_load_wireless_config},
    {"load_system_config",1,(php_func_t)ext_load_system_config},
};

void ext_sys_manage_handle(int argc, zval ***argv, zval *return_value)
{
    int count = sizeof(sys_manage_func_list)/sizeof(sys_manage_func_list[0]);
    ext_function_handle(argc, argv, return_value, count, sys_manage_func_list);
}

int get_int_from_file(char *filename)
{
	FILE * fd;
	int data, IGNORE_UBSV ret = -1;

	if(filename == NULL)
	{
		return -1;
	}

	fd = fopen(filename, "r");
	if (fd == NULL)
	{
  		printf("Open file:%s error!\n",filename);
		return -1;
	}
	
	ret = fscanf(fd, "%d", &data);
	fclose(fd);

	return data;
}

EXT_FUNCTION(ext_get_idle_timeout_threshold)/*返回-1表示失败*/
{	
    int ret = -1;

	ret = load_all_system_config();

	if(ret < 0 || global_idle_timeout < 0)
	{
	    global_idle_timeout = DEFAULT_IDLE_TIME;
	}
	RETURN_LONG((long)global_idle_timeout);
}

EXT_FUNCTION(ext_set_idle_timeout_threshold)/*返回1表示成功, 返回-1表示idle_timeout非法*/
{	
	char *idle_timeout = NULL; 	
	afc_config_s * afcconf = NULL;
	int time_num = 0, IGNORE_UBSV ret = -1;
	
    ext_para_get(argc, argv, EXT_TYPE_STRING, &idle_timeout);
    
	if(NULL == idle_timeout)
	{
		RETURN_LONG(INPUT_PARA_NULL);
	}
	

	time_num = strtoul(idle_timeout,NULL,10);
	
	if((time_num < 180)||(time_num > 65535))
	{
		RETURN_LONG(-1);
	}
	
    afcconf = get_config_info();

    if(afcconf)
    {
        afcconf->system.timeout = time_num;
    }
    save_config_info(afcconf);
    
	RETURN_LONG(1);
}

EXT_FUNCTION(ext_get_afi_version_update_value)
{
    RETURN_LONG(1);
}
EXT_FUNCTION(ext_set_afi_version_update_value)
{
    char *version_update_stat = NULL;  
    afc_config_s * afcconf = NULL;
    
    ext_para_get(argc, argv, EXT_TYPE_STRING, &version_update_stat);
    
    if(NULL == version_update_stat)
    {
        RETURN_LONG(INPUT_PARA_NULL);
    }
    
    afcconf = get_config_info();

    if(afcconf)
    {
        strcpy(afcconf->afi_policy.version_update,version_update_stat);
    }
    save_config_info(afcconf);
    
    RETURN_LONG(1);
}
EXT_FUNCTION(ext_get_afi_net_adaption_value)
{

}
EXT_FUNCTION(ext_set_afi_net_adaption_value)
{
    long net_adaption_flag = 0; 
    afc_config_s * afcconf = NULL;
    
    ext_para_get(argc, argv, EXT_TYPE_LONG, &net_adaption_flag);
    
     if( net_adaption_flag != 0  && net_adaption_flag != 1)
     {
         RETURN_LONG(-1);
     }
    afcconf = get_config_info();

    if(afcconf)
    {
        afcconf->afi_policy.net_adaption = (int)net_adaption_flag;
    }
    save_config_info(afcconf);
    
    RETURN_LONG(1);
}
EXT_FUNCTION(ext_get_afi_access_control_value)
{
    RETURN_LONG(1);
}
EXT_FUNCTION(ext_set_afi_access_control_value)
{
    long access_control_flag = 0; 
    afc_config_s * afcconf = NULL;
    
    ext_para_get(argc, argv, EXT_TYPE_LONG, &access_control_flag);
    
    if( access_control_flag != 0 && access_control_flag != 1)
    {
        RETURN_LONG(-1);
    }
    afcconf = get_config_info();

    if(afcconf)
    {
        afcconf->afi_policy.access_control = (BOOL)access_control_flag;
    }
    save_config_info(afcconf);
    
    RETURN_LONG(1);
}
EXT_FUNCTION(ext_get_wireless_global_country_code)
{
    RETURN_LONG(1);
}
EXT_FUNCTION(ext_set_wireless_global_country_code)
{
    char *country_code_str = NULL;  
    afc_config_s * afcconf = NULL;
    int country_code = 0;
    ext_para_get(argc, argv, EXT_TYPE_STRING, &country_code_str);
    
    if(NULL == country_code_str)
    {
        RETURN_LONG(INPUT_PARA_NULL);
    }
    

    country_code = strtoul(country_code_str,NULL,10);
    
    // if((time_num < 180)||(time_num > 65535))
    // {
    //     RETURN_LONG(-1);
    // }
    
    afcconf = get_config_info();

    if(afcconf)
    {
        afcconf->wireless_global.country_code = country_code;
    }
    save_config_info(afcconf);
    
    RETURN_LONG(1);
}
EXT_FUNCTION(ext_get_wireless_global_auto_optim_policy)
{
    RETURN_LONG(1);
}

EXT_FUNCTION(ext_set_wireless_global_auto_optim_policy)
{
    char *auto_optim_policy = NULL;  
    afc_config_s * afcconf = NULL;
    
    ext_para_get(argc, argv, EXT_TYPE_STRING, &auto_optim_policy);
    
    if(NULL == auto_optim_policy)
    {
        RETURN_LONG(INPUT_PARA_NULL);
    }
    
    afcconf = get_config_info();

    if(afcconf)
    {
        strcpy(afcconf->wireless_global.auto_optim_policy,auto_optim_policy);
    }
    save_config_info(afcconf);
    
    RETURN_LONG(1);

}
EXT_FUNCTION(ext_get_user_policy_auto_optim_policy)
{
    RETURN_LONG(1);
}
EXT_FUNCTION(ext_set_user_policy_auto_optim_policy)
{
    char *auto_optim_policy = NULL;  
    afc_config_s * afcconf = NULL;
    
    ext_para_get(argc, argv, EXT_TYPE_STRING, &auto_optim_policy);
    
    if(NULL == auto_optim_policy)
    {
        RETURN_LONG(INPUT_PARA_NULL);
    }
    
    afcconf = get_config_info();

    if(afcconf)
    {
        strcpy(afcconf->user_policy.auto_optim_policy,auto_optim_policy);
    }
    save_config_info(afcconf);
    
    RETURN_LONG(1);
}
EXT_FUNCTION(ext_get_afi_blacklist_node)
{
    RETURN_LONG(1);
}
EXT_FUNCTION(ext_set_afi_blacklist_node)
{
    char *afi_mac_name = NULL;  
    afc_config_s * afcconf = NULL;
    
    ext_para_get(argc, argv, EXT_TYPE_STRING, &afi_mac_name);
    
    if(NULL == afi_mac_name)
    {
        RETURN_LONG(INPUT_PARA_NULL);
    }
    
    afcconf = get_config_info();

    if(afcconf)
    {
        strcpy(afcconf->afi_blist.blist_conf.tail->mac,afi_mac_name);
    }
    save_config_info(afcconf);
    
    RETURN_LONG(1);
}
EXT_FUNCTION(ext_get_user_blacklist_node)
{
    RETURN_LONG(1);
}
EXT_FUNCTION(ext_set_user_blacklist_node)
{

}

int load_system_node_config(struct system_conf *system_node)
{
    	
	if(NULL != system_node && (system_node->timeout > 0))
	{
		global_idle_timeout = system_node->timeout;
	}
	else
	{
	    syslog(LOG_ERR, "get idle timeout failed, system_node %p timeout %d set idle time to default 1234", 
	        system_node, system_node ? system_node->timeout : 0);
		global_idle_timeout = DEFAULT_IDLE_TIME;
	}

    return 0;
}
int load_wlans_config(struct wlan_conf **wlans)
{
    int i = 0;
    if(!wlans)
    {
        return -1;
    }
    for(i = START_WLANID; i <= MAX_WLANID; i++)
    {
        if(wlans[i])
        {
            config_one_wlan((struct wlan_conf *)wlans[i]);
        }
    }
    return 0;
}

int load_wtps_config(struct wtp_conf **wtps)
{
    int i = 0;
    if(!wtps)
    {
        return -1;
    }
    for(i = START_WTPID; i <= MAX_WTP_ID; i++)
    {
        if(wtps[i])
        {
            config_one_wtp((struct wtp_conf *)wtps[i]);
        }
    }
    return 0;
}

int load_wireless_global_config(struct wireless_global_conf * wireless_global)
{
    ;
    return 0;
}

int load_afi_policy_config(struct afi_policy_conf * afi_policy)
{
    ;
    return 0;
}
int load_all_system_config()
{    
	afc_config_s * afcconf = NULL;
	
    afcconf = get_config_info();

    if(afcconf)
    {
        load_system_node_config(&afcconf->system);
        //load_sevices_config(&afcconf->services);
        //load_interface_config(&afcconf->interface);
        //load_mail_server_config(&afcconf->mail_server);
    }
    return 0;
}

int load_all_wireless_config()
{    
	afc_config_s * afcconf = NULL;
	
    afcconf = get_config_info();
    
    if(afcconf)
    {
        //load_user_group_config(&(afcconf->user_group));
        //load_guest_policy_config(&(afcconf->guest_policy));
        //load_block_list_config(&(afcconf->block_list));
        load_wlans_config(afcconf->wlans);
        
        load_wtps_config(afcconf->wtps);
        
        //load_wireless_global_config(&(afcconf->wireless_global));
    }              
}

EXT_FUNCTION(ext_load_system_config)
{
    int ret = -1;

    ret = load_all_system_config();

    RETURN_LONG(ret);
}

EXT_FUNCTION(ext_load_wireless_config)
{
    int ret = -1;

    ret = load_all_wireless_config();

    RETURN_LONG(ret);
}

