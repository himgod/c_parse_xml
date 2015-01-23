#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpathInternals.h>
#include <syslog.h>

#include "wcpss/wid/WID.h"
#include "afc_conf.h"

//static const unsigned char global_tx_power[TX_POWER_LEVEL_NUM] = {0/*auto*/, 10/*low*/, 20/*medium*/, 27/*high*/, 0xFF};
static const char * tx_power_level[TX_POWER_LEVEL_NUM] = {"auto", "low", "medium", "high", "custom"};
static const char * radio_mode_select[RADIO_MODE_TYPE] = {"auto", "ng", "na", "ac"};
static const char * wpa_mode_select[WPA_MODE_TYPE] = {"auto", "wpa1", "wpa2"};
static const char * network_mode_select[NETWORK_MODE_TYPE] = {"none", "static", "dhcp"};
static const char * sec_type_select[SEC_TYPE_TYPE] = {"open", "wep", "wpapsk", "wpaeap"};
static const char * enc_type_select[ENC_TYPE_TYPE] = {"auto", "tkip", "ccmp"};

afc_config_s * global_config_info = NULL;

void get_from_xml_node_to_ip_addr(xmlNodePtr testnode, unsigned int *ip_addr)
{
	struct in_addr ip;
	xmlChar *value = NULL;
	if(!testnode || !ip_addr)
	{
	    if(ip_addr)
	    {
	        *ip_addr = 0;
	    }
	    return;
	}
	value = xmlNodeGetContent(testnode);
    DEBUG_VALUE(testnode);
	memset(&ip, 0, sizeof(struct in_addr));
    if(strcmp((char *)value, ""))
    {
	    inet_pton(AF_INET, (char *)value, (void *)&ip);
	}
	*ip_addr = ntohl(ip.s_addr);
	xmlFree(value);
	return ;
}
void get_system_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr testnode = NULL;
	xmlChar *value = NULL;

	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}

	testnode=pcurnode;

	testnode=testnode->children;
	while(testnode !=NULL)
	{	 

		if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_SYSTEM_NAME )))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
			strncpy(afcconf->system.sys_name,(char *)value, MID_STRING_LEN-1);	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_SYSTEM_COUNTRY)))
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);	 
			strncpy(afcconf->system.country,(char *)value, MID_STRING_LEN-1);	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_SYSTEM_TIMEOUT)))
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);	 
			afcconf->system.timeout = (int)strtoul((char *)value, NULL, 10);	
			xmlFree(value);
		}
		else
		{
			syslog(LOG_WARNING, "unknow node to parse for conf file: %s", (char *)testnode->name);
		}
		
		testnode = testnode->next;
	}
}

void get_services_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr testnode = NULL;
	xmlChar *value = NULL;

	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}

	testnode=pcurnode;

	testnode=testnode->children;
	while(testnode !=NULL)
	{	 

		if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_SERVICES_AUTO_UPGRADE)))
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
			afcconf->services.auto_upgrade =  (0 == strcmp((char *)value, "true"));	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_SERVICES_STATUS_LED)))
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
			afcconf->services.status_led =  (0 == strcmp((char *)value, "true"));	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_SERVICES_BACK_SCAN)))
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
			afcconf->services.back_scan =  (0 == strcmp((char *)value, "true"));	
			xmlFree(value);
		}
		else if((!xmlStrcmp(testnode->name, BAD_CAST  CONF_SERVICES_LOAD_BALANCE)))
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
			afcconf->services.load_balance =  (0 == strcmp((char *)value, "true"));	
			xmlFree(value);
		}
		else if((!xmlStrcmp(testnode->name, BAD_CAST  CONF_SERVICES_NUM_PER_RADIO)))
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
			afcconf->services.num_per_radio = (unsigned char )strtoul((char *)value, NULL, 10);	
			xmlFree(value);
		}
		else if((!xmlStrcmp(testnode->name, BAD_CAST  CONF_SERVICES_UPNP_DISCOVERY)))
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
			afcconf->services.upnp_discovery =  (0 == strcmp((char *)value, "true"));	
			xmlFree(value);
		}
		else if((!xmlStrcmp(testnode->name, BAD_CAST  CONF_SERVICES_REMOTE_LOG)))
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
			afcconf->services.remote_log =  (0 == strcmp((char *)value, "true"));	
			xmlFree(value);
		}
		else if((!xmlStrcmp(testnode->name, BAD_CAST  CONF_SERVICES_LOG_SERVER_IP)))
		{
		    get_from_xml_node_to_ip_addr(testnode, &(afcconf->services.log_server_ip));
		}
		else if((!xmlStrcmp(testnode->name, BAD_CAST  CONF_SERVICES_LOG_SERVER_PORT)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
			afcconf->services.log_server_port = (unsigned short )strtoul((char *)value, NULL, 10);
			xmlFree(value);
		}
		else
		{
			syslog(LOG_WARNING, "unknow node to parse for conf file: %s", (char *)testnode->name);
		}
		testnode = testnode->next;
	}	 
}
void get_mail_server_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr testnode = NULL;
	xmlChar *value = NULL;

	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}

	testnode=pcurnode;

	testnode=testnode->children;
	while(testnode !=NULL)
	{	 

		if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_MAILSERVER_SERVER_ENABLED))) 
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
			afcconf->mail_server.server_enabled = (unsigned char )(0 == strcmp((char *)value, "true"));
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_MAILSERVER_SERVER_ADDR)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
			strncpy(afcconf->mail_server.server_addr, (char *)value, LONG_STRING_LEN-1);	
			xmlFree(value);
		}
		else if((!xmlStrcmp(testnode->name, BAD_CAST  CONF_MAILSERVER_SERVER_PORT)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
			afcconf->mail_server.server_port = (unsigned short )strtoul((char *)value, NULL, 10);
			xmlFree(value);
		}
		else if((!xmlStrcmp(testnode->name, BAD_CAST  CONF_MAILSERVER_ENABLE_SSL)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
			afcconf->mail_server.enable_ssl = (unsigned char )(0 == strcmp((char *)value, "true"));
			xmlFree(value);
		}
		else if((!xmlStrcmp(testnode->name, BAD_CAST  CONF_MAILSERVER_AUTHENTICATION)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
			afcconf->mail_server.authentication = (unsigned char )(0 == strcmp((char *)value, "true"));
			xmlFree(value);
		}
		else if((!xmlStrcmp(testnode->name, BAD_CAST  CONF_MAILSERVER_AUTHEN_USER)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
			strncpy(afcconf->mail_server.authen_user, (char *)value, MID_STRING_LEN-1);
			xmlFree(value);
		}
		else if((!xmlStrcmp(testnode->name, BAD_CAST  CONF_MAILSERVER_AUTHEN_PASS)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
			strncpy(afcconf->mail_server.authen_pass, (char *)value, MID_STRING_LEN-1);
			xmlFree(value);
		}
		else if((!xmlStrcmp(testnode->name, BAD_CAST  CONF_MAILSERVER_SENDER_ADDR)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
			strncpy(afcconf->mail_server.sender_addr, (char *)value, MID_STRING_LEN-1);
			xmlFree(value);
		}
		else
		{
			syslog(LOG_WARNING, "unknow node to parse for conf file: %s", (char *)testnode->name);
		}
		testnode = testnode->next;
	}	   
}

void get_interface_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{    

	xmlNodePtr testnode = NULL;
	xmlChar *value = NULL;

	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}

	testnode=pcurnode;

	testnode=testnode->children;
	while(testnode !=NULL)
	{	 

		if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_INTERFACE_NAME )))  
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
			strncpy(afcconf->interface.intf_name,(char *)value, INTF_NAME_LEN-1);	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_INTERFACE_IP)))
		{
		    get_from_xml_node_to_ip_addr(testnode, &(afcconf->interface.intf_ip));
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_INTERFACE_NET_MASK)))
		{
		    get_from_xml_node_to_ip_addr(testnode, &(afcconf->interface.net_mask));
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_INTERFACE_GATEWAY)))
		{
		    get_from_xml_node_to_ip_addr(testnode, &(afcconf->interface.gateway));
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_INTERFACE_FIRST_DNS)))
		{
		    get_from_xml_node_to_ip_addr(testnode, &(afcconf->interface.first_dns));
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_INTERFACE_SECOND_DNS)))
		{
		    get_from_xml_node_to_ip_addr(testnode, &(afcconf->interface.second_dns));
		}
		else
		{
			syslog(LOG_WARNING, "unknow node to parse for conf file: %s", (char *)testnode->name);
		}
		
		testnode = testnode->next;

	}
}
void get_user_group_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr testnode = NULL;
	xmlChar *value = NULL;
	
	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}
	testnode=pcurnode;

	testnode=testnode->children;
	while(testnode !=NULL)
	{
	    if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_USERGROUP_ID)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
			afcconf->user_group.group_id = (unsigned int)strtoul((char *)value, NULL, 10);
			xmlFree(value);
		} 
		testnode = testnode->next;
	}
	return ;
}
void get_guest_policy_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr testnode = NULL;
	xmlChar *value = NULL;
	
	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}
	testnode=pcurnode;

	testnode=testnode->children;
	while(testnode !=NULL)
	{
	    if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_GUESTPOLICY_ID)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
			afcconf->guest_policy.policy_id = (unsigned int)strtoul((char *)value, NULL, 10);
			xmlFree(value);
		} 
		testnode = testnode->next;
	}
	return ;
}

struct blist_node *insert_node(struct block_list_conf * block_hash, unsigned char * mac)
{
    unsigned char key = 0;
    struct blist_node * tmpNode = NULL;
    if(!block_hash || !mac)
    {
        return NULL;
    }
    tmpNode = find_blist_node(block_hash, mac);
    if(tmpNode)
    {
        return tmpNode;
    }
    key = (mac[0]^mac[1]^mac[2]^mac[3]^mac[4]^mac[5])/BLIST_HASH_LEN;
    tmpNode = (struct blist_node *)malloc(sizeof(struct blist_node));
    if(!tmpNode)
    {
        return NULL;
    }
    memcpy(tmpNode->mac, mac, MAC_LEN);
    tmpNode->hnext = block_hash->hash[key];
	tmpNode->next = NULL;
    block_hash->hash[key] = tmpNode;
	if(!block_hash->head)
	{
		block_hash->head = tmpNode;	
	}
	if(!block_hash->tail)
	{	
		block_hash->tail = tmpNode;
	}
	else
	{
		block_hash->tail->next = tmpNode;
		block_hash->tail = tmpNode;
	}
    block_hash->num++;
    return tmpNode;
}
BOOL remove_node(struct block_list_conf * block_hash, unsigned char * mac)
{
    unsigned char key = 0;
    struct blist_node * tmpNode = NULL;
    struct blist_node * preNode = NULL;
    if(!block_hash || !mac)
    {
        return FALSE;
    }
    key = (mac[0]^mac[1]^mac[2]^mac[3]^mac[4]^mac[5])/BLIST_HASH_LEN;
    tmpNode = block_hash->hash[key];
    while(tmpNode)
    {
        if(!memcmp(tmpNode->mac, mac, MAC_LEN))
        {
            if(NULL == preNode)
            {
                block_hash->hash[key] = tmpNode->hnext;
            }
            else
            {
                preNode->hnext = tmpNode->hnext;
            }
			if(block_hash->head == tmpNode)
			{
				block_hash->head = tmpNode->next;				
			}
			if(block_hash->tail == tmpNode)
			{
    			struct blist_node * tmpNodePtr = block_hash->head;
				if(tmpNodePtr == tmpNode)
				{
					block_hash->tail = NULL;
				}
				else 
				{
					while(tmpNodePtr)
					{
						if(tmpNodePtr->next == tmpNode)
						{
							block_hash->tail =  tmpNodePtr;
							break;
						}
						tmpNodePtr = tmpNodePtr->next;
					}
				}
			}
            free(tmpNode);
            block_hash->num--;
            return TRUE;
        }
        preNode = tmpNode;
        tmpNode = tmpNode->hnext;
    }
    return FALSE;
}
struct blist_node * find_blist_node(struct block_list_conf * block_hash, unsigned char * mac)
{
    unsigned char key = 0;
    struct blist_node * tmpNode = NULL;
    if(!block_hash || !mac)
    {
        return NULL;
    }
    key = (mac[0]^mac[1]^mac[2]^mac[3]^mac[4]^mac[5])/BLIST_HASH_LEN;
    tmpNode = block_hash->hash[key];
    while(tmpNode)
    {
        if(!memcmp(tmpNode->mac, mac, MAC_LEN))
        {
            return tmpNode;
        }
        tmpNode = tmpNode->hnext;
    }
    return NULL;
}
void destroy_block_list(struct block_list_conf * block_hash)
{
    struct blist_node * tmpNode = NULL;
    struct blist_node * preNode = NULL;
#ifdef DESTROY_BY_HASH
    unsigned char key = 0;
    for(key = 0; key < BLIST_HASH_LEN; key++)
    {
        tmpNode = block_hash->hash[key];
        block_hash->hash[key] = NULL;
        while(tmpNode)
        {
            preNode = tmpNode;
            tmpNode = tmpNode->hnext;
#if BLOCK_LIST_DEBUG
			syslog(LOG_DEBUG, "destroy node of mac %02x:%02x:%02x:%02x:%02x:%02x",
				preNode->mac[0], preNode->mac[1], preNode->mac[2], 
				preNode->mac[3], preNode->mac[4], preNode->mac[5]);
#endif
            free(preNode);
        }
    }
#else
    tmpNode = block_hash->head;
    
    while(tmpNode)
    {
        preNode = tmpNode;
        tmpNode = tmpNode->next;
#if BLOCK_LIST_DEBUG
		syslog(LOG_DEBUG, "delete block device mac %02x:%02x:%02x:%02x:%02x:%02x",
			preNode->mac[0], preNode->mac[1], preNode->mac[2], 
			preNode->mac[3], preNode->mac[4], preNode->mac[5]);
#endif
        free(preNode);
    }
#endif
	memset(block_hash, 0, sizeof(struct block_list_conf));
    return ;
}

void get_block_list_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
    xmlNodePtr testnode = NULL;
    xmlChar *value = NULL;

	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}

    testnode=pcurnode;

    testnode=testnode->children;
    while(testnode !=NULL)
    {	 

    	if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_BLOCKLIST_MAC))) 
    	{
    	    unsigned char tmpMac[MAC_LEN] = {0};
    	    char tmpValue[MID_STRING_LEN] = {0};
    	    char * tmpStr = tmpValue;
    	    int i = 0;
    		value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
            strncpy(tmpStr, (char *)value, MID_STRING_LEN-1);
            tmpStr = strtok(tmpStr, ":");
            while(tmpStr && i < MAC_LEN)
            {
                tmpMac[i] = (unsigned char)strtoul(tmpStr, NULL, 16);
                tmpStr = strtok(NULL, ":");
                i++;
            }
    		insert_node(&afcconf->block_list, (unsigned char *)tmpMac);
    		xmlFree(value);
    	}
		else
		{
			//syslog(LOG_WARNING, "unknow node to parse for conf file: %s", (char *)testnode->name);
		}
		testnode = testnode->next;
    }
}

void get_wireless_global_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
    xmlNodePtr testnode = NULL;
    xmlChar *value = NULL;

	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}

    testnode=pcurnode;

    testnode=testnode->children;
    while(testnode !=NULL)
    {	 

    	if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WIRELESS_GLOBAL_WTP_AUTO_ACCESS))) 
    	{
    		value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
    		afcconf->wireless_global.wtp_auto_access = (unsigned char )(0 == strcmp((char *)value, "true"));
    		xmlFree(value);
    	}
    	else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_GLOBAL_COUNTRY_CODE)))
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);	 
			afcconf->wireless_global.country_code = (int)strtoul((char *)value, NULL, 10);	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_GLOBAL_AUTO_OPTIM_POLICY)))
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);	 
			strncpy(afcconf->wireless_global.auto_optim_policy,(char *)value, MID_STRING_LEN-1);	
			xmlFree(value);
		}
		else
		{
			syslog(LOG_WARNING, "unknow node to parse for conf file: %s", (char *)testnode->name);
		}
		testnode = testnode->next;
    }
}

void get_afi_policy_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr testnode = NULL;
    xmlChar *value = NULL;

	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}

    testnode=pcurnode;

    testnode=testnode->children;
    while(testnode !=NULL)
    {	 

    	if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_VERSION_UPDATE))) 
    	{
    		value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
            strncpy(afcconf->afi_policy.version_update,(char *)value, MID_STRING_LEN-1);
    		xmlFree(value);
    	}
    	else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_NET_ADAPTION)))
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);	 
			afcconf->afi_policy.net_adaption = (unsigned char )(0 == strcmp((char *)value, "true"));	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_ACCESS_CONTROL)))
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);	 
			afcconf->afi_policy.access_control = (unsigned char )(0 == strcmp((char *)value, "true"));	
			xmlFree(value);
		}
		else
		{
			syslog(LOG_WARNING, "unknow node to parse for conf file: %s", (char *)testnode->name);
		}
		testnode = testnode->next;
    }
}
void get_user_policy_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr testnode = NULL;
    xmlChar *value = NULL;

	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}

    testnode=pcurnode;

    testnode=testnode->children;
    while(testnode !=NULL)
    {	 

    	if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_AUTO_OPTIM_POLICY))) 
    	{
    		value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
            strncpy(afcconf->user_policy.auto_optim_policy,(char *)value, MID_STRING_LEN-1);
    		xmlFree(value);
    	}
		else
		{
			syslog(LOG_WARNING, "unknow node to parse for conf file: %s", (char *)testnode->name);
		}
		testnode = testnode->next;
    }
}
void destroy_map_node(struct map_conf * map_node)
{
    if(map_node)
    {
        free(map_node);
    }
}

void get_map_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr testnode = NULL;
	xmlChar *value = NULL;
	struct map_conf *map_node = NULL;
	int mapid = 0;
	
	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}
	map_node = (struct map_conf *)malloc(sizeof(struct map_conf));
	if(!map_node)
	{
	    syslog(LOG_ERR, "map node malloc failed ");
	    return;
	}
	memset(map_node, 0, sizeof(struct map_conf));
	testnode=pcurnode;

	testnode=testnode->children;
	while(testnode !=NULL)
	{	 

		if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_MAP_NAME)))
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);	 
			strncpy(map_node->name,(char *)value, MID_STRING_LEN-1);	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_MAP_URL)))
		{
			
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);	 
			strncpy(map_node->url,(char *)value, LONG_STRING_LEN-1);	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_MAP_INIT_SCALE_UNIT)))
		{
			
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);	 
			strncpy(map_node->initscaleunit,(char *)value, 7);
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_MAP_INIT_SCALE_METER)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);		 
			map_node->initscalemeter = (unsigned short)strtoul((char *)value, NULL, 10);	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_MAP_INIT_SCALE_WIDTH)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);		 
			map_node->initscalewidth = (unsigned short)strtoul((char *)value, NULL, 10);	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_MAP_SELECTED)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
			map_node->selected = (0 == strcmp((char *)value, "true"));
			xmlFree(value);
		}
		else
		{
			//syslog(LOG_WARNING, "unknow node to parse for conf file: %s", (char *)testnode->name);
		}
		
		testnode = testnode->next;
	}
	mapid = START_MAPID;
	while(afcconf->maps[mapid] && mapid <= MAX_MAP_ID)
	{
	    mapid++;
	}
	if(mapid <= MAX_MAP_ID && NULL == afcconf->maps[mapid])
	{
		afcconf->maps[mapid] = map_node;
	}
	else
	{
		destroy_map_node(map_node);
		map_node = NULL;
	}
	return;
}
void destroy_wlan_node(struct wlan_conf * wlan_node)
{
    if(wlan_node)
    {
        free(wlan_node);
    }
}
void get_wlan_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr testnode = NULL;
	xmlChar *value = NULL;
	struct wlan_conf *wlan_node = NULL;
	
	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}
	wlan_node = (struct wlan_conf *)malloc(sizeof(struct wlan_conf));
	if(!wlan_node)
	{
	    syslog(LOG_ERR, "wlan node malloc failed ");
	    return;
	}
	memset(wlan_node, 0, sizeof(struct wlan_conf));
	testnode=pcurnode;

	testnode=testnode->children;
	while(testnode !=NULL)
	{	 

		if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WLAN_ID)))  
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
			wlan_node->wlan_id = (unsigned int)strtoul((char *)value, NULL, 10);
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WLAN_SSID)))
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);	 
			strncpy(wlan_node->wlan_ssid,(char *)value, SHORT_STRING_LEN-1);	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WLAN_SERVICE)))
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);	 
			wlan_node->wlan_service = (char)(0 == strcmp((char *)value, "true"));	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WLAN_SEC_TYPE)))
		{
            int type = 0;
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
             
        	for(type = 0; type < SEC_TYPE_TYPE; type ++)
        	{
        	    if(!strcmp((char *)value, sec_type_select[type]))
        	    {
        	        wlan_node->sec_type = type;
        	    }
        	}
        	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WLAN_ENCRY_TYPE)))
		{
		    int type = 0;
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);	 
             
        	for(type = 0; type < ENC_TYPE_TYPE; type ++)
        	{
        	    if(!strcmp((char *)value, enc_type_select[type]))
        	    {
        	        wlan_node->encry_type = type;
        	    }
        	}
        	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WLAN_PASSPHRASE)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);		 
			strncpy(wlan_node->passphrase,(char *)value, LONG_STRING_LEN-1);
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WLAN_WEP_KEY)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);		 
			strncpy(wlan_node->wep_key,(char *)value, LONG_STRING_LEN-1);
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WLAN_RADIUS_SECRET)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);		 
			strncpy(wlan_node->radius_secret,(char *)value, LONG_STRING_LEN-1);
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WLAN_RADIUS_IP)))
		{
		    get_from_xml_node_to_ip_addr(testnode, &(wlan_node->radius_ip));
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WLAN_RADIUS_PORT)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);		 
			wlan_node->radius_port = (unsigned short)strtoul((char *)value, NULL, 10);	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WLAN_GUEST_ENABLED)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);		 
			wlan_node->guest_enabled = (0 == strcmp((char *)value, "true"));	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WLAN_VLAN_ENABLED)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);		 
			wlan_node->vlan_enabled = (0 == strcmp((char *)value, "true"));	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WLAN_VLAN)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);		 
			wlan_node->vlan = (unsigned short)strtoul((char *)value, NULL, 10);	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WLAN_HIDDEN_SSID)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);		 
			wlan_node->hidden_ssid = (0 == strcmp((char *)value, "true"));	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WLAN_WPA_MODE)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
            if(!strcmp((char *)value, "wpa1"))
            {
                wlan_node->wpa_mode = WPA_MODE_WPA1;
            }
            else if(!strcmp((char *)value, "wpa2"))
            {
                wlan_node->wpa_mode = WPA_MODE_WPA2;
            }
            else
            {
                wlan_node->wpa_mode = WPA_MODE_AUTO;
            }
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WLAN_USER_GROUP_ID)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
			wlan_node->user_group_id = (unsigned int)strtoul((char *)value, NULL, 10);	
			xmlFree(value);
		}
		else
		{
			//syslog(LOG_WARNING, "unknow node to parse for conf file: %s", (char *)testnode->name);
		}
		
		testnode = testnode->next;
	}
	if(wlan_node->wlan_id > 0 && NULL == afcconf->wlans[wlan_node->wlan_id])
	{
		afcconf->wlans[wlan_node->wlan_id] = wlan_node;
	}
	else
	{
		if((wlan_node->wlan_id > 0  && wlan_node->wlan_id <= MAX_WLANID)&& NULL != afcconf->wlans[wlan_node->wlan_id] )
		{
			syslog(LOG_ERR, "config file error wlan %d duplicated ", wlan_node->wlan_id);
		}
		else if(0 != wlan_node->wlan_id)
		{
			syslog(LOG_ERR, "config file error illegal wlan node wlan id %d", wlan_node->wlan_id);
		}
		destroy_wlan_node(wlan_node);
		wlan_node = NULL;
	}
	return;
}
void destroy_radio_wlan(struct radio_wlan_conf * radio_wlan)
{
    if(radio_wlan)
    {
        free(radio_wlan);
    }
    return;
}
void destroy_wtp_radio(struct radio_conf * wtp_radio)
{
    if(wtp_radio)
    {
        int i = 0;
        for(i = 0; i <= MAX_WLANID; i++)
        {
            destroy_radio_wlan(wtp_radio->wlans[i]);
            wtp_radio->wlans[i] = NULL;
        }
        free(wtp_radio);
    }
}
void destroy_wtp_node(struct wtp_conf * wtp_node)
{
    if(wtp_node)
    {
        int i = 0;
        for(i = 0; i < MAX_RADIO_NUM; i++)
        {
            destroy_wtp_radio(wtp_node->radios[i]);
            wtp_node->radios[i] = NULL;
        }
        free(wtp_node);
    }
}

void destroy_afc_conf(afc_config_s * afcconf, int freeafc)
{
    if(afcconf)
    {
        int i = 0;
        
        destroy_block_list(&afcconf->block_list);
        
        for(i = 0; i <= MAX_WLANID; i++)
        {
            destroy_wlan_node(afcconf->wlans[i]);
            afcconf->wlans[i] = NULL;
        }
        for(i = 0; i <= MAX_WTP_ID; i++)
        {
            destroy_wtp_node(afcconf->wtps[i]);
            afcconf->wtps[i] = NULL;
        }
        if(freeafc)
        {
            free(afcconf);
        }
        else
        {
            memset(afcconf, 0, sizeof(afc_config_s));
        }
    }
    return ;
}

void get_radio_wlans_conf(xmlNodePtr pcurnode, struct radio_conf * wtp_radio)
{	
    /*    						
     CONF_WTP_RADIO_WLAN_ID 					
     CONF_WTP_RADIO_WLAN_ENABLED 			
     CONF_WTP_RADIO_WLAN_SSID 				
     CONF_WTP_RADIO_WLAN_SECURITY_KEY 
     CONF_WTP_RADIO_WLAN_VLAN_ENABLED 
     CONF_WTP_RADIO_WLAN_VLAN
    */
    xmlNodePtr testnode = NULL;
	xmlChar *value = NULL;
    struct radio_wlan_conf * radio_wlan = NULL;

	if(!pcurnode || !wtp_radio)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p wtp_radio %p", FUNC_LINE_VALUE, pcurnode, wtp_radio);
	    return;
	}

	radio_wlan = (struct radio_wlan_conf *)malloc(sizeof(struct radio_wlan_conf));
	if(!radio_wlan)
	{
	    syslog(LOG_ERR, "wlan node malloc failed ");
	    return;
	}
	memset(radio_wlan, 0, sizeof(struct radio_wlan_conf));

	testnode=pcurnode;

	testnode=testnode->children;
	while(testnode !=NULL)
	{	 

		if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_RADIO_WLAN_ID)))  
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
			radio_wlan->wlan_id = (unsigned int)strtoul((char *)value, NULL, 10);
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_RADIO_WLAN_ENABLED)))  
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
			radio_wlan->wlan_enabled = (0 == strcmp((char *)value, "true"));
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_RADIO_WLAN_SSID)))  
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
			strncpy(radio_wlan->wlan_essid, (char *)value, SHORT_STRING_LEN-1);
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_RADIO_WLAN_SECURITY_KEY)))  
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
			strncpy(radio_wlan->security_key, (char *)value, MID_STRING_LEN-1);
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_RADIO_WLAN_VLAN_ENABLED)))  
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
			radio_wlan->vlan_enabled = (0 == strcmp((char *)value, "true"));
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_RADIO_WLAN_VLAN)))  
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
			radio_wlan->vlan = (unsigned short)strtoul((char *)value, NULL, 10);
			xmlFree(value);
		}
		else
		{
			syslog(LOG_WARNING, "unknow node to parse for conf file: %s", (char *)testnode->name);
		}
		testnode = testnode->next;
	}
	if(radio_wlan->wlan_id > 0 && NULL == wtp_radio->wlans[radio_wlan->wlan_id])
	{
	    wtp_radio->wlans[radio_wlan->wlan_id] = radio_wlan;
	}
	else
	{
		if((radio_wlan->wlan_id > 0 && radio_wlan->wlan_id <= MAX_WLANID) 
			&& NULL != wtp_radio->wlans[radio_wlan->wlan_id])
		{
		    syslog(LOG_ERR, "config file error wtp radio wlans[%d] %p ", radio_wlan->wlan_id, 
		        (radio_wlan->wlan_id > 0) ? wtp_radio->wlans[radio_wlan->wlan_id]:NULL);
		}
		else if(0 != radio_wlan->wlan_id)
		{
			syslog(LOG_ERR, "config file error illegal wtp radio wlan id %d ", radio_wlan->wlan_id);
		}
	    destroy_radio_wlan(radio_wlan);
	    radio_wlan = NULL;
	}
	return ;    
}
void get_wtp_radio_conf(xmlNodePtr pcurnode, struct wtp_conf *wtp_node)
{
		/*								
 CONF_WTP_RADIO_LOCAL_ID					
 CONF_WTP_RADIO_CHANNEL						
 CONF_WTP_RADIO_CHANNEL_HT				
 CONF_WTP_RADIO_TX_POWER 					
 CONF_WTP_RADIO_CUSTOM_TX_POWER 	
 CONF_WTP_RADIO_MODE 							
 CONF_WTP_RADIO_ANTENNA_GAIN 			
 CONF_WTP_RADIO_WLAN 	 		
 */
	xmlNodePtr testnode = NULL;
	xmlChar *value = NULL;
    struct radio_conf * wtp_radio = NULL;
    
	if(!pcurnode || !wtp_node)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p wtp_node %p", FUNC_LINE_VALUE, pcurnode, wtp_node);
	    return;
	}
	wtp_radio = (struct radio_conf *)malloc(sizeof(struct radio_conf));
	if(!wtp_radio)
	{
	    syslog(LOG_ERR, "wlan node malloc failed ");
	    return;
	}
	memset(wtp_radio, 0, sizeof(struct radio_conf));

	testnode=pcurnode;

	testnode=testnode->children;
	wtp_radio->local_id = INVALID_RADIO_NUM;
	while(testnode !=NULL)
	{	 

		if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_RADIO_LOCAL_ID)))  
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
			wtp_radio->local_id = (unsigned char)strtoul((char *)value, NULL, 10);
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_RADIO_CHANNEL)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);		 
			wtp_radio->channel = (unsigned char)strtoul((char *)value, NULL, 10);
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_RADIO_CHANNEL_HT)))
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);	 
			wtp_radio->channel_ht = (unsigned char)strtoul((char *)value, NULL, 10);
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_RADIO_TX_POWER)))
		{
			value = xmlNodeGetContent(testnode);		 
			if(!strcmp((char *)value, "auto"))
			{
			    wtp_radio->tx_power = TX_POWER_AUTO;
			}
			else if(!strcmp((char *)value, "low"))
			{
			    wtp_radio->tx_power = TX_POWER_LOW;
			}
			else if(!strcmp((char *)value, "medium"))
			{
			    wtp_radio->tx_power = TX_POWER_MEDIUM;
			}
			else if(!strcmp((char *)value, "high"))
			{
			    wtp_radio->tx_power = TX_POWER_HIGH;
			}
			else if(!strcmp((char *)value, "custom"))
			{
			    wtp_radio->tx_power = TX_POWER_CUSTOM;
			}
			else
			{
			    wtp_radio->tx_power = TX_POWER_AUTO;
			}
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_RADIO_CUSTOM_TX_POWER)))
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);	 
			wtp_radio->custom_tx_power = (unsigned char)strtoul((char *)value, NULL, 10);
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_RADIO_MODE)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);		 
            if(!strcmp((char *)value, "ng"))
            {
                wtp_radio->radio_mode = RADIO_MODE_NG;
            }		 
            else if(!strcmp((char *)value, "na"))
            {
                wtp_radio->radio_mode = RADIO_MODE_NA;
            }	 
            else if(!strcmp((char *)value, "na"))
            {
                wtp_radio->radio_mode = RADIO_MODE_AC;
            }	 
            else
            {
                wtp_radio->radio_mode = RADIO_MODE_AUTO;
            }
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_RADIO_ANTENNA_GAIN)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
			wtp_radio->antenna_gain = (unsigned char)strtoul((char *)value, NULL, 10);
			xmlFree(value);
		}		
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_RADIO_WLAN)))
		{
		    DEBUG_NAME(testnode);
		    get_radio_wlans_conf(testnode, wtp_radio);
		}
		else
		{
			syslog(LOG_WARNING, "unknow node to parse for conf file: %s", (char *)testnode->name);
		}
		testnode = testnode->next;
	}
	if((wtp_radio->local_id >= START_RADIO_NUM 
		&& wtp_radio->local_id < MAX_RADIO_NUM) 
		&& NULL == wtp_node->radios[wtp_radio->local_id])
	{
	    wtp_node->radios[wtp_radio->local_id] = wtp_radio;
	}
	else
	{
		if((wtp_radio->local_id >= START_RADIO_NUM && 
			wtp_radio->local_id < MAX_RADIO_NUM) && 
			NULL != wtp_node->radios[wtp_radio->local_id])
		{
		    syslog(LOG_ERR, "config file error wtp wtp_node->radios[%d] %p", 
		        wtp_radio->local_id, 
		        (wtp_radio->local_id >= START_RADIO_NUM && 
		        wtp_radio->local_id < MAX_RADIO_NUM) ? 
		        wtp_node->radios[wtp_radio->local_id]:NULL);
		}
		else if(wtp_radio->local_id != INVALID_RADIO_NUM)
		{
			syslog(LOG_ERR, "config file error wtp radio local id %d", wtp_radio->local_id);
		}
	    destroy_wtp_radio(wtp_radio);
	    wtp_radio = NULL;
    }
}
void get_wtp_network_conf(xmlNodePtr pcurnode, struct wtp_conf *wtp_node)
{
 /* 								
 CONF_WTP_NETWORK_MODE 						
 CONF_WTP_NETWORK_IP_ADDR 
 CONF_WTP_NETWORK_NET_MASK 
 CONF_WTP_NETWORK_GATEWAY 
 CONF_WTP_NETWORK_FIRST_DNS 
 CONF_WTP_NETWORK_SECOND_DNS */
 	xmlNodePtr testnode = NULL;
	xmlChar *value = NULL;    
    
	if(!pcurnode || !wtp_node)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p wtp_node %p", FUNC_LINE_VALUE, pcurnode, wtp_node);
	    return;
	}

	testnode=pcurnode;

	testnode=testnode->children;
	while(testnode !=NULL)
	{	 

		if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_NETWORK_MODE)))  
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
			if(!strcmp((char *)value, "static"))
			{
			    wtp_node->network.mode = STATIC;
			}
			else if(!strcmp((char *)value, "dhcp"))
			{
			    wtp_node->network.mode = DHCP;
			}
			else
			{
			    wtp_node->network.mode = NETWORK_MODE_NONE;
			}
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_NETWORK_IP_ADDR)))
		{
		    get_from_xml_node_to_ip_addr(testnode, &(wtp_node->network.ip_addr));
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_NETWORK_NET_MASK)))
		{
		    get_from_xml_node_to_ip_addr(testnode, &(wtp_node->network.net_mask));
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_NETWORK_GATEWAY)))
		{
		    get_from_xml_node_to_ip_addr(testnode, &(wtp_node->network.gateway));
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_NETWORK_FIRST_DNS)))
		{
		    get_from_xml_node_to_ip_addr(testnode, &(wtp_node->network.first_dns));
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_NETWORK_SECOND_DNS)))
		{
		    get_from_xml_node_to_ip_addr(testnode, &(wtp_node->network.second_dns));
		}
		else
		{
			syslog(LOG_WARNING, "unknow node to parse for conf file: %s", (char *)testnode->name);
		}
		testnode = testnode->next;
	}
	return ;
}

void get_wtp_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr testnode = NULL;
	xmlChar *value = NULL;
	struct wtp_conf *wtp_node = NULL;
	
	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}
	wtp_node = (struct wtp_conf *)malloc(sizeof(struct wtp_conf));
	if(!wtp_node)
	{
	    syslog(LOG_ERR, "wlan node malloc failed ");
	    return;
	}
	memset(wtp_node, 0, sizeof(struct wtp_conf));

	testnode=pcurnode;

	testnode=testnode->children;
	while(testnode !=NULL)
	{	 

		if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_ID )))  
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
			wtp_node->wtp_id = (unsigned int)strtoul((char *)value, NULL, 10);	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_MODEL)))
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);	 
			strncpy(wtp_node->wtp_model,(char *)value, SHORT_STRING_LEN-1);	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_MAC)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
			strncpy(wtp_node->wtp_mac,(char *)value, SHORT_STRING_LEN-1);	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_NAME)))
		{
			value = xmlNodeGetContent(testnode);
            DEBUG_VALUE(testnode);
			strncpy(wtp_node->wtp_name, (char *)value, MID_STRING_LEN-1);	
			xmlFree(value);
		}
		else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_SERVICE)))  
		{
			value = xmlNodeGetContent(testnode);	
            DEBUG_VALUE(testnode);
			wtp_node->wtp_service = (int)strtoul((char *)value, NULL, 10);	
			xmlFree(value);
		}
        else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_RADIO )))   
		{/* CONF_WTP_RADIO */
		    DEBUG_NAME(testnode);
			get_wtp_radio_conf(testnode, wtp_node);
		}
        else if ((!xmlStrcmp(testnode->name, BAD_CAST  CONF_WTP_NETWORK)))   
		{/* CONF_WTP_NETWORK */
		    DEBUG_NAME(testnode);
			get_wtp_network_conf(testnode, wtp_node);
		}
		else
		{
			//syslog(LOG_WARNING, "unknow node to parse for conf file: %s", (char *)testnode->name);
		}
		testnode = testnode->next;
	}
	if(wtp_node->wtp_id > 0 && NULL == afcconf->wtps[wtp_node->wtp_id] )
	{
		afcconf->wtps[wtp_node->wtp_id] = wtp_node;
	}
	else
	{
		if((wtp_node->wtp_id > 0 && wtp_node->wtp_id <= MAX_WTP_ID) 
			&& NULL != afcconf->wtps[wtp_node->wtp_id] )
		{
			syslog(LOG_ERR, "config file error wtp %d duplicated ", wtp_node->wtp_id);
		}
		else if(wtp_node->wtp_id != 0)
		{
			syslog(LOG_ERR, "config file error wtp %d illegal ", wtp_node->wtp_id);
		}
		destroy_wtp_node(wtp_node);
		wtp_node = NULL;
	}
}

int read_afc_config_from_conf_file(char * pathFile, afc_config_s * afcconf)
{
	xmlDocPtr pdoc = NULL;

	xmlNodePtr pcurnode = NULL;
	char *psfilename = NULL;
	if(!pathFile || !afcconf)
	{
		syslog(LOG_ERR, "read afc config error, Bad input argument: path/file %p afcconf %p", pathFile, afcconf);
		return -1;
	}
	psfilename = pathFile;

	//memset(afcconf, 0, sizeof(afc_config_s) ); move out of this function 

	pdoc = xmlReadFile(psfilename,"utf-8",256);  //解析文件

	if(NULL == pdoc)
	{
		return -1;
	}  
	pcurnode = xmlDocGetRootElement(pdoc);  //得到根节点   


	pcurnode=pcurnode->xmlChildrenNode;  //得到子节点集合
	
	
	while (pcurnode != NULL)   //遍历子节点集合，找出所需的，
	{     

		if ((!xmlStrcmp(pcurnode->name, BAD_CAST CONF_SYSTEM)))
		{   
		    DEBUG_NAME(pcurnode);
			get_system_conf(pcurnode, afcconf);
		}  
		else if ((!xmlStrcmp(pcurnode->name, BAD_CAST CONF_SERVICES)))
		{
		    DEBUG_NAME(pcurnode);
			get_services_conf(pcurnode, afcconf);
		}  
		else if ((!xmlStrcmp(pcurnode->name, BAD_CAST CONF_MAILSERVER)))
		{
		    DEBUG_NAME(pcurnode);
			get_mail_server_conf(pcurnode, afcconf);
		}  
		else if ((!xmlStrcmp(pcurnode->name, BAD_CAST CONF_INTERFACE)))
		{
		    DEBUG_NAME(pcurnode);
			get_interface_conf(pcurnode, afcconf);
		}    
		else if ((!xmlStrcmp(pcurnode->name, BAD_CAST CONF_USERGROUP)))
		{
		    DEBUG_NAME(pcurnode);
			get_user_group_conf(pcurnode, afcconf);
		}  
		else if ((!xmlStrcmp(pcurnode->name, BAD_CAST CONF_GUESTPOLICY)))
		{
		    DEBUG_NAME(pcurnode);
			get_guest_policy_conf(pcurnode, afcconf);
		}
		else if ((!xmlStrcmp(pcurnode->name, BAD_CAST CONF_BLOCKLIST)))
		{
		    DEBUG_NAME(pcurnode);
			get_block_list_conf(pcurnode, afcconf);
		}
		else if ((!xmlStrcmp(pcurnode->name, BAD_CAST CONF_WIRELESS_GLOBAL)))
		{	
		    DEBUG_NAME(pcurnode);
		    get_wireless_global_conf(pcurnode, afcconf);
		}
		else if ((!xmlStrcmp(pcurnode->name, BAD_CAST CONF_AFI_POLICY)))
		{
			DEBUG_NAME(pcurnode);
		    get_afi_policy_conf(pcurnode, afcconf);
		}
		else if ((!xmlStrcmp(pcurnode->name, BAD_CAST CONF_USER_POLICY)))
		{
			DEBUG_NAME(pcurnode);
		    get_user_policy_conf(pcurnode, afcconf);
		}
		else if ((!xmlStrcmp(pcurnode->name, BAD_CAST CONF_MAP)))
		{
		    DEBUG_NAME(pcurnode);
			get_map_conf(pcurnode, afcconf);
		}
		else if ((!xmlStrcmp(pcurnode->name, BAD_CAST CONF_WLAN)))
		{
		    DEBUG_NAME(pcurnode);
			get_wlan_conf(pcurnode, afcconf);
		}
		else if ((!xmlStrcmp(pcurnode->name, BAD_CAST CONF_WTP)))
		{
		    DEBUG_NAME(pcurnode);
			get_wtp_conf(pcurnode, afcconf);
		}
		else
		{
			syslog(LOG_WARNING, "unknow node to parse for conf file: %s", (char *)pcurnode->name);
		}
		

		pcurnode = pcurnode->next;
	} 	

	xmlFreeDoc(pdoc);
	xmlCleanupParser();
	return 0;
}
void set_xml_node_value(xmlNodePtr tmp_node, char * value)
{
    char tmp[XML_NODE_BUF_LEN] = {0};    
    memset ( tmp, 0, LONG_STRING_LEN);
    snprintf(tmp, LONG_STRING_LEN-1, "%s",value);
    xmlNodeSetContent(tmp_node, (const xmlChar *)tmp);
    DEBUG_VALUE(tmp_node);
}
void set_xml_node_value_from_int(xmlNodePtr tmp_node, int value)
{
    char tmp[XML_NODE_BUF_LEN] = {0};    
    memset ( tmp, 0, LONG_STRING_LEN);
    snprintf(tmp, LONG_STRING_LEN-1, "%d",value);
    xmlNodeSetContent(tmp_node, (const xmlChar *)tmp);
    DEBUG_VALUE(tmp_node);
}

void set_xml_node_value_from_uint(xmlNodePtr tmp_node, unsigned int value)
{
    char tmp[XML_NODE_BUF_LEN] = {0};    
    memset ( tmp, 0, LONG_STRING_LEN);
    snprintf(tmp, LONG_STRING_LEN-1, "%u",value);
    xmlNodeSetContent(tmp_node, (const xmlChar *)tmp);
    DEBUG_VALUE(tmp_node);
}

void set_xml_node_value_from_ip_addr(xmlNodePtr tmp_node, unsigned int value)
{
    char tmp[XML_NODE_BUF_LEN] = {0};
	struct in_addr ip;
    memset ( tmp, 0, XML_NODE_BUF_LEN);
	memset(&ip, 0, sizeof(struct in_addr));
    if(value)
    {
        ip.s_addr = htonl(value);
        inet_ntop(AF_INET, (void *)&ip, (char *)tmp, (socklen_t)XML_NODE_BUF_LEN);
    }
    xmlNodeSetContent(tmp_node, (const xmlChar *)tmp);
    DEBUG_VALUE(tmp_node);
}

void set_xml_node_value_from_bool(xmlNodePtr tmp_node, BOOL value)
{
    char tmp[XML_NODE_BUF_LEN] = {0};    
    memset ( tmp, 0, LONG_STRING_LEN);
    snprintf(tmp, LONG_STRING_LEN-1, "%s",BOOL_STR(value));
    xmlNodeSetContent(tmp_node, (const xmlChar *)tmp);
    DEBUG_VALUE(tmp_node);
}

void set_system_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr tmp_node = NULL; 
	
	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}
	tmp_node = pcurnode->children;
    while(tmp_node !=NULL)
	{
		if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_SYSTEM_NAME)) )
		{
            set_xml_node_value(tmp_node, (char *)afcconf->system.sys_name);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_SYSTEM_COUNTRY)))
		{
            set_xml_node_value(tmp_node, (char *)afcconf->system.country);
		}		
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_SYSTEM_TIMEOUT)))
		{
            set_xml_node_value_from_int(tmp_node, (int)afcconf->system.timeout);
		}
		tmp_node = tmp_node->next;
	}
	return;
}
void set_services_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr tmp_node = NULL;
	
	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}
	tmp_node = pcurnode->children;
    while(tmp_node !=NULL)
	{
		if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_SERVICES_AUTO_UPGRADE)) )
		{
            set_xml_node_value_from_bool(tmp_node, (BOOL)afcconf->services.auto_upgrade);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_SERVICES_STATUS_LED)))
		{
		    set_xml_node_value_from_bool(tmp_node, (BOOL)afcconf->services.status_led);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_SERVICES_BACK_SCAN)))
		{
		    set_xml_node_value_from_bool(tmp_node, (BOOL)afcconf->services.back_scan);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_SERVICES_LOAD_BALANCE)))
		{
		    set_xml_node_value_from_bool(tmp_node, (BOOL)afcconf->services.load_balance);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_SERVICES_NUM_PER_RADIO)))
		{
		    set_xml_node_value_from_uint(tmp_node, (unsigned int)afcconf->services.num_per_radio);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_SERVICES_UPNP_DISCOVERY)))
		{
		    set_xml_node_value_from_bool(tmp_node, (BOOL)afcconf->services.upnp_discovery);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_SERVICES_REMOTE_LOG)))
		{
		    set_xml_node_value_from_bool(tmp_node, (BOOL)afcconf->services.remote_log);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_SERVICES_LOG_SERVER_IP)))
		{
		    set_xml_node_value_from_ip_addr(tmp_node, (unsigned int)afcconf->services.log_server_ip);
		}		
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_SERVICES_REMOTE_LOG)))
		{
		    unsigned int tmpPort = (unsigned int)afcconf->services.log_server_port; 
            if(tmpPort)
            {
                set_xml_node_value_from_uint(tmp_node, (unsigned int)tmpPort);
            }
		}
		
		tmp_node = tmp_node->next;
	}
	return;
}

void set_mail_server_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr tmp_node = NULL; 
	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}
	tmp_node = pcurnode->children;
    while(tmp_node !=NULL)
	{
		if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_MAILSERVER_SERVER_ENABLED)) )
		{
            set_xml_node_value_from_bool(tmp_node, (BOOL)afcconf->mail_server.server_enabled);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_MAILSERVER_SERVER_ADDR)) )
		{
            set_xml_node_value(tmp_node, (char *)afcconf->mail_server.server_addr);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_MAILSERVER_SERVER_PORT)) )
		{
		    unsigned int tmpPort = (unsigned int)afcconf->mail_server.server_port; 
            if(tmpPort)
            {
                set_xml_node_value_from_uint(tmp_node, (unsigned int)tmpPort);
            }
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_MAILSERVER_ENABLE_SSL)) )
		{
            set_xml_node_value_from_bool(tmp_node, (BOOL)afcconf->mail_server.enable_ssl);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_MAILSERVER_AUTHENTICATION)))
		{
            set_xml_node_value_from_bool(tmp_node, (BOOL)afcconf->mail_server.authentication);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_MAILSERVER_AUTHEN_USER)) )
		{
            set_xml_node_value(tmp_node, (char *)afcconf->mail_server.authen_user);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_MAILSERVER_AUTHEN_PASS)) )
		{
            set_xml_node_value(tmp_node, (char *)afcconf->mail_server.authen_pass);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_MAILSERVER_SENDER_ADDR)) )
		{
            set_xml_node_value(tmp_node, (char *)afcconf->mail_server.sender_addr);
		}
		tmp_node = tmp_node->next;
	}
	return;
}
void set_interface_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr tmp_node = NULL; 
	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}
	tmp_node = pcurnode->children;
    while(tmp_node !=NULL)
	{
		
		if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_INTERFACE_NAME)) )
		{
            set_xml_node_value(tmp_node, (char *)afcconf->interface.intf_name);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_INTERFACE_IP)) )
		{
            set_xml_node_value_from_ip_addr(tmp_node, (unsigned int)afcconf->interface.intf_ip);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_INTERFACE_NET_MASK)))
		{
            set_xml_node_value_from_ip_addr(tmp_node, (unsigned int)afcconf->interface.net_mask);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_INTERFACE_GATEWAY)) )
		{
            set_xml_node_value_from_ip_addr(tmp_node, (unsigned int)afcconf->interface.gateway);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_INTERFACE_FIRST_DNS)) )
		{
            set_xml_node_value_from_ip_addr(tmp_node, (unsigned int)afcconf->interface.first_dns);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_INTERFACE_SECOND_DNS)) )
		{
            set_xml_node_value_from_ip_addr(tmp_node, (unsigned int)afcconf->interface.second_dns);
		}
		tmp_node = tmp_node->next;
	}
	return;
}
void set_user_group_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr tmp_node = NULL; 
	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}
	tmp_node = pcurnode->children;
    while(tmp_node !=NULL)
	{
		if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_USERGROUP_ID)) )
		{
            set_xml_node_value_from_uint(tmp_node, (unsigned int)afcconf->user_group.group_id);
		}
		
		tmp_node = tmp_node->next;
	}
	return;
}
void set_guest_policy_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr tmp_node = NULL; 
	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}
	tmp_node = pcurnode->children;
    while(tmp_node !=NULL)
	{
		if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_GUESTPOLICY_ID)) )
		{
            set_xml_node_value_from_uint(tmp_node, (unsigned int)afcconf->guest_policy.policy_id);
		}
		
		tmp_node = tmp_node->next;
	}
	return;
}
void set_block_list_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr tmp_node = NULL; 
	struct blist_node * tmp_bnode = NULL;
	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}
	tmp_node = pcurnode->children; 
	pcurnode->children = NULL;
	while(tmp_node !=NULL)
	{
        xmlNodePtr nextNode;  
        nextNode = tmp_node->next;  
        xmlUnlinkNode(tmp_node);  
        xmlFreeNode(tmp_node);  
        tmp_node = nextNode;
	}
	tmp_bnode = afcconf->block_list.head;
    while(tmp_bnode)
	{
	    char tmpMacStr[32] = {0};
	    snprintf(tmpMacStr, 31, "%02x:%02x:%02x:%02x:%02x:%02x", 
	        tmp_bnode->mac[0], tmp_bnode->mac[1], tmp_bnode->mac[2], 
	        tmp_bnode->mac[3], tmp_bnode->mac[4], tmp_bnode->mac[5]);
        tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_BLOCKLIST_MAC, 
            BAD_CAST tmpMacStr); 
		//set_xml_node_value(tmp_node, (char *)tmpMacStr);
		tmp_bnode = tmp_bnode->next;
	}
	return;
}
void set_wireless_global_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr tmp_node = NULL; 
	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}
	tmp_node = pcurnode->children;
    while(tmp_node !=NULL)
	{
		if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_WIRELESS_GLOBAL_WTP_AUTO_ACCESS)) )
		{
            set_xml_node_value_from_bool(tmp_node, (BOOL)afcconf->wireless_global.wtp_auto_access);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_GLOBAL_COUNTRY_CODE)) )
		{
            set_xml_node_value_from_int(tmp_node, (int)afcconf->wireless_global.country_code);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_GLOBAL_AUTO_OPTIM_POLICY)) )
		{
			set_xml_node_value(tmp_node, (char *)afcconf->wireless_global.auto_optim_policy);
		}

		tmp_node = tmp_node->next;
	}
	return;
}

void set_afi_policy_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr tmp_node = NULL; 
	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}
	tmp_node = pcurnode->children;


    while(tmp_node !=NULL)
	{
		if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_VERSION_UPDATE)) )
		{
            set_xml_node_value(tmp_node, (char *)afcconf->afi_policy.version_update);
		}
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_NET_ADAPTION)))
		{
            set_xml_node_value_from_bool(tmp_node, (BOOL)afcconf->afi_policy.net_adaption);
		}		
		else if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_ACCESS_CONTROL)))
		{
            set_xml_node_value_from_bool(tmp_node, (BOOL)afcconf->afi_policy.access_control);
		}

		tmp_node = tmp_node->next;
	}
	return;
}

void set_user_policy_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr tmp_node = NULL; 
	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}
	tmp_node = pcurnode->children;
    while(tmp_node !=NULL)
	{
		if( (!xmlStrcmp(tmp_node->name, BAD_CAST CONF_AUTO_OPTIM_POLICY)) )
		{
            set_xml_node_value(tmp_node, (char *)afcconf->user_policy.auto_optim_policy);
		}
		tmp_node = tmp_node->next;
	}
	return;
}
void set_map_detail_conf(xmlNodePtr pcurnode, struct map_conf * map_node)
{
	xmlNodePtr tmp_node = NULL;
	
	if (!pcurnode || !map_node)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p map_node %p", FUNC_LINE_VALUE, pcurnode, map_node);
	    return;
	}
	
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_MAP_NAME, BAD_CAST ""); 
	set_xml_node_value(tmp_node, (char *)map_node->name);
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_MAP_URL, BAD_CAST ""); 
	set_xml_node_value(tmp_node, (char *)map_node->url);
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_MAP_INIT_SCALE_UNIT, BAD_CAST ""); 
	set_xml_node_value(tmp_node, (char *)map_node->initscaleunit);
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_MAP_INIT_SCALE_METER, BAD_CAST ""); 
	set_xml_node_value_from_uint(tmp_node, (unsigned int)map_node->initscalemeter); 
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_MAP_INIT_SCALE_WIDTH, BAD_CAST ""); 
	set_xml_node_value_from_uint(tmp_node, (unsigned int)map_node->initscalewidth); 
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_MAP_SELECTED, BAD_CAST ""); 
	set_xml_node_value_from_bool(tmp_node, (BOOL)map_node->selected);

	return;
}
void set_maps_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr tmp_map = NULL; 
	struct map_conf *tmpMap = NULL;
	int i = 0;
	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}	
	
	for(i = START_MAPID; i <= MAX_MAP_ID; i++)
	{
	    tmpMap = afcconf->maps[i];
	    if(tmpMap)
	    {
    	    tmp_map = xmlNewNode(NULL, BAD_CAST CONF_MAP);
            DEBUG_NAME(tmp_map);
    	    set_map_detail_conf(tmp_map, tmpMap);
    	    xmlAddChild(pcurnode, tmp_map);
    	}
	}
	return;
}
void set_wlan_detail_conf(xmlNodePtr pcurnode, struct wlan_conf * wlan_node)
{
	xmlNodePtr tmp_node = NULL; 
	unsigned int tmpPort = 0;
	if(!pcurnode || !wlan_node)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p wlan_node %p", FUNC_LINE_VALUE, pcurnode, wlan_node);
	    return;
	}
	
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WLAN_ID, BAD_CAST ""); 
	set_xml_node_value_from_uint(tmp_node, (unsigned int)wlan_node->wlan_id);
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WLAN_SSID, BAD_CAST ""); 
	set_xml_node_value(tmp_node, (char *)wlan_node->wlan_ssid);
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WLAN_SERVICE, BAD_CAST ""); 
	set_xml_node_value_from_bool(tmp_node, (BOOL)wlan_node->wlan_service);
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WLAN_SEC_TYPE, BAD_CAST "");
	set_xml_node_value(tmp_node, (char *)SEC_TYPE_STR(wlan_node->sec_type));
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WLAN_ENCRY_TYPE, BAD_CAST "");
	set_xml_node_value(tmp_node, (char *)ENC_TYPE_STR(wlan_node->encry_type)); 
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WLAN_PASSPHRASE, BAD_CAST "");
	set_xml_node_value(tmp_node, (char *)wlan_node->passphrase); 
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WLAN_WEP_KEY, BAD_CAST ""); 
	set_xml_node_value(tmp_node, (char *)wlan_node->wep_key);
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WLAN_RADIUS_SECRET, BAD_CAST "");
	set_xml_node_value(tmp_node, (char *)wlan_node->radius_secret); 
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WLAN_RADIUS_IP, BAD_CAST ""); 
	set_xml_node_value_from_ip_addr(tmp_node, (unsigned int)wlan_node->radius_ip); 
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WLAN_RADIUS_PORT, BAD_CAST ""); 
    tmpPort = (unsigned int)wlan_node->radius_port;
    if(tmpPort)
    {
        set_xml_node_value_from_uint(tmp_node, (unsigned int)tmpPort);
    }
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WLAN_GUEST_ENABLED, BAD_CAST "");
	set_xml_node_value_from_bool(tmp_node, (BOOL)wlan_node->guest_enabled); 
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WLAN_VLAN_ENABLED, BAD_CAST ""); 
	set_xml_node_value_from_bool(tmp_node, (BOOL)wlan_node->vlan_enabled);
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WLAN_VLAN, BAD_CAST "");
	if(wlan_node->vlan)
	{
	    set_xml_node_value_from_uint(tmp_node, (unsigned int)wlan_node->vlan);  
	}
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WLAN_HIDDEN_SSID, BAD_CAST ""); 
	set_xml_node_value_from_bool(tmp_node, (BOOL)wlan_node->hidden_ssid);
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WLAN_WPA_MODE, BAD_CAST ""); 
	set_xml_node_value(tmp_node, (char *)WPA_MODE_STR(wlan_node->wpa_mode)); 
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WLAN_USER_GROUP_ID, BAD_CAST ""); 
	set_xml_node_value_from_uint(tmp_node, (unsigned int)wlan_node->user_group_id); 

	return;
}
void set_wlans_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr tmp_wlan = NULL; 
	struct wlan_conf *tmpWlan = NULL;
	int i = 0;
	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}	
	
	for(i = START_WLANID; i <= MAX_WLANID; i++)
	{
	    tmpWlan = afcconf->wlans[i];
	    if(tmpWlan)
	    {
    	    tmp_wlan = xmlNewNode(NULL, BAD_CAST CONF_WLAN);
            DEBUG_NAME(tmp_wlan);
    	    set_wlan_detail_conf(tmp_wlan, tmpWlan);
    	    xmlAddChild(pcurnode, tmp_wlan);
    	}
	}
	return;
}

void set_wtp_radio_wlan_conf(xmlNodePtr pcurnode, struct radio_wlan_conf *radio_wlan_node)
{
    xmlNodePtr tmp_node = NULL;
    if(!pcurnode || !radio_wlan_node)
    {
        syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p radio_node %p", FUNC_LINE_VALUE, pcurnode, radio_wlan_node);
        return;
    }
    
    tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_RADIO_WLAN_ID, BAD_CAST ""); 
    set_xml_node_value_from_uint(tmp_node, (unsigned int)radio_wlan_node->wlan_id);
    tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_RADIO_WLAN_ENABLED, BAD_CAST ""); 
    set_xml_node_value_from_bool(tmp_node, (BOOL)radio_wlan_node->wlan_enabled);
    tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_RADIO_WLAN_SSID, BAD_CAST ""); 
    set_xml_node_value(tmp_node, (char *)radio_wlan_node->wlan_essid);
    tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_RADIO_WLAN_SECURITY_KEY, BAD_CAST ""); 
    set_xml_node_value(tmp_node, (char *)radio_wlan_node->security_key);
    tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_RADIO_WLAN_VLAN_ENABLED, BAD_CAST ""); 
    set_xml_node_value_from_bool(tmp_node, (BOOL)radio_wlan_node->vlan_enabled);  
    tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_RADIO_WLAN_VLAN, BAD_CAST ""); 
    if(radio_wlan_node->vlan)
    {
        set_xml_node_value_from_uint(tmp_node, (unsigned int)radio_wlan_node->vlan);
    }
    
    return;
}

void set_wtp_radio_conf(xmlNodePtr pcurnode, struct radio_conf *radio_node)
{
    xmlNodePtr tmp_node = NULL;
	xmlNodePtr tmp_radio_wlan = NULL; 
	struct radio_wlan_conf *tmpRadioWlan = NULL;
	int i = 0;
    if(!pcurnode || !radio_node)
    {
        syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p radio_node %p", FUNC_LINE_VALUE, pcurnode, radio_node);
        return;
    }
    
    tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_RADIO_LOCAL_ID, BAD_CAST ""); 
    set_xml_node_value_from_uint(tmp_node, (unsigned int)radio_node->local_id);
    tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_RADIO_CHANNEL, BAD_CAST ""); 
    set_xml_node_value_from_uint(tmp_node, (unsigned int)radio_node->channel);
    tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_RADIO_CHANNEL_HT, BAD_CAST ""); 
    set_xml_node_value_from_uint(tmp_node, (unsigned int)radio_node->channel_ht);
    tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_RADIO_TX_POWER, BAD_CAST ""); 
    set_xml_node_value(tmp_node, (char *)TX_POWER_STR(radio_node->tx_power));
    tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_RADIO_CUSTOM_TX_POWER, BAD_CAST ""); 
    set_xml_node_value_from_uint(tmp_node, (unsigned int)radio_node->custom_tx_power);  
    tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_RADIO_MODE, BAD_CAST ""); 
    set_xml_node_value(tmp_node, (char *)RADIO_MODE_STR(radio_node->radio_mode));
    tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_RADIO_ANTENNA_GAIN, BAD_CAST ""); 
    set_xml_node_value_from_uint(tmp_node, (unsigned int)radio_node->antenna_gain);

    for(i = START_WLANID; i <= MAX_WLANID; i++)
    {
        tmpRadioWlan = radio_node->wlans[i];
        if(tmpRadioWlan)
        {
            tmp_radio_wlan = xmlNewNode(NULL, BAD_CAST CONF_WTP_RADIO_WLAN);
            DEBUG_NAME(tmp_radio_wlan);
            set_wtp_radio_wlan_conf(tmp_radio_wlan, tmpRadioWlan);
    	    xmlAddChild(pcurnode, tmp_radio_wlan);
	    }
    }

    return;
}

void set_wtp_network_conf(xmlNodePtr pcurnode, struct network_conf * network_node)
{
	xmlNodePtr tmp_node = NULL; 
	
	if(!pcurnode || !network_node)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p network_node %p", FUNC_LINE_VALUE, pcurnode, network_node);
	    return;
	}
	
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_NETWORK_MODE, BAD_CAST ""); 
	set_xml_node_value(tmp_node, (char *)NETWORK_MODE_STR(network_node->mode));
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_NETWORK_IP_ADDR, BAD_CAST ""); 
	set_xml_node_value_from_ip_addr(tmp_node, (unsigned int)network_node->ip_addr);
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_NETWORK_NET_MASK, BAD_CAST ""); 
	set_xml_node_value_from_ip_addr(tmp_node, (unsigned int)network_node->net_mask);
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_NETWORK_GATEWAY, BAD_CAST ""); 
	set_xml_node_value_from_ip_addr(tmp_node, (unsigned int)network_node->gateway);
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_NETWORK_FIRST_DNS, BAD_CAST ""); 
	set_xml_node_value_from_ip_addr(tmp_node, (unsigned int)network_node->first_dns);
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_NETWORK_SECOND_DNS, BAD_CAST ""); 
	set_xml_node_value_from_ip_addr(tmp_node, (unsigned int)network_node->second_dns);
}

void set_wtp_detail_conf(xmlNodePtr pcurnode, struct wtp_conf *wtp_node)
{
	xmlNodePtr tmp_node = NULL; 
	struct network_conf *network_node = NULL;
	struct radio_conf * radio_node = NULL;
	int i = 0;
	if(!pcurnode || !wtp_node)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p wtp_node %p", FUNC_LINE_VALUE, pcurnode, wtp_node);
	    return;
	}
	
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_ID, BAD_CAST ""); 
	set_xml_node_value_from_int(tmp_node, (unsigned int)wtp_node->wtp_id);
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_MODEL, BAD_CAST ""); 
	set_xml_node_value(tmp_node, (char *)wtp_node->wtp_model);
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_NAME, BAD_CAST ""); 
	set_xml_node_value(tmp_node, (char *)wtp_node->wtp_name);
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_MAC, BAD_CAST ""); 
	set_xml_node_value(tmp_node, (char *)wtp_node->wtp_mac);
	tmp_node = xmlNewTextChild(pcurnode, NULL, BAD_CAST CONF_WTP_SERVICE, BAD_CAST ""); 
	set_xml_node_value_from_bool(tmp_node, (BOOL)wtp_node->wtp_service);
	for(i = START_RADIO_NUM; i < MAX_RADIO_NUM; i++)
	{
	    radio_node = wtp_node->radios[i];
	    if(radio_node)
	    {
	        tmp_node = xmlNewNode(NULL, BAD_CAST CONF_WTP_RADIO);
            DEBUG_NAME(tmp_node);
	        set_wtp_radio_conf(tmp_node, radio_node);
	        xmlAddChild(pcurnode, tmp_node);
	    }
	}
	network_node = &(wtp_node->network);
    tmp_node = xmlNewNode(NULL, BAD_CAST CONF_WTP_NETWORK);
    DEBUG_NAME(tmp_node);
    set_wtp_network_conf(tmp_node, network_node);
	xmlAddChild(pcurnode, tmp_node);
	return;
}
void set_wtps_conf(xmlNodePtr pcurnode, afc_config_s * afcconf)
{
	xmlNodePtr tmp_wtp = NULL;
	struct wtp_conf *tmpWtp = NULL;
	int i = 0;
	if(!pcurnode || !afcconf)
	{
	    syslog(LOG_ERR, FUNC_LINE_FORMAT" Bad input argument pcurnode %p afcconf %p", FUNC_LINE_VALUE, pcurnode, afcconf);
	    return;
	}
	
	for(i = START_WTPID; i <= MAX_WTP_ID; i++)
	{
	    tmpWtp = afcconf->wtps[i];
	    if(tmpWtp)
	    {
    	    tmp_wtp = xmlNewNode(NULL, BAD_CAST CONF_WTP);
            DEBUG_NAME(tmp_wtp);
    	    set_wtp_detail_conf(tmp_wtp, tmpWtp);
    	    xmlAddChild(pcurnode, tmp_wtp);
    	}
	}
	return;
}

xmlNodePtr remove_conf_node(xmlNodePtr pcurnode)
{
    xmlNodePtr nextNode;  
    nextNode = pcurnode->next;  
    xmlUnlinkNode(pcurnode);  
    xmlFreeNode(pcurnode); 
    return nextNode;
}

int write_afc_config_to_conf_file(char * pathFile, afc_config_s * afcconf)
{
	xmlDocPtr doc;
	xmlNodePtr rootnode; 
	xmlNodePtr pcurnode; 
    if(!pathFile || !afcconf)
    {
        syslog(LOG_ERR, "write afc config error, Bad input argument: path/file %p afcconf %p", pathFile, afcconf);
        return -1;
    }
	doc = xmlReadFile(pathFile, "utf-8", XML_PARSE_NOBLANKS/*256*/); //XML_PARSE_NOBLANKS
	if (doc == NULL ) 
	{
      		return -1;
	}
	rootnode = xmlDocGetRootElement(doc);

	if (!rootnode /*xmlStrcmp(cur->name, (const xmlChar *) "root")*/) /*ignore the super node name*/
	{
		xmlFreeDoc(doc);
		return -1;
    }
    DEBUG_NAME(rootnode);
	pcurnode = rootnode->xmlChildrenNode;
	
	while(pcurnode != NULL) 
	{
		if (!xmlStrcmp(pcurnode->name, BAD_CAST CONF_SYSTEM))
	  	{
            DEBUG_NAME(pcurnode);
	  		set_system_conf(pcurnode, afcconf);
		}
		else if (!xmlStrcmp(pcurnode->name, BAD_CAST CONF_SERVICES))
	  	{
            DEBUG_NAME(pcurnode);
	  		set_services_conf(pcurnode, afcconf);
		}
		else if (!xmlStrcmp(pcurnode->name, BAD_CAST CONF_MAILSERVER))
	  	{
            DEBUG_NAME(pcurnode);
	  		set_mail_server_conf(pcurnode, afcconf);
		}
		else if (!xmlStrcmp(pcurnode->name, BAD_CAST CONF_INTERFACE))
	  	{
            DEBUG_NAME(pcurnode);
	  		set_interface_conf(pcurnode, afcconf);
		}
		else if (!xmlStrcmp(pcurnode->name, BAD_CAST CONF_USERGROUP))
	  	{
            DEBUG_NAME(pcurnode);
	  		set_user_group_conf(pcurnode, afcconf);
		}
		else if (!xmlStrcmp(pcurnode->name, BAD_CAST CONF_GUESTPOLICY))
	  	{
            DEBUG_NAME(pcurnode);
	  		set_guest_policy_conf(pcurnode, afcconf);
		}
		else if (!xmlStrcmp(pcurnode->name, BAD_CAST CONF_BLOCKLIST))
	  	{
            DEBUG_NAME(pcurnode);
	  		set_block_list_conf(pcurnode, afcconf);
		}
		else if (!xmlStrcmp(pcurnode->name, BAD_CAST CONF_WIRELESS_GLOBAL))
	  	{
            DEBUG_NAME(pcurnode);
	  		set_wireless_global_conf(pcurnode, afcconf);
		}
		else if (!xmlStrcmp(pcurnode->name, BAD_CAST CONF_USER_POLICY))
	  	{
            DEBUG_NAME(pcurnode);
	  		set_user_policy_conf(pcurnode, afcconf);
		}
		else if (!xmlStrcmp(pcurnode->name, BAD_CAST CONF_AFI_POLICY))
	  	{
            DEBUG_NAME(pcurnode);
	  		set_afi_policy_conf(pcurnode, afcconf);
		}
		else if( (!xmlStrcmp(pcurnode->name, BAD_CAST CONF_MAP)) )
	    {
            pcurnode = remove_conf_node(pcurnode);
            continue;
	    }
		else if( (!xmlStrcmp(pcurnode->name, BAD_CAST CONF_WLAN)) )
	    {
            pcurnode = remove_conf_node(pcurnode);
            continue;
	    }
		else if( (!xmlStrcmp(pcurnode->name, BAD_CAST CONF_WTP)) )
	    {
            pcurnode = remove_conf_node(pcurnode);
            continue;
	    }
	
	   pcurnode = pcurnode->next;
	}
	set_maps_conf(rootnode, afcconf);
	set_wlans_conf(rootnode, afcconf);
	set_wtps_conf(rootnode, afcconf);
    
    xmlSaveFormatFile(pathFile, doc, 1); 
    
	xmlFreeDoc(doc);
	return 0;
}

int save_config_info(afc_config_s * afcconf)
{
    int ret = 0;
    char * filePathName = XML_CONFIG_FILE_NAME;
    ret = write_afc_config_to_conf_file(filePathName, afcconf);
    return ret;
}
afc_config_s * get_config_info()
{
    char * filePathName = XML_CONFIG_FILE_NAME;
    if(!global_config_info)
    {
        if(!filePathName)
        {
            return NULL;
        }
        global_config_info = (afc_config_s *)malloc(sizeof(afc_config_s));
        if(!global_config_info)
        {
            return NULL;
        }
        memset(global_config_info, 0, sizeof(afc_config_s));
        
    }
    else
    {
        destroy_afc_conf(global_config_info, NOT_FREE_AFC);
    }
    read_afc_config_from_conf_file(filePathName, global_config_info);
    return global_config_info;
}
#if 0
int modify_wireless_global_save_config(struct wireless_global_conf * wireless_g_node)
{
	afc_config_s * afcconf = NULL;
	
	int ret = -1;

	if(!wireless_g_node)
	{
	    return -1;
	}
	
    afcconf = get_config_info();

    if(afcconf)
    {
        memcpy(&(afcconf->wireless_global), wireless_g_node, sizeof(struct wireless_global_conf));
        
        ret = save_config_info(afcconf);
    }
    else
    {
        syslog(LOG_ERR, FUNC_LINE_FORMAT" failed to get config info !", FUNC_LINE_VALUE);
        
        return -1;
    }
    
    return ret;
}

int config_wtp_radios_save_config()
{
}

int config_wtp_network_save_config(unsigned int wtp_id, struct network_conf * network_conf)
{
#ifdef SAVE_WTP_NETWORK_TO_CONFIG

	afc_config_s * afcconf = NULL;
	
	int ret = -1;
	
	if(!network_conf)
	{
	    return -1;
	}
	
    afcconf = get_config_info();

    if(afcconf)
    {
        memcpy(&(afcconf->wtps[wtp_id]->network), network_conf, sizeof(struct network_conf));
        
        ret = save_config_info(afcconf);
    }
    else
    {
        syslog(LOG_ERR, FUNC_LINE_FORMAT" failed to get config info !", FUNC_LINE_VALUE);
        
        return -1;
    }
    
    return ret;
#else

    return 0;/*do nothing */

#endif
}

int config_wtp_radio_wlans_save_config()
{
    
}
#endif
#ifdef CONF_TEST_MAIN
int main()
{
    char *filePathName = "../web/xml_php.xml";
    unsigned char testMac[MAC_LEN] = {0x11,0x22,0x33,0x44,0x55,0x66};
    afc_config_s * afcconf = (afc_config_s *)malloc(sizeof(afc_config_s));
    struct wlan_conf * testWlan = NULL;
    if(!afcconf)
    {
        return -1;
    }
    memset(afcconf, 0, sizeof(afc_config_s));
    read_afc_config_from_conf_file(filePathName, afcconf);
    insert_node(&(afcconf->block_list), (unsigned char *)testMac);
    
    if(!afcconf->wlans[5])
    {
        testWlan = (struct wlan_conf *)malloc(sizeof(struct wlan_conf));
        if(testWlan)
        {
            memset(testWlan, 0, sizeof(struct wlan_conf));
            testWlan->wlan_id = 5;
            testWlan->sec_type = 1;
            afcconf->wlans[5] = testWlan;
        }
    }
    else
    {
        afcconf->wlans[5]->sec_type+=1;
    }
    write_afc_config_to_conf_file(filePathName, afcconf);

    destroy_afc_conf(afcconf, FREE_AFC);
    afcconf = NULL;
    return 0;
}
#endif
