#ifndef _AFC_CONF_H_
#define _AFC_CONF_H_

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpathInternals.h>

#define CONF_DEBUG_ENABLE 0
#define BLOCK_LIST_DEBUG 1

#define XML_CONFIG_FILE_NAME "/opt/run/afcconf/xml_php.xml"

#ifndef BAD_CAST
#define BAD_CAST (const xmlChar *)
#endif

#if CONF_DEBUG_ENABLE
#define DEBUG_VALUE(testnode) syslog(LOG_DEBUG, FUNC_LINE_FORMAT"        %s : %s ", FUNC_LINE_VALUE, (char *)((testnode)->name), (char *)xmlNodeGetContent((testnode)))
#define DEBUG_NAME(testnode) syslog(LOG_DEBUG, FUNC_LINE_FORMAT" %s ", FUNC_LINE_VALUE, (char *)((testnode)->name))
#define DEBUG_TRACE()
#else
#define DEBUG_VALUE(testnode) 
#define DEBUG_NAME(testnode)
#endif
#define BLIST_HASH_LEN 64
#define XML_NODE_BUF_LEN 128
#define FUNC_LINE_FORMAT "%s-%d"
#define FUNC_LINE_VALUE __func__,__LINE__
#define BOOL_STR(i) (i?"true":"false")
#ifndef BOOL
#define BOOL unsigned char
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#define MAC_LEN 6
#define START_WLANID 1
#define START_WTPID 1
#define START_MAPID 1
#define MAX_WLANID 16
#define MAX_WTP_ID 10
#define MAX_MAP_ID 10
#define START_RADIO_NUM 0
#define MAX_RADIO_NUM 4
#define INVALID_RADIO_NUM 0xFF
#define LONG_STRING_LEN 128
#define MID_STRING_LEN 64
#define SHORT_STRING_LEN 32
#define INTF_NAME_LEN 32

#define TX_POWER_LEVEL_NUM 5
#define RADIO_MODE_TYPE 5
#define WPA_MODE_TYPE 3
#define NETWORK_MODE_TYPE 3
#define SEC_TYPE_TYPE 4
#define ENC_TYPE_TYPE 3

#define TX_POWER_STR(index) (((index) < TX_POWER_LEVEL_NUM)?tx_power_level[(index)]:"auto")
#define RADIO_MODE_STR(index) (((index) < TX_POWER_LEVEL_NUM)?radio_mode_select[(index)]:"auto")
#define WPA_MODE_STR(index) (((index) < WPA_MODE_TYPE)?wpa_mode_select[(index)]:"auto")
#define NETWORK_MODE_STR(index) (((index) < NETWORK_MODE_TYPE)?network_mode_select[(index)]:"")
#define SEC_TYPE_STR(index) (((index) < SEC_TYPE_TYPE)?sec_type_select[(index)]:"")
#define ENC_TYPE_STR(index) (((index) < ENC_TYPE_TYPE)?enc_type_select[(index)]:"auto")

enum FREE_AFC_FLAG
{
    NOT_FREE_AFC = 0,
    FREE_AFC =1,
};
enum TX_POWER_LEVEL{
	TX_POWER_AUTO = 0,
	TX_POWER_LOW = 1,
	TX_POWER_MEDIUM = 2,
	TX_POWER_HIGH = 3,
	TX_POWER_CUSTOM = 4,
};
enum NETWORK_MODE{
    NETWORK_MODE_NONE = 0,
    STATIC = 1,
    DHCP = 2,
};
enum WPA_MODE{
    WPA_MODE_AUTO = 0,
    WPA_MODE_WPA1 = 1,
    WPA_MODE_WPA2 = 2,
};
enum RADIO_MODE{
    RADIO_MODE_AUTO = 0,
    RADIO_MODE_NG = 1,
    RADIO_MODE_NA = 2,
    RADIO_MODE_AC = 3,
};
enum SEC_TYPE{
    SEC_TYPE_OPEN = 0,
    SEC_TYPE_WEP = 1,
    SEC_TYPE_WPA_P = 2,
    SEC_TYPE_WPA_E = 3,
};
enum ENC_TYPE{
    ENC_TYPE_AUTO = 0,
    ENC_TYPE_TKIP = 1,
    ENC_TYPE_AES = 2,
};

struct system_conf{
	char sys_name[MID_STRING_LEN];
	char country[MID_STRING_LEN];
	int timeout;
};
struct services_conf{
	unsigned int log_server_ip;
	unsigned short log_server_port;
	BOOL upnp_discovery;
	BOOL remote_log;
	BOOL auto_upgrade;
	BOOL status_led;
	BOOL back_scan;
	BOOL load_balance;
	unsigned char num_per_radio;
	char pad[3];
};
struct mail_server_conf{
	char server_addr[LONG_STRING_LEN];
	char authen_user[MID_STRING_LEN];
	char authen_pass[MID_STRING_LEN];
	char sender_addr[MID_STRING_LEN];
	unsigned short server_port;
	BOOL enable_ssl;
	BOOL authentication;
	BOOL server_enabled;
	char pad[3];
};
struct interface_conf{
	char intf_name[INTF_NAME_LEN];
	unsigned int intf_ip;
	unsigned int net_mask;
	unsigned int gateway;
	unsigned int first_dns;
	unsigned int second_dns;
	char pad[4];
};
struct map_conf{
	char 	name[MID_STRING_LEN];/* map name */
	char	url[LONG_STRING_LEN];/* map picture url */
	char	initscaleunit[8];/* m, cm, km */
	unsigned int   initscalemeter;/* m/cm/km value */
	unsigned int  initscalewidth;/* the width of scale when zoom is 100% */
	BOOL    selected;/* selected map after page load */
};
struct user_group_conf{
	unsigned int group_id;
	char pad[4];
};
struct guest_policy_conf{
	unsigned int policy_id;
	char pad[4];
};
struct blist_node{
	struct blist_node * next;
	struct blist_node * hnext;
	unsigned char mac[MAC_LEN];
	char pad[2];
};
struct block_list_conf{
	unsigned int num;
	char pad[4];
	struct blist_node *head;
	struct blist_node *tail;
	struct blist_node *hash[BLIST_HASH_LEN];
};
struct afi_blist_conf{
	struct block_list_conf blist_conf;
};
struct user_blist_conf{
	struct block_list_conf blist_conf;
};
struct wireless_global_conf{
	BOOL wtp_auto_access;
	char pad[7];
    //himgod
	int country_code;
	char auto_optim_policy[MID_STRING_LEN];
};

struct afi_policy_conf{
	char version_update[MID_STRING_LEN];
	BOOL net_adaption;
	BOOL access_control;
};

struct user_policy_conf{
	char auto_optim_policy[MID_STRING_LEN];	
};
struct wlan_conf{
	unsigned int wlan_id;
	unsigned int user_group_id;
	unsigned int radius_ip;
	unsigned short radius_port;
	unsigned short vlan;
	char wlan_ssid[SHORT_STRING_LEN];
	char passphrase[LONG_STRING_LEN];
	char wep_key[LONG_STRING_LEN];
	char radius_secret[LONG_STRING_LEN];
	BOOL wlan_service;
	BOOL guest_enabled;
	BOOL vlan_enabled;
	BOOL hidden_ssid;
	unsigned char sec_type;
	unsigned char encry_type;
	unsigned char wpa_mode;
	unsigned char wep_index;
};
struct radio_wlan_conf{
	unsigned int wlan_id;
	unsigned short vlan;
	BOOL wlan_enabled;
	BOOL vlan_enabled;
	char wlan_essid[SHORT_STRING_LEN];
	char security_key[MID_STRING_LEN];
};
struct radio_conf{
	unsigned int local_id;
	unsigned char channel;
	unsigned char channel_ht;
	unsigned char tx_power;//auto, low, medium, high, custom 
	unsigned char custom_tx_power;
	unsigned char radio_mode;
	unsigned char antenna_gain;
	char pad[2];
	struct radio_wlan_conf * wlans[MAX_WLANID+1];// NULL or override config
};
struct network_conf{
	unsigned int mode;/*0 none , 1 static , 2 dhcp*/
	unsigned int ip_addr;
	unsigned int net_mask;
	unsigned int gateway;
	unsigned int first_dns;
	unsigned int second_dns;
};
struct wtp_conf{
	unsigned int wtp_id;
	BOOL wtp_service;
	char pad[3];
	char wtp_model[SHORT_STRING_LEN];
	char wtp_name[MID_STRING_LEN];
	char wtp_mac[SHORT_STRING_LEN];
	char mapname[MID_STRING_LEN];
	unsigned int mapleft;
	unsigned int maptop;
	BOOL maplock;
	struct radio_conf *radios[MAX_RADIO_NUM];
	struct network_conf network;
};

#define CONF_SYSTEM "system"
#define CONF_SYSTEM_NAME "sys_name"
#define CONF_SYSTEM_COUNTRY "country"
#define CONF_SYSTEM_TIMEOUT "timeout"
#define CONF_SERVICES "services"
#define CONF_SERVICES_AUTO_UPGRADE "auto_upgrade"
#define CONF_SERVICES_STATUS_LED "status_led"
#define CONF_SERVICES_BACK_SCAN "back_scan"
#define CONF_SERVICES_LOAD_BALANCE "load_balance"
#define CONF_SERVICES_NUM_PER_RADIO "num_per_radio"
#define CONF_SERVICES_UPNP_DISCOVERY "upnp_discovery"
#define CONF_SERVICES_REMOTE_LOG "remote_log"
#define CONF_SERVICES_LOG_SERVER_IP "log_server_ip"
#define CONF_SERVICES_LOG_SERVER_PORT "log_server_port"
#define CONF_MAILSERVER "mail_server"
#define CONF_MAILSERVER_SERVER_ENABLED "server_enabled"
#define CONF_MAILSERVER_SERVER_ADDR "server_addr"
#define CONF_MAILSERVER_SERVER_PORT "server_port"
#define CONF_MAILSERVER_ENABLE_SSL "enable_ssl"
#define CONF_MAILSERVER_AUTHENTICATION "authentication"
#define CONF_MAILSERVER_AUTHEN_USER "authen_user"
#define CONF_MAILSERVER_AUTHEN_PASS "authen_pass"
#define CONF_MAILSERVER_SENDER_ADDR "sender_addr"
#define CONF_INTERFACE "interface"
#define CONF_INTERFACE_NAME "intf_name"
#define CONF_INTERFACE_IP "intf_ipaddr"
#define CONF_INTERFACE_NET_MASK "intf_netmask"
#define CONF_INTERFACE_GATEWAY "intf_gateway"
#define CONF_INTERFACE_FIRST_DNS "intf_firstdns"
#define CONF_INTERFACE_SECOND_DNS "intf_seconddns"
#define CONF_USERGROUP "user_group"
#define CONF_USERGROUP_ID "group_id"
#define CONF_GUESTPOLICY "guest_policy"
#define CONF_GUESTPOLICY_ID "policy_id"
#define CONF_BLOCKLIST "block_list"
#define CONF_BLOCKLIST_MAC "mac"
#define CONF_WIRELESS_GLOBAL "wireless_global"
#define CONF_WIRELESS_GLOBAL_WTP_AUTO_ACCESS "wtp_auto_access"
#define CONF_GLOBAL_COUNTRY_CODE "country_code"
#define CONF_GLOBAL_AUTO_OPTIM_POLICY "auto_optim_policy"

#define CONF_AFI_POLICY "afi_policy"
#define CONF_VERSION_UPDATE "version_update"
#define CONF_NET_ADAPTION "net_adaption"
#define CONF_ACCESS_CONTROL "access_control"

#define CONF_USER_POLICY "user_policy"
#define CONF_AUTO_OPTIM_POLICY "auto_optim_policy"

#define CONF_AFI_BLACKLIST "afi_blacklist"
#define CONF_USER_BLACKLIST "user_blacklist"

#define CONF_MAP "map"
#define CONF_MAP_NAME "name"
#define CONF_MAP_URL "url"
#define CONF_MAP_INIT_SCALE_UNIT "initscaleunit"
#define CONF_MAP_INIT_SCALE_METER "initscalemeter"
#define CONF_MAP_INIT_SCALE_WIDTH "initscalewidth"
#define CONF_MAP_SELECTED "selected"
#define CONF_WLAN "wlan"
#define CONF_WLAN_ID "wlan_id"
#define CONF_WLAN_SSID "wlan_ssid"
#define CONF_WLAN_SERVICE "wlan_service"
#define CONF_WLAN_SEC_TYPE "sec_type"
#define CONF_WLAN_ENCRY_TYPE "encry_type"
#define CONF_WLAN_PASSPHRASE "passphrase"
#define CONF_WLAN_WEP_KEY "wep_key"
#define CONF_WLAN_RADIUS_SECRET "radius_secret"
#define CONF_WLAN_RADIUS_IP "radius_ip"
#define CONF_WLAN_RADIUS_PORT "radius_port"
#define CONF_WLAN_GUEST_ENABLED "guest_enabled"
#define CONF_WLAN_VLAN_ENABLED "vlan_enabled"
#define CONF_WLAN_VLAN "vlan"
#define CONF_WLAN_HIDDEN_SSID "hidden_ssid"
#define CONF_WLAN_WPA_MODE "wpa_mode"
#define CONF_WLAN_USER_GROUP_ID "user_group_id"
#define CONF_WTP "wtp"
#define CONF_WTP_ID "wtp_id"
#define CONF_WTP_MODEL "wtp_model"
#define CONF_WTP_NAME "wtp_name"
#define CONF_WTP_MAC "wtp_mac"
#define CONF_WTP_SERVICE "wtp_service"
#define CONF_WTP_MAPNAME "mapname"
#define CONF_WTP_MAPLEFT "mapleft"
#define CONF_WTP_MAPTOP "maptop"
#define CONF_WTP_MAPLOCK "maplock"
#define CONF_WTP_RADIO "radio"
#define CONF_WTP_RADIO_LOCAL_ID "local_id"
#define CONF_WTP_RADIO_CHANNEL "channel"
#define CONF_WTP_RADIO_CHANNEL_HT "channel_ht"
#define CONF_WTP_RADIO_TX_POWER "tx_power"
#define CONF_WTP_RADIO_CUSTOM_TX_POWER "custom_tx_power"
#define CONF_WTP_RADIO_MODE "radio_mode"
#define CONF_WTP_RADIO_ANTENNA_GAIN "antenna_gain"
#define CONF_WTP_RADIO_WLAN "radio_wlan"
#define CONF_WTP_RADIO_WLAN_ID "wlan_id"
#define CONF_WTP_RADIO_WLAN_ENABLED "wlan_enabled"
#define CONF_WTP_RADIO_WLAN_SSID "wlan_ssid"
#define CONF_WTP_RADIO_WLAN_SECURITY_KEY "security_key"
#define CONF_WTP_RADIO_WLAN_VLAN_ENABLED "vlan_enabled"
#define CONF_WTP_RADIO_WLAN_VLAN "vlan"
#define CONF_WTP_NETWORK "network"
#define CONF_WTP_NETWORK_MODE "mode"
#define CONF_WTP_NETWORK_IP_ADDR "ip_addr"
#define CONF_WTP_NETWORK_NET_MASK "net_mask"
#define CONF_WTP_NETWORK_GATEWAY "gateway"
#define CONF_WTP_NETWORK_FIRST_DNS "first_dns"
#define CONF_WTP_NETWORK_SECOND_DNS "second_dns"


typedef struct afc_config{
	struct system_conf system;
	struct services_conf services;
	struct mail_server_conf mail_server;
	struct interface_conf interface;
	struct user_group_conf user_group;
	struct guest_policy_conf guest_policy;
	//struct block_list_conf block_list;
	struct afi_blist_conf afi_blist;
	struct user_blist_conf user_blist;
	struct wireless_global_conf wireless_global;
	struct afi_policy_conf afi_policy;
	struct user_policy_conf user_policy;
	struct wlan_conf *wlans[MAX_WLANID+1];
	struct wtp_conf  *wtps[MAX_WTP_ID+1];	
	struct map_conf  *maps[MAX_MAP_ID+1];
} afc_config_s;

void get_system_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void get_services_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void get_mail_server_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void get_interface_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void get_user_group_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void get_guest_policy_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);

struct blist_node *insert_node(struct block_list_conf * block_hash, unsigned char * mac);
BOOL remove_node(struct block_list_conf * block_hash, unsigned char * mac);
struct blist_node * find_blist_node(struct block_list_conf * block_hash, unsigned char * mac);
void destroy_block_list(struct block_list_conf * block_hash);
//void get_block_list_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void get_user_block_list_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void get_afi_block_list_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void get_wireless_global_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void get_afi_policy_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void get_user_policy_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);

//TODO
void get_afi_blacklist_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void get_user_blacklist_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);

void destroy_map_node(struct map_conf * map_node);
void get_map_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void destroy_wlan_node(struct wlan_conf * wlan_node);
void get_wlan_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void get_guest_wlan_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void destroy_radio_wlan(struct radio_wlan_conf * radio_wlan);
void destroy_wtp_radio(struct radio_conf * wtp_radio);
void destroy_wtp_node(struct wtp_conf * wtp_node);
void destroy_afc_conf(afc_config_s * afcconf, int freeafc);
void get_radio_wlans_conf(xmlNodePtr pcurnode, struct radio_conf * wtp_radio);
void get_wtp_radio_conf(xmlNodePtr pcurnode, struct wtp_conf *wtp_node);
void get_wtp_network_conf(xmlNodePtr pcurnode, struct wtp_conf *wtp_node);
void get_guest_wtp_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
int read_afc_config_from_conf_file(char * pathFile, afc_config_s * afcconf);
void set_xml_node_value(xmlNodePtr tmp_node, char * value);
void set_xml_node_value_from_int(xmlNodePtr tmp_node, int value);
void set_xml_node_value_from_uint(xmlNodePtr tmp_node, unsigned int value);
void set_xml_node_value_from_ip_addr(xmlNodePtr tmp_node, unsigned int value);
void set_xml_node_value_from_bool(xmlNodePtr tmp_node, BOOL value);
void set_system_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void set_services_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void set_mail_server_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void set_interface_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void set_user_group_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void set_guest_policy_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
//void set_block_list_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void set_user_block_list_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void set_afi_block_list_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);

void set_wireless_global_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void set_afi_policy_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void set_user_policy_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
//TODO
void set_afi_blacklist_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void set_user_blacklist_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);

void set_map_detail_conf(xmlNodePtr pcurnode, struct map_conf * map_node);
void set_maps_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void set_wlan_detail_conf(xmlNodePtr pcurnode, struct wlan_conf * wlan_node);
void set_wlans_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
void set_wtp_radio_wlan_conf(xmlNodePtr pcurnode, struct radio_wlan_conf *radio_wlan_node);
void set_wtp_radio_conf(xmlNodePtr pcurnode, struct radio_conf *radio_node);
void set_wtp_network_conf(xmlNodePtr pcurnode, struct network_conf * network_node);
void set_wtp_detail_conf(xmlNodePtr pcurnode, struct wtp_conf *wtp_node);
void set_wtps_conf(xmlNodePtr pcurnode, afc_config_s * afcconf);
xmlNodePtr remove_conf_node(xmlNodePtr pcurnode);
int write_afc_config_to_conf_file(char * pathFile, afc_config_s * afcconf);

afc_config_s * get_config_info();
int save_config_info(afc_config_s * afcconf);
void destroy_map_node(struct map_conf * map_node);

#endif

