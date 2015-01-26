#ifndef _PHP_EXT_FUNCPUBLIC_H_
#define _PHP_EXT_FUNCPUBLIC_H_

//#include "ws_init_dbus.h"
//#include "ws_dbus_list_interface.h"

//#define VE_SUB_INTERFACE_NAME_MIN	(strlen("ve09f1.1")) /*>= 8 byte*/
//#define OTHER_INTERFACE				0
//#define VE_INTERFACE 		   		3/*vex*/
//#define VE_SUB_INTERFACE 		    4/*vex.xx*/

struct php_langlist                              /*链表结构*/
{
	char val[256];                           /*存放变量及其对应值*/
	struct php_langlist *next;                     /*指向下一节点的指针*/
};  

enum php_result_no_e {
	ANALYSIS_SLOTID_INSID_FAIL = 1000,		
	SECURITY_ID_ILLEGAL,
	WLAN_ID_ILLEGAL,
	WTP_ID_ILLEGAL,
	RADIO_ID_ILLEGAL,	
	INPUT_PARA_NULL,
	INPUT_PARA_ILLEGAL,
	INPUT_PARA_EXCEED_MAX_VALUE,
	PHP_FAILED_GET_REPLY,
	PHP_OBJ_INIT_FAIL	
};

enum {
	LANG_EN,
	LANG_CH
};

void ext_funcpublic_handle(int argc, zval ***argv, zval *return_value);

EXT_FUNCTION(ext_get_chain_head);  
EXT_FUNCTION(ext_delete_garbage_session_file);  

//EXT_FUNCTION(ext_set_wireless_network);
//EXT_FUNCTION(ext_set_guest_wireless_network);
void delete_enter(char * string);

#endif
