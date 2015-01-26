#ifndef _PHP_EXT_HISTORY_H
#define _PHP_EXT_HISTORY_H

#define    AFI_NUM             16
#define    TM_FORMAT_STRING    "%d-%d-%d %d:%d:%d"

typedef enum _tagTM_FLAGS {
	CAL_BY_UNKOWN = -1,
	CAL_BY_HOUR,
	CAL_BY_DAY
}TM_FLAGS_E;

typedef enum _tagBASE_NOTATION
{
	LOCAL_24HR = 24,
	LOCAL_30DAY = 30,
	
}BASE_NOTATION_E;


typedef struct _tagTM_FORMAT {
	int year;
	int month;
	int day;
	int hour;
	int minute;
	int second;
}TM_FORMAT_OBJ, *TM_FORMAT_HANDLE;

void ext_show_history_handle(int argc, zval ***argv, zval *return_value);



EXT_FUNCTION(ext_history_ap_info);
EXT_FUNCTION(ext_history_afi_info);
EXT_FUNCTION(ext_history_sys_score_info);
EXT_FUNCTION(ext_history_usr_detail);
EXT_FUNCTION(ext_history_wireless_info);
EXT_FUNCTION(ext_history_flow_info);
EXT_FUNCTION(ext_history_wifi_info);
EXT_FUNCTION(ext_history_terminal_info);


#endif
