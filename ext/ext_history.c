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

#include "ext_history.h"
#include "DAO.h"


#define   RANDOM

ext_func_handle_t ext_show_history_list[] = 
{
	{"get_ap_info", 2, (php_func_t)ext_history_ap_info},
	{"get_afi_info", 1, (php_func_t)ext_history_afi_info},
	{"get_sys_score_info", 2, (php_func_t)ext_history_sys_score_info},
	{"get_usr_detail_info", 1, (php_func_t)ext_history_usr_detail},
	{"get_wireless_info", 3, (php_func_t)ext_history_wireless_info},
	{"get_flow_info", 2, (php_func_t)ext_history_flow_info},
	{"get_wifi_info", 2, (php_func_t)ext_history_wifi_info},
	{"get_terminal_info", 2, (php_func_t)ext_history_terminal_info},
};



void ext_show_history_handle(int argc, zval ***argv, zval *return_value)
{
    int count = sizeof(ext_show_history_list)/sizeof(ext_show_history_list[0]);
    ext_function_handle(argc, argv, return_value, count, ext_show_history_list);
}

int get_ap_info_demo(query_ap_info *ap_info_demo, int tm_type)
{
	if (NULL == ap_info_demo) {
		return -1;
	}
	int i;
	
	ap_info_demo->num_rows = tm_type;
	ap_info_demo->apInfo = (ap_info *)malloc(ap_info_demo->num_rows * sizeof(ap_info));
	if (NULL == ap_info_demo->apInfo) {
		syslog(LOG_ERR, "get_ap_info_demo: malloc error!");
		return -1;
	}
	srand(time(NULL));
	for (i = 0; i < ap_info_demo->num_rows; i++) {
		if (tm_type > 24)
			sprintf(ap_info_demo->apInfo[i].collect_timestamp, TM_FORMAT_STRING, 2014, 12, i, 0, 10, 11);
		else
			sprintf(ap_info_demo->apInfo[i].collect_timestamp, TM_FORMAT_STRING, 2014, 12, 22, i, 10, 11);
		ap_info_demo->apInfo[i].down_up_BW = rand () % 100;
		ap_info_demo->apInfo[i].signal_intensity = rand() % 100;
		ap_info_demo->apInfo[i].time_delay = rand() % 100;
	}

	return 0;
}


EXT_FUNCTION(ext_history_ap_info)
{
	int rtval = -1, i;
	TM_FLAGS_E tm_flag = CAL_BY_UNKOWN;
	TM_FORMAT_OBJ tm;
	query_ap_info ap_info_obj;
	int ap_info_cnt = 0, collect_point_cnt = 0;
	int tmp_tm_val = 0, tm_val = 0;

	zval *iter, *iter_array;
	MAKE_STD_ZVAL(iter);
	array_init(iter);
	zval *iter_len;
	MAKE_STD_ZVAL(iter_len);
	array_init(iter_len);

	int bw = 0, sig_intens = 0, tm_delay;

	//recv the printing format of time;
	ext_para_get(argc, argv, EXT_TYPE_LONG, &tm_flag);

	syslog(LOG_ERR, "TM TYPE IS %d, AP", tm_flag);
#ifndef RANDOM
	switch (tm_flag) {
			case CAL_BY_HOUR:
				rtval = db_get_ap_index_info_within_24h(NULL, &ap_info_obj);
				if (rtval < 0) {
					syslog(LOG_ERR, "db_get_ap_index_info_within_24h: error!");
					RETURN_LONG(rtval);
				}
				sscanf(ap_info_obj.apInfo[0].collect_timestamp, TM_FORMAT_STRING, &(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
				tm_val = tm.hour;
				break;
				
			case CAL_BY_DAY:
				rtval = db_get_ap_index_info_within_30d(NULL, &ap_info_obj);
				if (rtval < 0) {
					syslog(LOG_ERR, "db_get_ap_index_info_within_30d: error!");
					RETURN_LONG(rtval);
				}
				sscanf(ap_info_obj.apInfo[0].collect_timestamp, TM_FORMAT_STRING, &(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
				tm_val = tm.day;
				break;
	
			default:
				syslog(LOG_ERR, "Not support!");
				free(ap_info_obj.apInfo);
				RETURN_LONG(rtval);
	}
#else
	if (tm_flag == 0)
		rtval = get_ap_info_demo(&ap_info_obj, 24);
	else if (tm_flag == 1)
		rtval = get_ap_info_demo(&ap_info_obj, 30);
	if (rtval < 0) {
		syslog(LOG_ERR, "ext_history: get_ap_info_demo error!");
		RETURN_LONG(rtval);
	}
	sscanf(ap_info_obj.apInfo[0].collect_timestamp, TM_FORMAT_STRING, &(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
		if (tm_flag == 0)
		tm_val = tm.hour;
	else if (tm_flag == 1)
		tm_val = tm.day;
#endif
	memset(&tm, 0, sizeof(tm));
	sig_intens = ap_info_obj.apInfo[0].signal_intensity;
	bw = ap_info_obj.apInfo[0].down_up_BW;
	tm_delay = ap_info_obj.apInfo[0].time_delay;
	ap_info_cnt = 1;

	for (i = 1; i < ap_info_obj.num_rows; i++) {
		sscanf(ap_info_obj.apInfo[i].collect_timestamp, TM_FORMAT_STRING, &(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
		if (CAL_BY_HOUR == tm_flag)
			tmp_tm_val = tm.hour;
		else if (CAL_BY_DAY == tm_flag)
			tmp_tm_val = tm.day;
		memset(&tm, 0, sizeof(tm));
		if (tm_val == tmp_tm_val) {
			sig_intens += ap_info_obj.apInfo[i].signal_intensity;
			bw += ap_info_obj.apInfo[i].down_up_BW;
			tm_delay += ap_info_obj.apInfo[i].time_delay;
			ap_info_cnt++;
			continue;
		} else {    //get the data's averaging
			sig_intens = sig_intens / ap_info_cnt;
			bw = bw / ap_info_cnt;
			tm_delay = tm_delay / ap_info_cnt;
			
			MAKE_STD_ZVAL(iter_array);
			array_init(iter_array);
			add_assoc_long(iter_array, "SignalIntens", (long)(sig_intens));
			add_assoc_long(iter_array, "DownUpBW", (long)(bw));
			add_assoc_long(iter_array, "TmDelay", (long)(tm_delay));
			add_assoc_long(iter_array, "TmStmp", (long)(tm_val));
			add_next_index_zval(iter, iter_array);
			collect_point_cnt++;
			
			tm_val = tmp_tm_val;
			sig_intens = ap_info_obj.apInfo[i].signal_intensity;
			bw = ap_info_obj.apInfo[i].down_up_BW;
			tm_delay = ap_info_obj.apInfo[i].time_delay;
			ap_info_cnt = 1;
		}	
	}
	
	sig_intens = sig_intens / ap_info_cnt;
	bw = bw / ap_info_cnt;
	tm_delay = tm_delay / ap_info_cnt;
	
	MAKE_STD_ZVAL(iter_array);
	array_init(iter_array);
	add_assoc_long(iter_array, "SignalIntens", (long)(sig_intens));
	add_assoc_long(iter_array, "DownUpBW", (long)(bw));
	add_assoc_long(iter_array, "TmDelay", (long)(tm_delay));
	add_assoc_long(iter_array, "TmStmp", (long)(tm_val));
	add_next_index_zval(iter, iter_array);
	collect_point_cnt++;
	
	free(ap_info_obj.apInfo);
	if(object_init(return_value) != SUCCESS)
	{
		RETURN_LONG(PHP_OBJ_INIT_FAIL);
	}
	
	add_assoc_long(iter_len, "ap_num", (long)(collect_point_cnt));
	add_property_zval(return_value, "ap_info", iter_len);
	add_property_zval(return_value, "value", iter); 
}

EXT_FUNCTION(ext_history_afi_info)
{
	query_afi_info afi_info_obj;
	int rtval = -1, i;

	zval *iter, *iter_array;
	MAKE_STD_ZVAL(iter);
	array_init(iter);
	zval *iter_len;
	MAKE_STD_ZVAL(iter_len);
	array_init(iter_len);


	rtval = db_get_afi_info(&afi_info_obj);
	if (rtval < 0) {
		syslog(LOG_ERR, "db_get_afi_info: error!");
		RETURN_LONG(rtval);
	}
	for (i = 0; i < afi_info_obj.num_rows; i++) {
			MAKE_STD_ZVAL(iter_array);
			array_init(iter_array);
			add_assoc_string(iter_array, "IP", (char *)(afi_info_obj.afiInfo[i].afi_ip_address), 1);
			add_assoc_string(iter_array, "AfiName", (char *)(afi_info_obj.afiInfo[i].afi_name), 1);
			add_assoc_string(iter_array, "AfiType", (char*)(afi_info_obj.afiInfo[i].afi_type), 1);
			add_assoc_string(iter_array, "AfiVer", (char*)(afi_info_obj.afiInfo[i].afi_version), 1);
			add_assoc_string(iter_array, "MAC", (char*)(afi_info_obj.afiInfo[i].mac_address), 1);
			add_assoc_string(iter_array, "TmStmp", (char *)(afi_info_obj.afiInfo[i].collect_timestamp), 1);
			add_assoc_long(iter_array, "ULnkByteNum", (long)(afi_info_obj.afiInfo[i].uplink_byte_num));
			add_assoc_long(iter_array, "DLnkByteNum", (long)(afi_info_obj.afiInfo[i].downlink_byte_num));
			add_assoc_long(iter_array, "ULnkPackNum", (long)(afi_info_obj.afiInfo[i].uplink_packet_num));
			add_assoc_long(iter_array, "DLnkPackNum", (long)(afi_info_obj.afiInfo[i].downlink_packet_num));
			add_assoc_double(iter_array, "RunTm", (double)(afi_info_obj.afiInfo[i].running_time));		
			add_next_index_zval(iter, iter_array);
	}
	//free the malloc bytes
	free(afi_info_obj.afiInfo);
	
	if(object_init(return_value) != SUCCESS)
	{
		RETURN_LONG(PHP_OBJ_INIT_FAIL);
	}
	
	add_assoc_long(iter_len, "afi_num", (long)(afi_info_obj.num_rows));
	add_property_zval(return_value, "afi_info", iter_len);
	add_property_zval(return_value, "value", iter); 
}

EXT_FUNCTION(ext_history_sys_score_info)
{
	
	query_sys_info sys_info_obj;
	int rtval = -1, i;
	TM_FLAGS_E tm_flag = CAL_BY_UNKOWN;
	
	zval *iter, *iter_array;
	MAKE_STD_ZVAL(iter);
	array_init(iter);
	zval *iter_len;
	MAKE_STD_ZVAL(iter_len);
	array_init(iter_len);
	
	TM_FORMAT_OBJ tm;
	int sys_index_info = 0, collect_point_cnt = 0;

	int cover_area = 0, sig_intens = 0, sig_inter = 0, usr_acc_rate = 0,
		uplink_bytes = 0, downlink_bytes = 0, score = 0, online_usr_nums = 0;
	int tm_val = 0, tmp_tm_val = 0;

	ext_para_get(argc, argv, EXT_TYPE_LONG, &tm_flag);
	
	switch (tm_flag) {
		case CAL_BY_HOUR:
			rtval = db_get_sys_score_info_within_24h(NULL, &sys_info_obj);
			if (rtval < 0) {
				syslog(LOG_ERR, "db_get_ap_index_info_within_24h: error!");
				RETURN_LONG(rtval);
			}
			sscanf(sys_info_obj.sysInfo[0].collect_timestamp, TM_FORMAT_STRING, 
				&(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
			tm_val = tm.hour;
			break;
			
		case CAL_BY_DAY:
			rtval = db_get_sys_score_info_within_30d(NULL, &sys_info_obj);
			if (rtval < 0) {
				syslog(LOG_ERR, "db_get_ap_index_info_within_30d: error!");
				RETURN_LONG(rtval);
			}
			sscanf(sys_info_obj.sysInfo[0].collect_timestamp, TM_FORMAT_STRING, 
				&(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
			tm_val = tm.day;
			break;

		default:
			syslog(LOG_ERR, "Not support!");
			RETURN_LONG(rtval);
	}

	cover_area = sys_info_obj.sysInfo[0].cover_area;
	sig_intens = sys_info_obj.sysInfo[0].signal_intensity;
	sig_inter  = sys_info_obj.sysInfo[0].signal_interference;
	score = sys_info_obj.sysInfo[0].health_score;
	uplink_bytes = sys_info_obj.sysInfo[0].uplink_byte_num;
	downlink_bytes = sys_info_obj.sysInfo[0].downlink_byte_num;
	online_usr_nums = sys_info_obj.sysInfo[0].online_user_num;
	usr_acc_rate = sys_info_obj.sysInfo[0].user_access_rate;
	sys_index_info = 1;

	for (i = 1; i < sys_info_obj.num_rows; i++) {
		sscanf(sys_info_obj.sysInfo[i].collect_timestamp, TM_FORMAT_STRING, 
			&(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
		if (CAL_BY_HOUR == tm_flag)
			tmp_tm_val = tm.hour;
		else if (CAL_BY_DAY == tm_flag)
			tmp_tm_val = tm.day;
		if (tm_val == tmp_tm_val) {
			sig_intens += sys_info_obj.sysInfo[i].signal_intensity;
			sig_inter += sys_info_obj.sysInfo[i].signal_interference;
			score += sys_info_obj.sysInfo[i].health_score;
			uplink_bytes += sys_info_obj.sysInfo[i].uplink_byte_num;
			downlink_bytes += sys_info_obj.sysInfo[i].downlink_byte_num;
			online_usr_nums += sys_info_obj.sysInfo[i].online_user_num;
			usr_acc_rate += sys_info_obj.sysInfo[i].user_access_rate;
			cover_area += sys_info_obj.sysInfo[i].cover_area;
			sys_index_info++;
			continue;
		} else {  
			sig_intens = sig_intens / sys_index_info;
			sig_inter = sig_inter / sys_index_info;
			score = score / sys_index_info;
			uplink_bytes = uplink_bytes / sys_index_info;
			downlink_bytes = downlink_bytes / sys_index_info;
			online_usr_nums = online_usr_nums / sys_index_info;
			usr_acc_rate = usr_acc_rate / sys_index_info;
			cover_area = cover_area / sys_index_info;
			
			MAKE_STD_ZVAL(iter_array);
			array_init(iter_array);
			add_assoc_long(iter_array, "CoverArea", (long)(cover_area));
			add_assoc_long(iter_array, "SignalInten", (long)(sig_intens));
			add_assoc_long(iter_array, "SignalInter", (long)(sig_inter));
			add_assoc_long(iter_array, "Score", (long)(score));
			add_assoc_long(iter_array, "OnLnUsrNum", (long)(online_usr_nums));
			add_assoc_long(iter_array, "UsrACCRate", (long)(usr_acc_rate));
			add_assoc_long(iter_array, "ULnkByteNum", (long)(uplink_bytes));
			add_assoc_long(iter_array, "DLnkByteNum", (long)(downlink_bytes));
			add_assoc_long(iter_array, "TmStmp", (long)(tm_val));
			add_next_index_zval(iter, iter_array);
			collect_point_cnt++;
			tm_val = tmp_tm_val;

			sig_intens = sys_info_obj.sysInfo[i].signal_intensity;
			sig_inter = sys_info_obj.sysInfo[i].signal_interference;
			score = sys_info_obj.sysInfo[i].health_score;
			uplink_bytes = sys_info_obj.sysInfo[i].uplink_byte_num;
			downlink_bytes = sys_info_obj.sysInfo[i].downlink_byte_num;
			online_usr_nums = sys_info_obj.sysInfo[i].online_user_num;
			usr_acc_rate = sys_info_obj.sysInfo[i].user_access_rate;
			cover_area = sys_info_obj.sysInfo[i].cover_area;
			sys_index_info = 1;
		}
				
	}

	sig_intens = sig_intens / sys_index_info;
	sig_inter = sig_inter / sys_index_info;
	score = score / sys_index_info;
	uplink_bytes = uplink_bytes / sys_index_info;
	downlink_bytes = downlink_bytes / sys_index_info;
	online_usr_nums = online_usr_nums / sys_index_info;
	usr_acc_rate = usr_acc_rate / sys_index_info;
	cover_area = cover_area / sys_index_info;
	
	MAKE_STD_ZVAL(iter_array);
	array_init(iter_array);
	add_assoc_long(iter_array, "CoverArea", (long)(cover_area));
	add_assoc_long(iter_array, "SignalInten", (long)(sig_intens));
	add_assoc_long(iter_array, "SignalInter", (long)(sig_inter));
	add_assoc_long(iter_array, "Score", (long)(score));
	add_assoc_long(iter_array, "OnLnUsrNum", (long)(online_usr_nums));
	add_assoc_long(iter_array, "UsrACCRate", (long)(usr_acc_rate));
	add_assoc_long(iter_array, "ULnkByteNum", (long)(uplink_bytes));
	add_assoc_long(iter_array, "DLnkByteNum", (long)(downlink_bytes));
	add_assoc_long(iter_array, "TmStmp", (long)(tm_val));
	add_next_index_zval(iter, iter_array);
	collect_point_cnt++;
	
	free(sys_info_obj.sysInfo);
	if(object_init(return_value) != SUCCESS)
	{
		RETURN_LONG(PHP_OBJ_INIT_FAIL);
	}
	
	add_assoc_long(iter_len, "sys_score_num", (long)(collect_point_cnt));
	add_property_zval(return_value, "sys_score_info", iter_len);
	add_property_zval(return_value, "value", iter); 
}
EXT_FUNCTION(ext_history_usr_detail)
{
	query_user_detailinfo usr_detail_obj;
	int rtval = -1, i;

	zval *iter, *iter_array;
	MAKE_STD_ZVAL(iter);
	array_init(iter);
	zval *iter_len;
	MAKE_STD_ZVAL(iter_len);
	array_init(iter_len);

	rtval = db_get_user_detail_info(&usr_detail_obj);
	if (rtval < 0) {
		syslog(LOG_ERR, "db_get_user_detail_info: error!");
		RETURN_LONG(rtval);	
	}
	for (i = 0; i < usr_detail_obj.num_rows; i++) {
		MAKE_STD_ZVAL(iter_array);
		array_init(iter_array);
		add_assoc_long(iter_array, "ULnkByteNum", (long)(usr_detail_obj.userInfo[i].uplink_byte_num));
		add_assoc_long(iter_array, "DLnkByteNum", (long)(usr_detail_obj.userInfo[i].downlink_byte_num));
		add_assoc_long(iter_array, "ULnkPackNum", (long)(usr_detail_obj.userInfo[i].uplink_packet_num));
		add_assoc_long(iter_array, "DLnkPackNum", (long)(usr_detail_obj.userInfo[i].downlink_packet_num));
		//notes double type
		add_assoc_double(iter_array, "RunTm", (long long)(usr_detail_obj.userInfo[i].running_time));
		add_assoc_string(iter_array, "DvType", (char *)(usr_detail_obj.userInfo[i].device_type), 1);
		add_assoc_string(iter_array, "MAC", (char *)(usr_detail_obj.userInfo[i].mac_address), 1);
		add_assoc_string(iter_array, "MacAlias", (char *)(usr_detail_obj.userInfo[i].mac_alias), 1);
		add_assoc_string(iter_array, "TmStmp", (char *)(usr_detail_obj.userInfo[i].collect_timestamp), 1);
		add_assoc_string(iter_array, "AccPoint", (char *)(usr_detail_obj.userInfo[i].access_point), 1);
		add_assoc_string(iter_array, "HostName", (char *)(usr_detail_obj.userInfo[i].hostname), 1);
		add_assoc_string(iter_array, "IP", (char *)(usr_detail_obj.userInfo[i].ip_address), 1);
		add_assoc_string(iter_array, "IsOnline", (char *)(usr_detail_obj.userInfo[i].is_online), 1);
		add_next_index_zval(iter, iter_array);
	}
	free(usr_detail_obj.userInfo);
	if(object_init(return_value) != SUCCESS)
	{
		RETURN_LONG(PHP_OBJ_INIT_FAIL);
	}
	
	add_assoc_long(iter_len, "usr_num", (long)(usr_detail_obj.num_rows));
	add_property_zval(return_value, "usr_detail", iter_len);
	add_property_zval(return_value, "value", iter); 
}

int get_wireless_info_demo(query_wireless_info *wireless_info_handle, int tm_type)
{
	if (NULL == wireless_info_handle)
		return -1;
	int i;

	wireless_info_handle->num_rows = tm_type;
	wireless_info_handle->wirelessInfo = (wireless_info *)malloc(wireless_info_handle->num_rows  * sizeof(wireless_info));
	if (NULL == wireless_info_handle->wirelessInfo) {
		syslog(LOG_ERR, "get_wireless_info_demo: malloc error!");
		return -1;
	}
	srand(time(NULL));
	for (i = 0; i < wireless_info_handle->num_rows; i++) {
		if (tm_type > 24)
			sprintf(wireless_info_handle->wirelessInfo[i].collect_timestamp, TM_FORMAT_STRING, 2014, 12, i, 1, 10, 11);
		else
			sprintf(wireless_info_handle->wirelessInfo[i].collect_timestamp, TM_FORMAT_STRING, 2014, 12, 23, i, 10, 11);
		wireless_info_handle->wirelessInfo[i].uplink_byte_num = rand() % 100;
		wireless_info_handle->wirelessInfo[i].uplink_packet_num = rand() % 100;
		wireless_info_handle->wirelessInfo[i].downlink_byte_num = rand() % 100;
		wireless_info_handle->wirelessInfo[i].downlink_packet_num = rand() % 100;
		wireless_info_handle->wirelessInfo[i].online_user_count = rand() % 100;
	}
	return 0;
}

EXT_FUNCTION(ext_history_wireless_info)
{
	query_wireless_info wireless_info_obj;
	int rtval = -1, i;
	TM_FORMAT_OBJ tm;
	TM_FLAGS_E tm_flag = CAL_BY_UNKOWN;
	int tm_val = 0, tmp_tm_val = 0;
	int collect_point_cnt = 0;
	char *afi_str = NULL;
	char afi_num[AFI_NUM] = { 0 };

	zval *iter, *iter_array;
	MAKE_STD_ZVAL(iter);
	array_init(iter);
	zval *iter_len;
	MAKE_STD_ZVAL(iter_len);
	array_init(iter_len);

	int uplink_bytes = 0, uplink_packs = 0, downlink_bytes = 0, downlink_packs = 0, online_usr_cnt = 0;

	ext_para_get(argc, argv, EXT_TYPE_LONG, &tm_flag, EXT_TYPE_STRING, &afi_str);
	syslog(LOG_ERR, "TM TYPE IS %d, WIRELESS", tm_flag);
	syslog(LOG_ERR, "AFI NUM IS %s, WIRELESS", afi_str);
	memcpy(afi_num, afi_str, strlen(afi_str)+1);

#ifdef RANDOM
	if (tm_flag == 0)
		rtval = get_wireless_info_demo(&wireless_info_obj, 24);
	else if (tm_flag == 1)
		rtval = get_wireless_info_demo(&wireless_info_obj, 30);
	if (rtval < 0) {
		syslog(LOG_ERR, "get_wireless_info_demo: ERROR!");
		RETURN_LONG(rtval);
	}
	sscanf(wireless_info_obj.wirelessInfo[0].collect_timestamp, TM_FORMAT_STRING, 
			&(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
	if (tm_flag == 0)
		tm_val = tm.hour;
	else if (tm_flag == 1)
		tm_val = tm.day;
#else
	switch (tm_flag) {
		case CAL_BY_HOUR:
			rtval = db_get_wireless_index_info_within_24h_and_essid_or_AFi(NULL, afi_num, &wireless_info_obj);
			if (rtval < 0) {
				syslog(LOG_ERR, "db_get_throughout_index_info_within_24h: error!");
				RETURN_LONG(rtval);
			}
			sscanf(wireless_info_obj.wirelessInfo[0].collect_timestamp, TM_FORMAT_STRING, 
				&(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
			tm_val = tm.hour;
			break;
			
		case CAL_BY_DAY:
			rtval = db_get_wireless_index_info_within_30d_and_essid_or_AFi(NULL, afi_num, &wireless_info_obj);
			if (rtval < 0) {
				syslog(LOG_ERR, "db_get_throughout_index_info_within_30d: error!");
				RETURN_LONG(rtval);
			}
			sscanf(wireless_info_obj.wirelessInfo[0].collect_timestamp, TM_FORMAT_STRING, 
				&(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
			tm_val = tm.day;
			break;

		default:
			syslog(LOG_ERR, "Not support!");
			RETURN_LONG(rtval);
	}
#endif
	uplink_bytes = wireless_info_obj.wirelessInfo[0].uplink_byte_num;
	uplink_packs = wireless_info_obj.wirelessInfo[0].uplink_packet_num;
	downlink_bytes = wireless_info_obj.wirelessInfo[0].downlink_byte_num;
	downlink_packs = wireless_info_obj.wirelessInfo[0].downlink_packet_num;
	online_usr_cnt = wireless_info_obj.wirelessInfo[0].online_user_count;

	for (i = 0; i < wireless_info_obj.num_rows; i++) {
		sscanf(wireless_info_obj.wirelessInfo[i].collect_timestamp, TM_FORMAT_STRING, 
				&(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
		if (CAL_BY_HOUR == tm_flag)
			tmp_tm_val = tm.hour;
		else if (CAL_BY_DAY == tm_flag)
			tmp_tm_val = tm.day;
		if (tm_val == tmp_tm_val) {
			int tmp = wireless_info_obj.wirelessInfo[i].uplink_byte_num;
			uplink_bytes = tmp > uplink_bytes ? tmp : uplink_bytes;
			tmp = wireless_info_obj.wirelessInfo[i].uplink_packet_num;
			uplink_packs = tmp > uplink_packs ? tmp : uplink_packs;
			tmp = wireless_info_obj.wirelessInfo[i].downlink_byte_num;
			downlink_bytes = tmp > downlink_bytes ? tmp : downlink_bytes;
			tmp = wireless_info_obj.wirelessInfo[i].downlink_packet_num;
			downlink_packs = tmp > downlink_packs ? tmp : downlink_packs;
			tmp = wireless_info_obj.wirelessInfo[i].online_user_count;
			online_usr_cnt = tmp > online_usr_cnt ? tmp : online_usr_cnt;
		} else {
			MAKE_STD_ZVAL(iter_array);
			array_init(iter_array);
			add_assoc_string(iter_array, "Essid", (char *)(wireless_info_obj.wirelessInfo[i].essid), 1);
			add_assoc_string(iter_array, "AFIN", (char *)(wireless_info_obj.wirelessInfo[i].AFi_n), 1);
			add_assoc_long(iter_array, "ULnkByteNum", (long)(uplink_bytes));
			add_assoc_long(iter_array, "DLnkByteNum", (long)(downlink_bytes));
			add_assoc_long(iter_array, "ULnkPackNum", (long)(uplink_packs));
			add_assoc_long(iter_array, "DLnkPackNum", (long)(downlink_packs));
			add_assoc_long(iter_array, "OnUsrCnt", (long)(online_usr_cnt));
			add_assoc_long(iter_array, "TmStmp", (long)(tm_val));
			add_next_index_zval(iter, iter_array);	
			collect_point_cnt++;

			tm_val = tmp_tm_val;
			uplink_bytes = wireless_info_obj.wirelessInfo[i].uplink_byte_num;
			uplink_packs = wireless_info_obj.wirelessInfo[i].uplink_packet_num;
			downlink_bytes = wireless_info_obj.wirelessInfo[i].downlink_byte_num;
			downlink_packs = wireless_info_obj.wirelessInfo[i].downlink_packet_num;
			online_usr_cnt = wireless_info_obj.wirelessInfo[i].online_user_count;
			
		}
	}
	
	MAKE_STD_ZVAL(iter_array);
	array_init(iter_array);
	add_assoc_long(iter_array, "ULnkByteNum", (long)(uplink_bytes));
	add_assoc_long(iter_array, "DLnkByteNum", (long)(downlink_bytes));
	add_assoc_long(iter_array, "ULnkPackNum", (long)(uplink_packs));
	add_assoc_long(iter_array, "DLnkPackNum", (long)(downlink_packs));
	add_assoc_long(iter_array, "OnUsrCnt", (long)(online_usr_cnt));
	add_assoc_long(iter_array, "TmStmp", (long)(tm_val));
	add_next_index_zval(iter, iter_array);	
	collect_point_cnt++;
#if 0
	for (i = 0; i < wireless_info_obj.num_rows; i++) {
		MAKE_STD_ZVAL(iter_array);
		array_init(iter_array);

		add_assoc_string(iter_array, "Essid", (char *)(wireless_info_obj.wirelessInfo[i].essid), 1);
		add_assoc_string(iter_array, "TmStmp", (char *)(wireless_info_obj.wirelessInfo[i].collect_timestamp), 1);
		add_assoc_string(iter_array, "AFIN", (char *)(wireless_info_obj.wirelessInfo[i].AFi_n), 1);
		add_assoc_long(iter_array, "ULnkByteNum", (long)(wireless_info_obj.wirelessInfo[i].uplink_byte_num));
		add_assoc_long(iter_array, "DLnkByteNum", (long)(wireless_info_obj.wirelessInfo[i].downlink_byte_num));
		add_assoc_long(iter_array, "ULnkPackNum", (long)(wireless_info_obj.wirelessInfo[i].uplink_packet_num));
		add_assoc_long(iter_array, "DLnkPackNum", (long)(wireless_info_obj.wirelessInfo[i].downlink_packet_num));
		add_assoc_long(iter_array, "OnUsrCnt", (long)(wireless_info_obj.wirelessInfo[i].online_user_count));
		add_next_index_zval(iter, iter_array);	
	}
#endif
	free(wireless_info_obj.wirelessInfo);
	if(object_init(return_value) != SUCCESS)
	{
		RETURN_LONG(PHP_OBJ_INIT_FAIL);
	}
	
	add_assoc_long(iter_len, "wireless_num", (long)(collect_point_cnt));
	add_property_zval(return_value, "wireless_info", iter_len);
	add_property_zval(return_value, "value", iter);
}

int get_flow_info_demo(query_throughout_info *flow_info, int tm_type)
{
	if (NULL == flow_info) {
		syslog(LOG_ERR, "get_flow_info : Parameter error!");
		return -1;
	}
	int i;

	flow_info->num_rows = tm_type;
	flow_info->throughoutInfo = (throughout_info *)malloc(flow_info->num_rows * sizeof(throughout_info));
	if (NULL == flow_info->throughoutInfo) {
		syslog(LOG_ERR, "get_flow_info_demo: malloc error!");
		return -1;
	}
	srand(time(NULL));
	for (i = 0; i < flow_info->num_rows; i++) {
		if (tm_type > 24)
			sprintf(flow_info->throughoutInfo[i].collect_timestamp, TM_FORMAT_STRING, 2014, 12, i, 1, 10, 11);
		else
			sprintf(flow_info->throughoutInfo[i].collect_timestamp, TM_FORMAT_STRING, 2014, 12, 23, i, 10, 11);
		flow_info->throughoutInfo[i].uplink_byte_num = rand() % 100;
		flow_info->throughoutInfo[i].uplink_packet_num = rand() % 100;
		flow_info->throughoutInfo[i].downlink_byte_num = rand() % 100;
		flow_info->throughoutInfo[i].downlink_packet_num = rand() % 100;
	}
	
	return 0;
}


EXT_FUNCTION(ext_history_flow_info)
{
	query_throughout_info flow_info_obj;
	int rtval = -1, i;
	TM_FORMAT_OBJ tm;
	TM_FLAGS_E tm_flag = CAL_BY_UNKOWN;
	int tm_val = 0, tmp_tm_val = 0;
	int collect_point_cnt = 0;

	zval *iter, *iter_array;
	MAKE_STD_ZVAL(iter);
	array_init(iter);
	zval *iter_len;
	MAKE_STD_ZVAL(iter_len);
	array_init(iter_len);

	int uplink_bytes = 0, uplink_packs = 0, downlink_bytes = 0, downlink_packs = 0;

	ext_para_get(argc, argv, EXT_TYPE_LONG, &tm_flag);
	syslog(LOG_ERR, "TM TYPE IS %d, FLOW", tm_flag);
	
#ifdef RANDOM
	if (tm_flag == 0)
		rtval = get_flow_info_demo(&flow_info_obj, 24);
	else if (tm_flag == 1) 
		rtval = get_flow_info_demo(&flow_info_obj, 30);
	if (rtval < 0) {
		syslog(LOG_ERR, "get_flow_info_demo: ERROR!");
		RETURN_LONG(rtval);
	}
	sscanf(flow_info_obj.throughoutInfo[0].collect_timestamp, TM_FORMAT_STRING, 
			&(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
	if (tm_flag == 0)
		tm_val = tm.hour;
	else if (tm_flag == 1)
		tm_val = tm.day;
#else
	switch (tm_flag) {
		case CAL_BY_HOUR:
			rtval = db_get_throughout_info_within_24h(NULL, &flow_info_obj);
			if (rtval < 0) {
				syslog(LOG_ERR, "db_get_throughout_index_info_within_24h: error!");
				RETURN_LONG(rtval);
			}
			sscanf(flow_info_obj.throughoutInfo[0].collect_timestamp, TM_FORMAT_STRING, 
				&(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
			tm_val = tm.hour;
			break;
			
		case CAL_BY_DAY:
			rtval = db_get_throughout_info_within_30d(NULL, &flow_info_obj);
			if (rtval < 0) {
				syslog(LOG_ERR, "db_get_throughout_index_info_within_30d: error!");
				RETURN_LONG(rtval);
			}
			sscanf(flow_info_obj.throughoutInfo[0].collect_timestamp, TM_FORMAT_STRING, 
				&(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
			tm_val = tm.day;
			break;

		default:
			syslog(LOG_ERR, "Not support!");
			free(flow_info_obj.throughoutInfo);
			RETURN_LONG(rtval);
	}
#endif
	uplink_bytes = flow_info_obj.throughoutInfo[0].uplink_byte_num;
	uplink_packs = flow_info_obj.throughoutInfo[0].uplink_packet_num;
	downlink_bytes = flow_info_obj.throughoutInfo[0].downlink_byte_num;
	downlink_packs = flow_info_obj.throughoutInfo[0].downlink_packet_num;

	for (i = 0; i < flow_info_obj.num_rows; i++) {
		sscanf(flow_info_obj.throughoutInfo[i].collect_timestamp, TM_FORMAT_STRING, 
				&(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
		if (CAL_BY_HOUR == tm_flag)
			tmp_tm_val = tm.hour;
		else if (CAL_BY_DAY == tm_flag)
			tmp_tm_val = tm.day;
		if (tm_val == tmp_tm_val) {
			int tmp = flow_info_obj.throughoutInfo[i].uplink_byte_num;
			uplink_bytes = tmp > uplink_bytes ? tmp : uplink_bytes;
			tmp = flow_info_obj.throughoutInfo[i].uplink_packet_num;
			uplink_packs = tmp > uplink_packs ? tmp : uplink_packs;
			tmp = flow_info_obj.throughoutInfo[i].downlink_byte_num;
			downlink_bytes = tmp > downlink_bytes ? tmp : downlink_bytes;
			tmp = flow_info_obj.throughoutInfo[i].downlink_packet_num;
			downlink_packs = tmp > downlink_packs ? tmp : downlink_packs;
		} else {
		
			MAKE_STD_ZVAL(iter_array);
			array_init(iter_array);
			add_assoc_long(iter_array, "ULnkByteNum", (long)(uplink_bytes));
			add_assoc_long(iter_array, "DLnkByteNum", (long)(uplink_packs));
			add_assoc_long(iter_array, "ULnkPackNum", (long)(downlink_bytes));
			add_assoc_long(iter_array, "DLnkPackNum", (long)(downlink_packs));
			add_assoc_long(iter_array, "TmStmp", (long)(tm_val));
			add_next_index_zval(iter, iter_array);	
			collect_point_cnt++;

			tm_val = tmp_tm_val;
			uplink_bytes = flow_info_obj.throughoutInfo[i].uplink_byte_num;
			uplink_packs = flow_info_obj.throughoutInfo[i].uplink_packet_num;
			downlink_bytes = flow_info_obj.throughoutInfo[i].downlink_byte_num;
			downlink_packs = flow_info_obj.throughoutInfo[i].downlink_packet_num;
		}
	}
		
	MAKE_STD_ZVAL(iter_array);
	array_init(iter_array);
	add_assoc_long(iter_array, "ULnkByteNum", (long)(uplink_bytes));
	add_assoc_long(iter_array, "DLnkByteNum", (long)(uplink_packs));
	add_assoc_long(iter_array, "ULnkPackNum", (long)(downlink_bytes));
	add_assoc_long(iter_array, "DLnkPackNum", (long)(downlink_packs));
	add_assoc_long(iter_array, "TmStmp", (long)(tm_val));
	add_next_index_zval(iter, iter_array);	
	collect_point_cnt++;

	free(flow_info_obj.throughoutInfo);
	if(object_init(return_value) != SUCCESS)
	{
		RETURN_LONG(PHP_OBJ_INIT_FAIL);
	}
	
	add_assoc_long(iter_len, "flow_num", (long)(collect_point_cnt));
	add_property_zval(return_value, "flow_info", iter_len);
	add_property_zval(return_value, "value", iter);
}

int get_wifi_info_demo(query_wifi_info *wifi_info_demo, int tm_type)
{
	if (NULL == wifi_info_demo) {
		return -1;
	}
	int i;
	
	wifi_info_demo->num_rows = tm_type;
	wifi_info_demo->wifiInfo= (wifi_info *)malloc(wifi_info_demo->num_rows * sizeof(wifi_info));
	if (NULL == wifi_info_demo->wifiInfo) {
		syslog(LOG_ERR, "get_wifi_info_demo: malloc error!");
		return -1;
	}
	srand(time(NULL));
	for (i = 0; i < wifi_info_demo->num_rows; i++) {
		if (tm_type > 24)
			sprintf(wifi_info_demo->wifiInfo[i].collect_timestamp, TM_FORMAT_STRING, 2014, 12, i, 1, 10, 11);
		else
			sprintf(wifi_info_demo->wifiInfo[i].collect_timestamp, TM_FORMAT_STRING, 2014, 12, 23, i, 10, 11);
		wifi_info_demo->wifiInfo[i].signal_interference= rand () % 100;
		wifi_info_demo->wifiInfo[i].channel_utilization= rand() % 100;
		wifi_info_demo->wifiInfo[i].signal_noise_rate= rand() % 100;
	}

	return 0;

}

EXT_FUNCTION(ext_history_wifi_info)
{
	query_wifi_info wifi_info_obj;
	int rtval = -1, i;
	TM_FORMAT_OBJ tm;
	TM_FLAGS_E tm_flag = CAL_BY_UNKOWN;
	int tm_val = 0, tmp_tm_val = 0;
	int wifi_info_cnt = 0, collect_point_cnt = 0;

	zval *iter, *iter_array;
	MAKE_STD_ZVAL(iter);
	array_init(iter);
	zval *iter_len;
	MAKE_STD_ZVAL(iter_len);
	array_init(iter_len);

	int sig_noise_rate = 0, sig_inter = 0, chan_utilize = 0;
	
	ext_para_get(argc, argv, EXT_TYPE_LONG, &tm_flag);
	syslog(LOG_ERR, "TM TYPE IS %d, WIFI", tm_flag);

#ifdef RANDOM
		if (tm_flag == 0)
			rtval = get_wifi_info_demo(&wifi_info_obj, 24);
		else if (tm_flag == 1)
			rtval = get_wifi_info_demo(&wifi_info_obj, 30);
		if (rtval < 0) {
			syslog(LOG_ERR, "get_wifi_info_demo: ERROR!");
			RETURN_LONG(rtval);
		}
		sscanf(wifi_info_obj.wifiInfo[0].collect_timestamp, TM_FORMAT_STRING, 
				&(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
		if (tm_flag == 0)
			tm_val = tm.hour;
		else if (tm_flag == 1)
			tm_val = tm.day;
#else
		switch (tm_flag) {
			case CAL_BY_HOUR:
				rtval = db_get_wifi_index_info_within_24h(NULL, &wifi_info_obj);
				if (rtval < 0) {
					syslog(LOG_ERR, "db_get_ap_index_info_within_24h: error!");
					RETURN_LONG(rtval);
				}
				sscanf(wifi_info_obj.wifiInfo[0].collect_timestamp, TM_FORMAT_STRING, 
					&(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
				tm_val = tm.hour;
				break;
				
			case CAL_BY_DAY:
				rtval = db_get_wifi_index_info_within_30d(NULL, &wifi_info_obj);
				if (rtval < 0) {
					syslog(LOG_ERR, "db_get_ap_index_info_within_30d: error!");
					RETURN_LONG(rtval);
				}
				sscanf(wifi_info_obj.wifiInfo[0].collect_timestamp, TM_FORMAT_STRING, 
					&(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
				tm_val = tm.day;
				break;
	
			default:
				syslog(LOG_ERR, "Not support!");
				free(wifi_info_obj.wifiInfo);
				RETURN_LONG(rtval);
		}
#endif

	sig_inter = wifi_info_obj.wifiInfo[0].signal_interference;
	chan_utilize = wifi_info_obj.wifiInfo[0].channel_utilization;
	sig_noise_rate = wifi_info_obj.wifiInfo[0].signal_noise_rate;
	wifi_info_cnt = 1;

	for (i = 1; i < wifi_info_obj.num_rows; i++) {
		sscanf(wifi_info_obj.wifiInfo[i].collect_timestamp, TM_FORMAT_STRING, 
			&(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
		if (CAL_BY_HOUR == tm_flag)
			tmp_tm_val = tm.hour;
		else if (CAL_BY_DAY == tm_flag)
			tmp_tm_val = tm.day;
		
		if (tm_val == tmp_tm_val) {
			sig_inter += wifi_info_obj.wifiInfo[i].signal_interference;
			chan_utilize += wifi_info_obj.wifiInfo[i].channel_utilization;
			sig_noise_rate += wifi_info_obj.wifiInfo[i].signal_noise_rate;
			wifi_info_cnt++;
			continue;
		} else { 
			sig_inter = sig_inter / wifi_info_cnt;
			chan_utilize = chan_utilize / wifi_info_cnt;
			sig_noise_rate = sig_noise_rate / wifi_info_cnt;

			MAKE_STD_ZVAL(iter_array);
			array_init(iter_array);
			add_assoc_long(iter_array, "SignalInter", (long)(sig_inter));
			add_assoc_long(iter_array, "ChanUtilize", (long)(chan_utilize));
			add_assoc_long(iter_array, "SignalNoiseRate", (long)(sig_noise_rate));
			add_assoc_long(iter_array, "TmStmp", (long)(tm_val));
			add_next_index_zval(iter, iter_array);
			collect_point_cnt++;

			tm_val = tmp_tm_val;
			sig_inter = wifi_info_obj.wifiInfo[i].signal_interference;
			chan_utilize = wifi_info_obj.wifiInfo[i].channel_utilization;
			sig_noise_rate = wifi_info_obj.wifiInfo[i].signal_noise_rate;
			wifi_info_cnt = 1;
		}
		
	}
	
	sig_inter = sig_inter / wifi_info_cnt;
	sig_noise_rate = sig_noise_rate / wifi_info_cnt;
	chan_utilize = chan_utilize / wifi_info_cnt;

	MAKE_STD_ZVAL(iter_array);
	array_init(iter_array);
	add_assoc_long(iter_array, "SignalInter", (long)(sig_inter));
	add_assoc_long(iter_array, "ChanUtilize", (long)(chan_utilize));
	add_assoc_long(iter_array, "SignalNoiseRate", (long)(sig_noise_rate));
	add_assoc_long(iter_array, "TmStmp", (long)(tm_val));
	add_next_index_zval(iter, iter_array);
	collect_point_cnt++;
	
	free(wifi_info_obj.wifiInfo);
	if(object_init(return_value) != SUCCESS)
	{
		RETURN_LONG(PHP_OBJ_INIT_FAIL);
	}
	
	add_assoc_long(iter_len, "wifi_num", (long)(collect_point_cnt));
	add_property_zval(return_value, "wifi_info", iter_len);
	add_property_zval(return_value, "value", iter);
}

int get_ternimal_info_demo(query_user_info *terminal_info_demo, int tm_type)
{
	if (NULL == terminal_info_demo) {
			return -1;
		}
		int i;
		
		terminal_info_demo->num_rows = tm_type;
		terminal_info_demo->userInfo = (user_info *)malloc(terminal_info_demo->num_rows * sizeof(user_info));
		if (NULL == terminal_info_demo->userInfo) {
			syslog(LOG_ERR, "get_ap_info_demo: malloc error!");
			return -1;
		}
		srand(time(NULL));
		for (i = 0; i < terminal_info_demo->num_rows; i++) {
			if (tm_type > 24)
				sprintf(terminal_info_demo->userInfo[i].collect_timestamp, TM_FORMAT_STRING, 2014, 12, i, 1, 10, 11);
			else
				sprintf(terminal_info_demo->userInfo[i].collect_timestamp, TM_FORMAT_STRING, 2014, 12, 22, i, 10, 11);
			terminal_info_demo->userInfo[i].signal_intensity = rand () % 100;
			terminal_info_demo->userInfo[i].access_rate = rand() % 100;
			terminal_info_demo->userInfo[i].WL_retransmission_rate = rand() % 100;
			terminal_info_demo->userInfo[i].consultation_rate = rand() % 100;
		}
	
		return 0;

}


EXT_FUNCTION(ext_history_terminal_info)
{
	query_user_info terminal_info_obj;
	int rtval = -1, i;
	TM_FLAGS_E tm_flag = CAL_BY_UNKOWN;
	TM_FORMAT_OBJ tm;
	int tm_val = 0, tmp_tm_val = 0;
	int terminal_info_cnt = 0, collect_point_cnt = 0;

	zval *iter, *iter_array;
	MAKE_STD_ZVAL(iter);
	array_init(iter);
	zval *iter_len;
	MAKE_STD_ZVAL(iter_len);
	array_init(iter_len);

	int sig_intens = 0, access_rate = 0, retrans_rate = 0, negotiate_rate = 0;
	
	ext_para_get(argc, argv, EXT_TYPE_LONG, &tm_flag);
	syslog(LOG_ERR, "TM TYPE IS %d, TERMINAL", tm_flag);

#ifdef RANDOM
	if (tm_flag == 0)
		rtval = get_ternimal_info_demo(&terminal_info_obj, 24);
	else if (tm_flag == 1)
		rtval = get_ternimal_info_demo(&terminal_info_obj, 30);
	if (rtval < 0) {
		syslog(LOG_ERR, "get_terminal_info_demo: ERROR!");
		RETURN_LONG(rtval);
	}
	sscanf(terminal_info_obj.userInfo[0].collect_timestamp, TM_FORMAT_STRING, 
			&(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
	if (tm_flag == 0)
		tm_val = tm.hour;
	else if (tm_flag == 1)
		tm_val = tm.day;
#else
	switch (tm_flag) {
		case CAL_BY_HOUR:
			rtval = db_get_user_index_info_within_24h(NULL, &terminal_info_obj);
			if (rtval < 0) {
				syslog(LOG_ERR, "db_get_ap_index_info_within_24h: error!");
				RETURN_LONG(rtval);
			}
			sscanf(terminal_info_obj.userInfo[0].collect_timestamp, TM_FORMAT_STRING, 
				&(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
			tm_val = tm.hour;
			break;
			
		case CAL_BY_DAY:
			rtval = db_get_user_index_info_within_30d(NULL, &terminal_info_obj);
			if (rtval < 0) {
				syslog(LOG_ERR, "db_get_ap_index_info_within_30d: error!");
				RETURN_LONG(rtval);
			}
			sscanf(terminal_info_obj.userInfo[0].collect_timestamp, TM_FORMAT_STRING, 
				&(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
			tm_val = tm.day;
			break;

		default:
			syslog(LOG_ERR, "Not support!");
			free(terminal_info_obj.userInfo);
			RETURN_LONG(rtval);
	}
#endif
	sig_intens = terminal_info_obj.userInfo[0].signal_intensity;
	access_rate = terminal_info_obj.userInfo[0].access_rate;
	retrans_rate = terminal_info_obj.userInfo[0].WL_retransmission_rate;
	negotiate_rate = terminal_info_obj.userInfo[0].consultation_rate;
	terminal_info_cnt = 1;

	for (i = 1; i < terminal_info_obj.num_rows; i++) {
		sscanf(terminal_info_obj.userInfo[i].collect_timestamp, TM_FORMAT_STRING, 
			&(tm.year), &(tm.month), &(tm.day), &(tm.hour), &(tm.minute), &(tm.second));
		if (CAL_BY_HOUR == tm_flag)
			tmp_tm_val = tm.hour;
		else if (CAL_BY_DAY == tm_flag)
			tmp_tm_val = tm.day;
		
		if (tm_val == tmp_tm_val) {
			sig_intens += terminal_info_obj.userInfo[i].signal_intensity;
			access_rate += terminal_info_obj.userInfo[i].access_rate;
			retrans_rate += terminal_info_obj.userInfo[i].WL_retransmission_rate;
			negotiate_rate += terminal_info_obj.userInfo[i].consultation_rate;
			terminal_info_cnt++;
			continue;
		} else { 
			sig_intens = sig_intens / terminal_info_cnt;
			access_rate = access_rate / terminal_info_cnt;
			retrans_rate = retrans_rate / terminal_info_cnt;
			negotiate_rate = negotiate_rate / terminal_info_cnt;

			MAKE_STD_ZVAL(iter_array);
			array_init(iter_array);
			add_assoc_long(iter_array, "SignalIntens", (long)(sig_intens));
			add_assoc_long(iter_array, "AccessRate", (long)(access_rate));
			add_assoc_long(iter_array, "RetransRate", (long)(retrans_rate));
			add_assoc_long(iter_array, "NegotiateRate", (long)(negotiate_rate));
			add_assoc_long(iter_array, "TmStmp", (long)(tm_val));
			add_next_index_zval(iter, iter_array);
			collect_point_cnt++;

			tm_val = tmp_tm_val;
			sig_intens = terminal_info_obj.userInfo[i].signal_intensity;
			access_rate = terminal_info_obj.userInfo[i].access_rate;
			retrans_rate = terminal_info_obj.userInfo[i].WL_retransmission_rate;
			negotiate_rate = terminal_info_obj.userInfo[i].consultation_rate;
			terminal_info_cnt = 1;
		}
		
	}
	sig_intens = sig_intens / terminal_info_cnt;
	access_rate = access_rate / terminal_info_cnt;
	retrans_rate = retrans_rate / terminal_info_cnt;
	negotiate_rate = negotiate_rate / terminal_info_cnt;

	MAKE_STD_ZVAL(iter_array);
	array_init(iter_array);
	add_assoc_long(iter_array, "SignalIntens", (long)(sig_intens));
	add_assoc_long(iter_array, "AccessRate", (long)(access_rate));
	add_assoc_long(iter_array, "RetransRate", (long)(retrans_rate));
	add_assoc_long(iter_array, "NegotiateRate", (long)(negotiate_rate));
	add_assoc_long(iter_array, "TmStmp", (long)(tm_val));
	add_next_index_zval(iter, iter_array);
	collect_point_cnt++;
	
	free(terminal_info_obj.userInfo);
	if(object_init(return_value) != SUCCESS)
	{
		RETURN_LONG(PHP_OBJ_INIT_FAIL);
	}
	
	add_assoc_long(iter_len, "term_num", (long)(collect_point_cnt));
	add_property_zval(return_value, "terminal_info", iter_len);
	add_property_zval(return_value, "value", iter);
}

