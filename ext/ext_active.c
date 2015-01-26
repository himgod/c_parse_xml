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
#include "ext_active.h"
#include "wid_ac.h"
#include "ext_dbus.h"
#include "dbop.h"
//extern void YLog(char *format,...);

#define ACTIVE_DEBUG_ENABLE 0
#define THIS_HANDLE_FUNC_LIST active_func_list
ext_func_handle_t THIS_HANDLE_FUNC_LIST[] = {
    {"get_object_active_after_id", 2, (php_func_t)ext_get_object_active_after_id},
    {"get_object_active_after_id_with_all_filter", 7, (php_func_t)ext_get_object_active_after_id_with_all_filter},
    {"get_event_report_and_hint", 7, (php_func_t)ext_active_get_event_report_and_hint},
    {"get_alert_with_filter", 2, (php_func_t)ext_get_alert_with_filter},
	{"archive_alert_by_activeid_apmac", 3, (php_func_t)ext_archive_alert_by_activeid_apmac},
	{"archive_all_alert", 1, (php_func_t)ext_archive_all_alert},
    {"add_upgrade_active_to_db", 6, (php_func_t)ext_add_upgrade_active_to_db},
    {"ap_down_pubkey_step_info", 4, (php_func_t)ext_ap_down_pubkey_step_info},
    	
};

void ext_active_handle(int argc, zval ***argv, zval *return_value)
{
    int count = sizeof(THIS_HANDLE_FUNC_LIST)/sizeof(THIS_HANDLE_FUNC_LIST[0]);
    ext_function_handle(argc, argv, return_value, count, THIS_HANDLE_FUNC_LIST);
}

EXT_FUNCTION(ext_get_object_active_after_id)
{
    int ret = -1;
	long _id = 0;
	int i = 0;
	int maxid = 0;
	int count = 0;
	double time = 0;
    zval *iter_array;
    zval *iter;
    MAKE_STD_ZVAL(iter);
    array_init(iter);
    //zval *iter_max;
    //MAKE_STD_ZVAL(iter_max);
    //array_init(iter_max);
	
#ifdef OBJECT_ACTIVE_SUPPORT
	query_active queryactive;
	memset(&queryactive, 0, sizeof(query_active));
#endif
	ext_para_get(argc, argv, EXT_TYPE_LONG, &_id);
	
#ifdef OBJECT_ACTIVE_SUPPORT
#if ACTIVE_DEBUG_ENABLE
	syslog(LOG_DEBUG, "get all object active after id %ld ", _id);
#endif
	ret = db_get_all_activeinfo_after_id((int)_id, &queryactive);/**/
#endif
#if ACTIVE_DEBUG_ENABLE
#ifdef OBJECT_ACTIVE_SUPPORT	
	db_log_query_active(&queryactive);
#else
#endif

#endif
	//add_assoc_long(iter_array, "result", (long)ret);

#ifdef OBJECT_ACTIVE_SUPPORT
	if(0 == ret)
	{
		for(i = 0; i < queryactive.row_num; i++)
		{
		    MAKE_STD_ZVAL(iter_array);
		    array_init(iter_array);
			add_assoc_long(iter_array, "_id", (long)queryactive.activeinfo[i]._id);
			// pending data
			//add_assoc_long(iter_array, "time", (long)(queryactive.activeinfo[i].time));

			add_assoc_string(iter_array, "datetime", (char *)queryactive.activeinfo[i].event_time, 1);
			
			time = (double)get_time_t_from_db_format_time((char *)queryactive.activeinfo[i].event_time);
			time *= 1000;/* to microsecond*/
			add_assoc_double(iter_array, "time", time);

			add_assoc_string(iter_array, "key", (char *)queryactive.activeinfo[i].event, 1);

			add_assoc_string(iter_array, "msg", (char *)queryactive.activeinfo[i].msg, 1);

			add_assoc_string(iter_array, "admin", queryactive.activeinfo[i].admin, 1);

			add_assoc_string(iter_array, "ap", queryactive.activeinfo[i].ap, 1);

			add_assoc_string(iter_array, "user", queryactive.activeinfo[i].user, 1);

			add_assoc_string(iter_array, "guest", queryactive.activeinfo[i].guest, 1);
			
		    add_next_index_zval(iter, iter_array);
			if(queryactive.activeinfo[i]._id >= maxid)
			{
				maxid = queryactive.activeinfo[i]._id;
			}
			count++;
		}
	}
	
#endif
	
	db_destroy_object_active(queryactive.activeinfo);
	if(object_init(return_value) != SUCCESS)
    {
        RETURN_LONG(PHP_OBJ_INIT_FAIL);
    }
	
    //add_assoc_long(iter_max, "lastId", (long)maxid);
    add_property_long(return_value, "result", (long)ret);
    add_property_long(return_value, "count", (long)count);
    add_property_long(return_value, "lastId", (long)maxid);
    add_property_zval(return_value, "value", iter); 
}

EXT_FUNCTION (ext_active_get_event_report_and_hint)
{
	int rtval = -1, i = 0, j;
	long id = 0, maxid = 0, hours = 0;
	int count = 0, archived = 0, alart = 0;
	double time = 0;
	char * admin = NULL, *ap = NULL, *usr = NULL, *guest = NULL;
    zval *iter_array;
    zval *iter;
    MAKE_STD_ZVAL(iter);
    array_init(iter);

	alert_info_s alert_ids[256];
	memset(&alert_ids, 0, sizeof(alert_info_s)*256);
    DBusConnection *connection = NULL;
	
	rtval = dbus_connection_init(&connection);
    if(!connection || 0 != rtval)
    {
        syslog(LOG_ERR, "dbus connection init failed when archive_alert_by_id %d ret %d", archived, rtval);
        if(connection)
        {           
            uninit_dbus_connection(&connection);
        }
        RETURN_LONG(-1);
    } 
	//archived -1 all, 1 true , 0 false
    rtval = hand_get_ap_alert_ids(alert_ids, connection);
	if (0 != rtval) {
		syslog(LOG_ERR, "hand_get_ap_alert_ids: error!");	
	}
	if(connection){
		uninit_dbus_connection(&connection);
	}

	query_active queryactive;
	memset(&queryactive, 0, sizeof(query_active));
	
	//get parameters from php
	ext_para_get(argc, argv, EXT_TYPE_LONG, &id, EXT_TYPE_STRING, &admin, EXT_TYPE_STRING, &ap, 
			EXT_TYPE_STRING, &usr, EXT_TYPE_STRING, &guest, EXT_TYPE_LONG, &hours);
#if ACTIVE_DEBUG_ENABLE
	syslog(LOG_DEBUG, "get all object active after id %ld with filter admin %s ap %s user %s guest %s ", 
		id, admin?admin:"", ap?ap:"", usr?usr:"", guest?guest:"");
#endif
	//get data from the db
	rtval = db_get_all_activeinfo_after_id_by_object_within_hours((int)id, 
		&queryactive, admin, ap, usr, guest, (int)hours);	
#if ACTIVE_DEBUG_ENABLE
	db_log_query_active(&queryactive);
#endif
	if(0 == rtval)
	{
		for(i = 0; i < queryactive.row_num; i++)
		{
			alart = 0;
			archived = 1;   
		    MAKE_STD_ZVAL(iter_array);
		    array_init(iter_array);
			for (j = 0; j < 256; j++) {
				if (queryactive.activeinfo[i]._id == alert_ids[j].active_id) {
					alart = 1;
					archived = alert_ids[j].archived;
				}
			}
			add_assoc_long(iter_array, "alert", (long)alart);
			add_assoc_long(iter_array, "archived", (long)archived);
			add_assoc_long(iter_array, "_id", (long)queryactive.activeinfo[i]._id);
			add_assoc_string(iter_array, "datetime", (char *)queryactive.activeinfo[i].event_time, 1);
			
			time = (double)get_time_t_from_db_format_time((char *)queryactive.activeinfo[i].event_time);
			time *= 1000;
			add_assoc_double(iter_array, "time", (double)time);
			add_assoc_string(iter_array, "key", (char *)queryactive.activeinfo[i].event, 1);
			add_assoc_string(iter_array, "msg", (char *)queryactive.activeinfo[i].msg, 1);
			add_assoc_string(iter_array, "admin", queryactive.activeinfo[i].admin, 1);
			add_assoc_string(iter_array, "ap", (char *)queryactive.activeinfo[i].ap, 1);
			add_assoc_string(iter_array, "user", queryactive.activeinfo[i].user, 1);
			add_assoc_string(iter_array, "guest", queryactive.activeinfo[i].guest, 1);
			
		    add_next_index_zval(iter, iter_array);
			if(queryactive.activeinfo[i]._id > maxid)
			{
				maxid = queryactive.activeinfo[i]._id;
			}
			count++;
		}
	}
	
	db_destroy_object_active(queryactive.activeinfo);
   	if(object_init(return_value) != SUCCESS)
   	{
		RETURN_LONG(PHP_OBJ_INIT_FAIL);
   	}

    //add_assoc_long(iter_max, "lastId", (long)maxid);
    add_property_long(return_value, "result", (long)rtval);
    add_property_long(return_value, "count", (long)count);
    add_property_long(return_value, "lastId", (long)maxid);
    add_property_zval(return_value, "value", iter); 
}

EXT_FUNCTION(ext_get_object_active_after_id_with_all_filter)
{
    int ret = -1;
	long _id = 0;
	int i = 0;
	int maxid = 0;
	int count = 0;
	char * admin = NULL;
	char * ap = NULL;
	char * user = NULL;
	char * guest = NULL;
    zval *iter_array;
    zval *iter;
    MAKE_STD_ZVAL(iter);
    array_init(iter);
	double time = 0;
	long hours = 0;
    //zval *iter_max;
    //MAKE_STD_ZVAL(iter_max);
    //array_init(iter_max);
	
#ifdef OBJECT_ACTIVE_SUPPORT
	query_active queryactive;
	memset(&queryactive, 0, sizeof(query_active));
#endif
	ext_para_get(argc, argv, EXT_TYPE_LONG, &_id, EXT_TYPE_STRING, &admin, EXT_TYPE_STRING, &ap, 
		EXT_TYPE_STRING, &user, EXT_TYPE_STRING, &guest, EXT_TYPE_LONG, &hours);
	
#ifdef OBJECT_ACTIVE_SUPPORT
#if ACTIVE_DEBUG_ENABLE
	syslog(LOG_DEBUG, "get all object active after id %ld with filter admin %s ap %s user %s guest %s ", 
		_id, admin?admin:"", ap?ap:"", user?user:"", guest?guest:"");
#endif
	ret = db_get_all_activeinfo_after_id_by_object_within_hours((int)_id, &queryactive, admin, ap, user, guest, (int)hours);/**/
#endif
#if ACTIVE_DEBUG_ENABLE
#ifdef OBJECT_ACTIVE_SUPPORT	
	db_log_query_active(&queryactive);
#else
#endif

#endif
	//add_assoc_long(iter_array, "result", (long)ret);

#ifdef OBJECT_ACTIVE_SUPPORT
	if(0 == ret)
	{
		for(i = 0; i < queryactive.row_num; i++)
		{
		    MAKE_STD_ZVAL(iter_array);
		    array_init(iter_array);
			add_assoc_long(iter_array, "_id", (long)queryactive.activeinfo[i]._id);
			// pending data
			//add_assoc_long(iter_array, "time", (long)(queryactive.activeinfo[i].time));

			add_assoc_string(iter_array, "datetime", (char *)queryactive.activeinfo[i].event_time, 1);
			
			time = (double)get_time_t_from_db_format_time((char *)queryactive.activeinfo[i].event_time);
			time *= 1000;
			
			add_assoc_double(iter_array, "time", (double)time);

			add_assoc_string(iter_array, "key", (char *)queryactive.activeinfo[i].event, 1);

			add_assoc_string(iter_array, "msg", (char *)queryactive.activeinfo[i].msg, 1);

			add_assoc_string(iter_array, "admin", queryactive.activeinfo[i].admin, 1);

			add_assoc_string(iter_array, "ap", queryactive.activeinfo[i].ap, 1);

			add_assoc_string(iter_array, "user", queryactive.activeinfo[i].user, 1);

			add_assoc_string(iter_array, "guest", queryactive.activeinfo[i].guest, 1);
			
		    add_next_index_zval(iter, iter_array);
			if(queryactive.activeinfo[i]._id > maxid)
			{
				maxid = queryactive.activeinfo[i]._id;
			}
			count++;
		}
	}
	
#endif
	
	db_destroy_object_active(queryactive.activeinfo);
	if(object_init(return_value) != SUCCESS)
    {
        RETURN_LONG(PHP_OBJ_INIT_FAIL);
    }
	
    //add_assoc_long(iter_max, "lastId", (long)maxid);
    add_property_long(return_value, "result", (long)ret);
    add_property_long(return_value, "count", (long)count);
    add_property_long(return_value, "lastId", (long)maxid);
    add_property_zval(return_value, "value", iter); 
}

#ifdef OBJECT_ACTIVE_SUPPORT

int assemble_alert_to_php_object_by_archived(zval * iter, query_active *queryactive, int archived)
{
	int i = 0;	
	int maxid = 0;
	double time = 0;
    zval *iter_array;
	
	for(i = 0; i < queryactive->row_num; i++)
	{
	    MAKE_STD_ZVAL(iter_array);
	    array_init(iter_array);
		add_assoc_long(iter_array, "_id", (long)queryactive->activeinfo[i]._id);
		// pending data
		//add_assoc_long(iter_array, "time", (long)(queryactive.activeinfo[i].time));

		add_assoc_string(iter_array, "datetime", (char *)queryactive->activeinfo[i].event_time, 1);
		
		time = (double)get_time_t_from_db_format_time((char *)queryactive->activeinfo[i].event_time);
		time *= 1000;/*set to microsecond */
		
		add_assoc_double(iter_array, "time", (double)time);

		add_assoc_string(iter_array, "key", (char *)queryactive->activeinfo[i].event, 1);

		add_assoc_string(iter_array, "msg", (char *)queryactive->activeinfo[i].msg, 1);

		add_assoc_string(iter_array, "admin", queryactive->activeinfo[i].admin, 1);

		add_assoc_string(iter_array, "ap", queryactive->activeinfo[i].ap, 1);

		add_assoc_string(iter_array, "user", queryactive->activeinfo[i].user, 1);

		add_assoc_string(iter_array, "guest", queryactive->activeinfo[i].guest, 1);

		add_assoc_long(iter_array, "archived", archived);
		
	    add_next_index_zval(iter, iter_array);
		if(queryactive->activeinfo[i]._id == maxid)
		{
			maxid = queryactive->activeinfo[i]._id;
		}
	}
	return maxid;
}

int assemble_all_alert_to_php_object(zval * iter, query_active *queryactive, alert_info_s *alert_ids)
{
	int i = 0;	
	int maxid = 0;
	double time = 0;
    zval *iter_array;
	
	for(i = 0; i < queryactive->row_num; i++)
	{
	    MAKE_STD_ZVAL(iter_array);
	    array_init(iter_array);
		add_assoc_long(iter_array, "_id", (long)queryactive->activeinfo[i]._id);
		// pending data
		//add_assoc_long(iter_array, "time", (long)(queryactive.activeinfo[i].time));

		add_assoc_string(iter_array, "datetime", (char *)queryactive->activeinfo[i].event_time, 1);
		
		time = (double)get_time_t_from_db_format_time((char *)queryactive->activeinfo[i].event_time);
		time *= 1000;/*set to microsecond */
		
		add_assoc_double(iter_array, "time", (double)time);

		add_assoc_string(iter_array, "key", (char *)queryactive->activeinfo[i].event, 1);

		add_assoc_string(iter_array, "msg", (char *)queryactive->activeinfo[i].msg, 1);

		add_assoc_string(iter_array, "admin", queryactive->activeinfo[i].admin, 1);

		add_assoc_string(iter_array, "ap", queryactive->activeinfo[i].ap, 1);

		add_assoc_string(iter_array, "user", queryactive->activeinfo[i].user, 1);

		add_assoc_string(iter_array, "guest", queryactive->activeinfo[i].guest, 1);

		add_assoc_long(iter_array, "archived", alert_ids[i].archived);
		
	    add_next_index_zval(iter, iter_array);
		if(queryactive->activeinfo[i]._id > maxid)
		{
			maxid = queryactive->activeinfo[i]._id;
		}
	}
	return maxid;
}

#endif
EXT_FUNCTION(ext_get_alert_with_filter)
{
    int ret = -1;
	int maxid = 0;
	int count = 0;
	long archived = 0;
    zval *iter;
    MAKE_STD_ZVAL(iter);
    array_init(iter);
	alert_info_s alert_ids[256];
    DBusConnection *connection = NULL;
	
	memset(&alert_ids, 0, sizeof(alert_info_s)*256);
#ifdef OBJECT_ACTIVE_SUPPORT
	query_active queryactive;
	//memset(&queryactive, 0, sizeof(query_active));
#endif
	ext_para_get(argc, argv, EXT_TYPE_LONG, &archived);
	
#if ACTIVE_DEBUG_ENABLE
	syslog(LOG_DEBUG, "get all alert with filter archived %ld ", archived);
#endif
    ret = dbus_connection_init(&connection);
    if(!connection || 0 != ret)
    {
        syslog(LOG_ERR, "dbus connection init failed when archive_alert_by_id %ld ret %d", archived, ret);
        if(connection)
        {           
            uninit_dbus_connection(&connection);
        }
        RETURN_LONG(-1);
    } 
	//ret = db_get_all_alertinfo_after_id_by_archived(0/*get all*/, &queryactive, (int)archived);/*archived -1 all, 1 true , 0 false*/
    ret = hand_get_ap_alert_ids(alert_ids, connection);
	//if(archived == -1 || archived == 1)
	if(0 == ret)
	{
#ifdef OBJECT_ACTIVE_SUPPORT
		memset(&queryactive, 0, sizeof(query_active));
		ret = db_get_all_activeinfo_by_ids((alert_info_db_s *)alert_ids, archived, &queryactive);
		count = queryactive.row_num;
#if ACTIVE_DEBUG_ENABLE
		db_log_query_active(&queryactive);
#endif
		if(archived != -1)
		{
			maxid = assemble_alert_to_php_object_by_archived(iter, &queryactive, archived);
		}
		else
		{
			maxid = assemble_all_alert_to_php_object(iter, &queryactive, alert_ids);
		}
		db_destroy_object_active(queryactive.activeinfo);
	}
	else if(-1 == ret)
	{
		ret = 0; /*ignor this error*/
	}
	
#if 0
	if(archived == -1 || archived == 0)
	{	
		memset(&queryactive, 0, sizeof(query_active));
		ret = db_get_all_activeinfo_by_ids(unarchived_ids, &queryactive);
		archived = 0;
		count += queryactive.row_num;
#if ACTIVE_DEBUG_ENABLE
		db_log_query_active(&queryactive);
#endif
		maxid += assemble_alert_to_php_object(iter, &queryactive, archived);
		db_destroy_object_active(queryactive.activeinfo);
	}
#endif
#endif
#if 0
#ifdef OBJECT_ACTIVE_SUPPORT
#if ACTIVE_DEBUG_ENABLE	
	db_log_query_active(&queryactive);
#endif
#endif
	//add_assoc_long(iter_array, "result", (long)ret);

#ifdef OBJECT_ACTIVE_SUPPORT
	if(0 == ret)
	{
		for(i = 0; i < queryactive.row_num; i++)
		{
		    MAKE_STD_ZVAL(iter_array);
		    array_init(iter_array);
			add_assoc_long(iter_array, "_id", (long)queryactive.activeinfo[i]._id);
			// pending data
			//add_assoc_long(iter_array, "time", (long)(queryactive.activeinfo[i].time));

			add_assoc_string(iter_array, "datetime", (char *)queryactive.activeinfo[i].event_time, 1);
			
			time = (double)get_time_t_from_db_format_time((char *)queryactive.activeinfo[i].event_time);
			time *= 1000;/*set to microsecond */
			
			add_assoc_double(iter_array, "time", (double)time);

			add_assoc_string(iter_array, "key", (char *)queryactive.activeinfo[i].event, 1);

			add_assoc_string(iter_array, "msg", (char *)queryactive.activeinfo[i].msg, 1);

			add_assoc_string(iter_array, "admin", queryactive.activeinfo[i].admin, 1);

			add_assoc_string(iter_array, "ap", queryactive.activeinfo[i].ap, 1);

			add_assoc_string(iter_array, "user", queryactive.activeinfo[i].user, 1);

			add_assoc_string(iter_array, "guest", queryactive.activeinfo[i].guest, 1);

			add_assoc_long(iter_array, "archived", queryactive.activeinfo[i].archived);
			
		    add_next_index_zval(iter, iter_array);
			if(queryactive.activeinfo[i]._id == maxid)
			{
				maxid = queryactive.activeinfo[i]._id;
			}
			count++;
		}
	}
	
#endif
	
	db_destroy_object_active(queryactive.activeinfo);
#endif
    if(connection)
    {
        uninit_dbus_connection(&connection);
    }
	if(object_init(return_value) != SUCCESS)
    {
        RETURN_LONG(PHP_OBJ_INIT_FAIL);
    }
	
    //add_assoc_long(iter_max, "lastId", (long)maxid);
    add_property_long(return_value, "result", (long)ret);
    add_property_long(return_value, "count", (long)count);
    add_property_long(return_value, "lastId", (long)maxid);
    add_property_zval(return_value, "value", iter); 
}

EXT_FUNCTION(ext_archive_alert_by_activeid_apmac)
{
	int i = 0;
    int ret = -1;
	//long _id = 0;
	long activeid = 0;
	char * apmac = NULL;
	char *tmpPtr = NULL;
	unsigned char  macArr[MAC_LEN] = {0};
    DBusConnection *connection = NULL;
	
	//ext_para_get(argc, argv, EXT_TYPE_LONG, &_id);
	ext_para_get(argc, argv, EXT_TYPE_LONG, &activeid, EXT_TYPE_STRING, &apmac);
#if ACTIVE_DEBUG_ENABLE
	syslog(LOG_DEBUG, "archive alertinfo by activeid %ld and apmac %s ", activeid, apmac);
#endif

	tmpPtr = strtok(apmac, ":");
	while(tmpPtr && i < MAC_LEN)
	{
		macArr[i++] = (unsigned char)strtoul(tmpPtr, NULL, 16);
		tmpPtr = strtok(NULL, ":");
	}
    ret = dbus_connection_init(&connection);
    if(!connection || 0 != ret)
    {
        syslog(LOG_ERR, "dbus connection init failed when archive_alert_by_id %ld ret %d", activeid, ret);
        if(connection)
        {           
            uninit_dbus_connection(&connection);
        }
        RETURN_LONG(-1);
    }   
#ifdef OBJECT_ACTIVE_SUPPORT

	//ret = db_archive_alertinfo_by_id((int)_id);/**/
    
#endif
    ret = hand_archive_alertinfo_by_activeid_apmac(macArr, (int)activeid, connection);
	
#if ACTIVE_DEBUG_ENABLE
		syslog(LOG_DEBUG, "archive alertinfo by id %ld mac %02x:%02x:%02x:%02x:%02x:%02x, ret %d", activeid, 
			macArr[0], macArr[1], macArr[2], macArr[3], macArr[4], macArr[5], ret);
#endif

	if(0 != ret)
	{
		syslog(LOG_DEBUG, "archive alertinfo by activeid %ld apmac %s failed, ret %d", activeid, apmac, ret);
	}
    if(connection)
    {
        uninit_dbus_connection(&connection);
    }
    
	RETURN_LONG(ret);
}

EXT_FUNCTION(ext_archive_all_alert)
{
    int ret = -1;
    DBusConnection *connection = NULL;
    
    ret = dbus_connection_init(&connection);
    if(!connection || 0 != ret)
    {
        syslog(LOG_ERR, "dbus connection init failed when archive_all_alert ret %d", ret);
        if(connection)
        {           
            uninit_dbus_connection(&connection);
        }
        RETURN_LONG(-1);
    }   
#if ACTIVE_DEBUG_ENABLE
	syslog(LOG_DEBUG, "archive all alertinfo");
#endif
#ifdef OBJECT_ACTIVE_SUPPORT

	//ret = db_archive_all_alertinfo();
#endif
    ret = hand_archive_all_alert(connection);
	if(0 != ret)
	{
		syslog(LOG_DEBUG, "archive all alertinfo failed, ret %d", ret);
	}
    if(connection)
    {
        uninit_dbus_connection(&connection);
    }
	RETURN_LONG(ret);

}
EXT_FUNCTION(ext_add_upgrade_active_to_db)
{
	char * mac = NULL;
	char * operater = NULL;
	char * version = NULL;
	char * key = NULL;
	char * ip = NULL;
	int step = 0;
	int ret = 0;
	char apinfo[128] = {0};
	
	ext_para_get(argc, argv, EXT_TYPE_STRING, &mac, EXT_TYPE_STRING, &ip, EXT_TYPE_STRING, &operater, 
		EXT_TYPE_STRING, &version, EXT_TYPE_STRING, &key);
/*
key:
	cannot_found_image
	no_describe_file
	no_md5_file
	md5_erro
	invalid_board
	wrong_size
	tar_version_faild
	invalid_firmware_file
	
	workos_sysupgrade
	cannot_get_image
	get_the_image
	sysupgrade_end   // after upgrade befor reboot
	sysupgrade_start_successfull  //after upgrade and reboot
	sysupgrede_successfull_from_minios //after upgrade and reboot
*/
	if(!strcmp(key, "workos_sysupgrade") || !strcmp(key, "minios_sysupgrade"))
	{
		if(!strncmp(operater, "Admin:", 6))
		{
			step = AP_UPGRADE_BY_ADMIN_START;
			operater = operater+6;
		}
		else
		{
			step = AP_AUTO_UPGRADE_START;
		}
	}
	else if(!strcmp(key, "sysupgrade_start_successfull") 
		|| !strcmp(key, "sysupgrede_successfull_from_minios"))
	{
		if(!strncmp(operater, "Admin:", 6))
		{
			step = AP_UPGRADED_BY_ADMIN_SUCCESS;
			operater = operater+6;
		}
		else
		{
			step = AP_AUTO_UPGRADED_SUCCESS;
		}
	}
	else if(!strcmp(key, "get_the_image") || !strcmp(key, "sysupgrade_end"))
	{
		if(!strncmp(operater, "Admin:", 6))
		{
			step = AP_UPGRADE_BY_ADMIN_STEP;
			operater = operater+6;
		}
		else
		{
			step = AP_AUTO_UPGRADE_STEP;
		}
	}
	else
	{
		if(!strncmp(operater, "Admin:", 6))
		{
			step = AP_UPGRADE_BY_ADMIN_FAILED;
			operater = operater+6;
		}
		else
		{
			step = AP_AUTO_UPGRADE_FAILED;
		}
	}
	if(strcmp(mac, "") && strcmp(ip, ""))
	{
		snprintf(apinfo, 127, "%s,%s", mac, ip);
	}
	else if(strcmp(mac, ""))
	{
		snprintf(apinfo, 127, "%s", mac);
	}
	else if(strcmp(ip, ""))
	{
		snprintf(apinfo, 127, "%s", ip);
	}
	else
	{
		snprintf(apinfo, 127, "unknown_ap");
	}
	ret = active_ap_upgrade_to_version(apinfo, operater, version, key, step);
	//YLog("upgrade[%s] afi[%s] to version %s by %s ", key, mac, version, operater);
	
	if(0 != ret)
	{
		syslog(LOG_DEBUG, "add upgrade active %d mac %s ip %s operater %s version %s key %s to database failed, ret %d", 
			step, mac, ip, operater, version, key, ret);
	}
	RETURN_LONG(ret);
}
EXT_FUNCTION(ext_ap_down_pubkey_step_info)
{
	char * mac = NULL;
	char * key = NULL;
	char * ip = NULL;
	int step = 0;
	int ret = 0;
	char apinfo[128] = {0};
	
	ext_para_get(argc, argv, EXT_TYPE_STRING, &mac, EXT_TYPE_STRING, &ip, EXT_TYPE_STRING, &key);
/*
key:
	get_pubkey_fail
	save_pubkey_fail
	get_save_pubkey_success
*/
	if(!strcmp(key, "get_pubkey_fail") )
	{
		step = AP_DOWNLOAD_PUBKEY_FAILED;
	}
	else if(!strcmp(key, "save_pubkey_fail"))
	{
		step = AP_SAVE_PUBKEY_FAILED;
	}
	else if(!strcmp(key, "get_save_pubkey_success"))
	{
		step = AP_DOWNLOAD_SAVE_PUBKEY_SUCCESS;
	}
	if(strcmp(mac, "") && strcmp(ip, ""))
	{
		snprintf(apinfo, 127, "%s,%s", mac, ip);
	}
	else if(strcmp(mac, ""))
	{
		snprintf(apinfo, 127, "%s", mac);
	}
	else if(strcmp(ip, ""))
	{
		snprintf(apinfo, 127, "%s", ip);
	}
	else
	{
		snprintf(apinfo, 127, "unknown_ap");
	}
	ret = active_ap_actived_or_changed(apinfo,step);
	//YLog("authorize to AFC %s from afi[%s]", key, mac);
	
	if(0 != ret)
	{
		syslog(LOG_DEBUG, "add afi[ip %s mac %s] active %d failed, ret %d", ip, mac, step, ret);
	}
	RETURN_LONG(ret);
}

