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
#include "ext_admin.h"
//#include "ext_dbus.h"
#include "dbop.h"

#define FUNC_LINE_FORMAT "%s-%d"
#define FUNC_LINE_VALUE __func__,__LINE__

#define ADMIN_DEBUG_ENABLE 1
#define THIS_HANDLE_FUNC_LIST admin_func_list
ext_func_handle_t THIS_HANDLE_FUNC_LIST[] = {
    {"init_softac_config", 1, (php_func_t)ext_init_softac_config},
    {"check_user_passwd", 4, (php_func_t)ext_check_user_passwd},
    {"get_userinfo_by_id", 2, (php_func_t)ext_get_userinfo_by_id},
    {"update_userinfo_by_id_or_passwd", 10, (php_func_t)ext_update_userinfo_by_id_or_passwd},
    {"add_new_user_to_admin_user", 7, (php_func_t)ext_add_new_user_to_admin_user},
    {"get_admin_userinfo_count", 1, (php_func_t)ext_get_admin_userinfo_count},
    {"get_userinfo_by_name", 2, (php_func_t)ext_get_userinfo_by_name},
};

void ext_admin_handle(int argc, zval ***argv, zval *return_value)
{
    int count = sizeof(THIS_HANDLE_FUNC_LIST)/sizeof(THIS_HANDLE_FUNC_LIST[0]);
    ext_function_handle(argc, argv, return_value, count, THIS_HANDLE_FUNC_LIST);
}
EXT_FUNCTION(ext_init_softac_config)
{/* reset afc to default */
    long ret = 0;
    int ret2 = 0;
    ret = (long)system("mysql -uroot -pautelan < /opt/run/db/softacDB.sql");
    if(0 != ret)
    {
        syslog(LOG_ERR, FUNC_LINE_FORMAT" call system failed ret %ld", FUNC_LINE_VALUE, ret);
    }
    ret2 = system("sudo cp -f /var/www/afc/xml_php.xml /opt/run/afcconf/;"
            "sudo chmod 777 /opt/run/afcconf/xml_php.xml;"
            "sudo /opt/bin/startwid.sh");
    if(0 != ret2)
    {
        syslog(LOG_ERR, FUNC_LINE_FORMAT" call system failed ret %d", FUNC_LINE_VALUE, ret2);
    }
    ret2 = system("rm -f /var/www/afc/session/sess_*");
    if(0 != ret2)
    {
        syslog(LOG_ERR, FUNC_LINE_FORMAT" call system failed ret %d", FUNC_LINE_VALUE, ret2);
    }
    RETURN_LONG(ret);
}

EXT_FUNCTION(ext_check_user_passwd)
{
    int ret = -1;
	char * userName = NULL;
	char * passwd = NULL;
	char * userip = NULL;
	time_t now;
	
#ifdef ADMIN_USER_SUPPORT
	admin_user userinfo;
	memset(&userinfo, 0, sizeof(admin_user));
#endif
    zval *iter_array;
    MAKE_STD_ZVAL(iter_array);
    array_init(iter_array);
	ext_para_get(argc, argv, EXT_TYPE_STRING, &userName, EXT_TYPE_STRING, &passwd, EXT_TYPE_STRING, &userip);
	
#ifdef ADMIN_USER_SUPPORT
	strncpy(userinfo.name, userName, (USER_NAME_LEN-1));
	strncpy(userinfo.passwd, passwd, (USER_PASSWD_LEN-1));
	strncpy(userinfo.last_login_ip, userip, (USER_LAST_LOGIN_IP_LEN-1));
#if ADMIN_DEBUG_ENABLE
	now = time(NULL);
	syslog(LOG_DEBUG, "check user passwd user %s login server at %s from '%s' use passwd '%s'", 
		userName, ctime(&now), userip, passwd);
#endif
	ret = db_check_user_passwd(&userinfo, 1);/*login=1: is login action, to update login ip and time  */
#endif
#if ADMIN_DEBUG_ENABLE
#ifdef ADMIN_USER_SUPPORT
	syslog(LOG_DEBUG, "check user passwd ret %d , username %s passwd %s loginip %s "
		"userid %d administrator %d language %s logintime "STR_FORMAT" loginip '%s'", 
		ret, userName, passwd, userip, userinfo._id, userinfo.administrator, 
		userinfo.language, STR_VALUE(userinfo.last_login_time), userinfo.last_login_ip);
#else
	syslog(LOG_DEBUG, "check user passwd ret %d , username %s passwd %s loginip %s",
		ret, userName, passwd, userip);
#endif

#endif
	add_assoc_long(iter_array, "result", (long)ret);

#ifdef ADMIN_USER_SUPPORT
	if(TRUE == ret && -1 != userinfo._id)
	{
		add_assoc_long(iter_array, "_id", (long)userinfo._id);

		add_assoc_long(iter_array, "administrator", (long)(userinfo.administrator == 1 ? 1:0));

		add_assoc_string(iter_array, "language", userinfo.language, 1);

		add_assoc_string(iter_array, "last_login_time", PTR_TO_STR(userinfo.last_login_time), 1);

		add_assoc_string(iter_array, "last_login_ip", userinfo.last_login_ip, 1);
	}
#endif
	
	if(object_init(return_value) != SUCCESS)
    {
        RETURN_LONG(PHP_OBJ_INIT_FAIL);
    }
	
    add_property_zval(return_value, "value", iter_array); 
}

EXT_FUNCTION(ext_get_userinfo_by_id)
{	
    int ret = -1;
	long userid = -1;
	
#ifdef ADMIN_USER_SUPPORT
	query_user qu_userinfo;
	memset(&qu_userinfo, 0, sizeof(query_user));
#endif
    zval *iter_array;
    zval *iter;
    MAKE_STD_ZVAL(iter_array);
    array_init(iter_array);
    MAKE_STD_ZVAL(iter);
    array_init(iter);
	ext_para_get(argc, argv, EXT_TYPE_LONG, &userid);

#ifdef ADMIN_USER_SUPPORT
#if ADMIN_DEBUG_ENABLE
	syslog(LOG_DEBUG, "%s line %d get userinfo by id %ld ", __func__, __LINE__, userid);
#endif
	ret = db_get_all_userinfo_by_id((int)userid, &qu_userinfo);
#endif
#if ADMIN_DEBUG_ENABLE
	syslog(LOG_DEBUG, "get userinfo by id %ld ret %d ", userid, ret);
#ifdef ADMIN_USER_SUPPORT
	if(0 == ret && qu_userinfo.row_num > 0)
	{
		db_log_query_user(&qu_userinfo);
	}
#endif

#endif

#ifdef ADMIN_USER_SUPPORT
	if(0 == ret && qu_userinfo.row_num > 0)
	{
		add_assoc_long(iter_array, "_id", (long)qu_userinfo.userinfo[0]._id);
		add_assoc_string(iter_array, "name", qu_userinfo.userinfo[0].name, 1);
		add_assoc_string(iter_array, "x_password", qu_userinfo.userinfo[0].passwd, 1);
		add_assoc_long(iter_array, "for_hotspot", 0);
		add_assoc_long(iter_array, "currentlogin", 1);
		add_assoc_long(iter_array, "email_alert_enabled", (long)((qu_userinfo.userinfo[0].email_alert == 1) ? 1:0));
		add_assoc_string(iter_array, "email", qu_userinfo.userinfo[0].email_address, 1);
		add_assoc_string(iter_array, "lang", qu_userinfo.userinfo[0].language, 1);
		add_assoc_string(iter_array, "note", qu_userinfo.userinfo[0].note, 1);
	}
	db_destroy_admin_user(qu_userinfo.userinfo);
#endif
	
	if(object_init(return_value) != SUCCESS)
    {
        RETURN_LONG(PHP_OBJ_INIT_FAIL);
    }
	
	add_assoc_long(iter, "ret", (long)ret);
    add_property_zval(return_value, "result", iter); 
    add_property_zval(return_value, "value", iter_array); 
}


EXT_FUNCTION(ext_update_userinfo_by_id_or_passwd)
{	
    int ret = -1;
	long userid = -1;/*get current login admin user id */
	long administrator = -1;
	long email_alert = -1;
	char * oldname = NULL;
	char * oldpasswd = NULL;
	char * name = NULL;
	char * passwd = NULL;
	char * language = NULL;
	char * email_address = NULL;	
	
#ifdef ADMIN_USER_SUPPORT
	admin_user userinfo;
	memset(&userinfo, 0, sizeof(admin_user));
#endif
    zval *iter_array;
    MAKE_STD_ZVAL(iter_array);
    array_init(iter_array);
	ext_para_get(argc, argv, EXT_TYPE_LONG, &userid, EXT_TYPE_STRING, &oldname, EXT_TYPE_STRING, &name, 
		EXT_TYPE_STRING, &oldpasswd, EXT_TYPE_STRING, &passwd, EXT_TYPE_LONG, &administrator, 
		EXT_TYPE_LONG, &email_alert, EXT_TYPE_STRING, &email_address, EXT_TYPE_STRING, &language);

#ifdef ADMIN_USER_SUPPORT
	if(strcmp(passwd, ""))
	{
		strncpy(userinfo.name, oldname, (USER_NAME_LEN-1));
		strncpy(userinfo.passwd, oldpasswd, (USER_PASSWD_LEN-1));
		ret = db_check_user_passwd(&userinfo, 0);
		if(TRUE == ret)
		{
			if(userid != userinfo._id)
			{
				if(administrator == 1)
				{
					userid = userinfo._id;/*modify another line for the same name admin user */
					/* _id1 admin passwd1 */
					/* _id2 admin passwd2 */
					/*... */
					ret = 2;/*2 means modify another same name user's info */
				}
				else
				{
					ret = 3;/*not admin user but try to modify other user's info */
				}
				
			}
			memset(&userinfo, 0, sizeof(admin_user));
		}
		else
		{
			ret = -2;/*-2 means check old passwd failed*/
		}
	}
	else
	{
		ret = TRUE;
	}
	if(TRUE == ret || 2 == ret)
	{
		userinfo._id = (int)userid;
		userinfo.administrator = (char)administrator;
		userinfo.email_alert = (char)email_alert;
		strncpy(userinfo.name, name, (USER_NAME_LEN-1));
		strncpy(userinfo.passwd, passwd, (USER_PASSWD_LEN-1));
		strncpy(userinfo.language, language, (USER_LANGUAGE_LEN-1));
		strncpy(userinfo.email_address, email_address, (USER_EMAIL_LEN-1));
#if ADMIN_DEBUG_ENABLE
		syslog(LOG_DEBUG, "%s line %d update userinfo by id %d oldname '%s' oldpasswd '%s'", 
			__func__, __LINE__, userinfo._id, oldname, oldpasswd);
		db_output_userinfo(&userinfo);
#endif
		ret = db_update_userinfo_by_id(&userinfo);
#if ADMIN_DEBUG_ENABLE
		syslog(LOG_DEBUG, "update userinfo by id %d ret %d ", userinfo._id, ret);
#endif
#endif
	}
	add_assoc_long(iter_array, "result", (long)ret);

	if(object_init(return_value) != SUCCESS)
    {
        RETURN_LONG(PHP_OBJ_INIT_FAIL);
    }
	
    add_property_zval(return_value, "value", iter_array); 
}
EXT_FUNCTION(ext_get_admin_userinfo_count)
{
	query_user queryuser;
	int ret = -1;
	int count = 0;
	int i = 0;
    zval *iter_array;
    MAKE_STD_ZVAL(iter_array);
    array_init(iter_array);
	
	memset(&queryuser, 0, sizeof(query_user));
	ret = db_get_userinfo_list(&queryuser);
	count = 0;
	if(0 == ret && queryuser.row_num > 0)
	{
		for(i = 0; i < queryuser.row_num; i++)
		{
			if(1 == queryuser.userinfo[i].administrator)
			{
				count++;
			}
		}
	}
	db_destroy_admin_user(queryuser.userinfo);
	
	add_assoc_long(iter_array, "result", (long)count);

	if(object_init(return_value) != SUCCESS)
    {
        RETURN_LONG(PHP_OBJ_INIT_FAIL);
    }
	
    add_property_zval(return_value, "value", iter_array); 
}
EXT_FUNCTION(ext_add_new_user_to_admin_user)
{	
    int ret = -1;
	long administrator = -1;
	long email_alert = -1;
	char * name = NULL;
	char * passwd = NULL;
	char * language = NULL;
	char * email_address = NULL;	
	
#ifdef ADMIN_USER_SUPPORT
	admin_user userinfo;
	memset(&userinfo, 0, sizeof(admin_user));
#endif
    zval *iter_array;
    MAKE_STD_ZVAL(iter_array);
    array_init(iter_array);
	ext_para_get(argc, argv, EXT_TYPE_STRING, &name, EXT_TYPE_STRING, &passwd, EXT_TYPE_LONG, &administrator, 
		EXT_TYPE_LONG, &email_alert, EXT_TYPE_STRING, &email_address, EXT_TYPE_STRING, &language);

#ifdef ADMIN_USER_SUPPORT
	
	{
		userinfo.administrator = (char)administrator;
		userinfo.email_alert = (char)email_alert;
		strncpy(userinfo.name, name, (USER_NAME_LEN-1));
		strncpy(userinfo.passwd, passwd, (USER_PASSWD_LEN-1));
		strncpy(userinfo.language, language, (USER_LANGUAGE_LEN-1));
		strncpy(userinfo.email_address, email_address, (USER_EMAIL_LEN-1));
#if ADMIN_DEBUG_ENABLE
		syslog(LOG_DEBUG, "%s line %d add userinfo into admin user, name '%s' administrator %ld language '%s'", 
			__func__, __LINE__, name, administrator, language);

#endif
		ret = db_add_userinfo_into_admin_user(&userinfo);
#if ADMIN_DEBUG_ENABLE
		syslog(LOG_DEBUG, "add userinfo into admin_user _id %d ret %d ", userinfo._id, ret);
#endif
#endif
	}
	add_assoc_long(iter_array, "result", (long)ret);
	add_assoc_long(iter_array, "userid", (long)userinfo._id);

	if(object_init(return_value) != SUCCESS)
    {
        RETURN_LONG(PHP_OBJ_INIT_FAIL);
    }
	
    add_property_zval(return_value, "value", iter_array); 
}
EXT_FUNCTION(ext_get_userinfo_by_name)
{
	query_user queryuser;
	char * username = NULL;
	int ret = -1;
	int count = 0;
	int i = 0;
    zval *iter_array, *iter;
    MAKE_STD_ZVAL(iter);
    array_init(iter);
	
    zval *iter_len;
    MAKE_STD_ZVAL(iter_len);
    array_init(iter_len);
	
	memset(&queryuser, 0, sizeof(query_user));
	ext_para_get(argc, argv, EXT_TYPE_STRING, &username);
	ret = db_get_all_userinfo_by_name(username, &queryuser);
	count = 0;
	if(0 == ret && queryuser.row_num > 0)
	{
		for(i = 0; i < queryuser.row_num; i++)
		{
		    MAKE_STD_ZVAL(iter_array);
		    array_init(iter_array);
			add_assoc_long(iter_array, "_id", (long)queryuser.userinfo[i]._id);
			add_assoc_string(iter_array, "name", queryuser.userinfo[i].name, 1);
			add_assoc_string(iter_array, "x_password", queryuser.userinfo[i].passwd, 1);
			add_assoc_long(iter_array, "email_alert_enabled", (long)((queryuser.userinfo[i].email_alert == 1) ? 1:0));
			add_assoc_string(iter_array, "email", queryuser.userinfo[i].email_address, 1);
			add_assoc_string(iter_array, "lang", queryuser.userinfo[i].language, 1);
			add_assoc_string(iter_array, "note", queryuser.userinfo[i].note, 1);
			
		    add_next_index_zval(iter, iter_array);
		}
		count = queryuser.row_num;
	}
	db_destroy_admin_user(queryuser.userinfo);
	
	if(object_init(return_value) != SUCCESS)
    {
        RETURN_LONG(PHP_OBJ_INIT_FAIL);
    }
	
    add_assoc_long(iter_len, "count", (long)count);
    add_property_zval(return_value, "users", iter_len);
    add_property_zval(return_value, "value", iter); 
}

