#include <stdio.h>
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

#include "ext_operate.h"


ext_func_handle_t ext_operate_list[] = 
{
	{"get_service_code", 1, (php_func_t)ext_operate_get_service_code},
};

void ext_operate_handle(int argc, zval ***argv, zval *return_value)
{
    int count = sizeof(ext_operate_list)/sizeof(ext_operate_list[0]);
    ext_function_handle(argc, argv, return_value, count, ext_operate_list);
}

EXT_FUNCTION (ext_operate_get_service_code)
{
	char buf[128];
	zval *iter;
	MAKE_STD_ZVAL(iter);
	array_init(iter);
	
	memset(buf, 0, sizeof(buf));
	
	FILE *fp = fopen(MINION_FILE_PATH, "r");
	if (NULL == fp) {
		syslog(LOG_ERR, "open %s error!\n", MINION_FILE_PATH);
		RETURN_LONG(-1);
	}
	char *ret = fgets(buf, sizeof(buf), fp);
	if (NULL == ret) {
		syslog(LOG_ERR, "read %s error!\n", MINION_FILE_PATH);
		RETURN_LONG(-1);
	}
	fclose(fp);
	buf[strlen(buf)-1] = 0;
	//syslog(LOG_ERR, "service_code: %s+++++++++++++\n", buf);
	add_assoc_string(iter, "service_code", (char *)(buf), 1);
	if(object_init(return_value) != SUCCESS)
	{
		RETURN_LONG(PHP_OBJ_INIT_FAIL);
	}
	
	add_property_zval(return_value, "value", iter);
}

