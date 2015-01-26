#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext_main.h"
//#include "ws_dbus_list.h"
#include "ext_public.h"

#include "ext_funcpublic.h"
#include "ext_sys_config.h"
#include "ext_wireless.h"
#include "ext_wtp.h"
#include "ext_map.h"
#include "ext_admin.h"
#include "ext_active.h"
#include "ext_history.h"
#include "ext_operate.h"

static zval **ext_argv[EXT_MAX_ARGC];

/* If you declare any globals in php_ext.h uncomment this: */
ZEND_DECLARE_MODULE_GLOBALS(ext)

/* True global resources - no need for thread safety here
static int le_ext;
*/

/* {{{ ext_functions[]
 *
 * Every user visible function must have an entry in ext_functions[].
 */
const zend_function_entry ext_functions[] = {
    PHP_FE(ext_wireless,    NULL)
    PHP_FE(ext_wtp,    NULL)
    PHP_FE(ext_map,    NULL)
    PHP_FE(ext_admin,    NULL)
    PHP_FE(ext_active,    NULL)
    PHP_FE(ext_sys_manage,   NULL)
    PHP_FE(ext_funcpublic,    NULL)
    PHP_FE(ext_history,    NULL)
    PHP_FE(ext_operate,    NULL)
    PHP_FE_END	
};
/* }}} */

/* {{{ ext_module_entry
 */
zend_module_entry ext_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
    
#endif
	"ext",
	ext_functions,
	PHP_MINIT(ext),
	PHP_MSHUTDOWN(ext),
	PHP_RINIT(ext),		/* Replace with NULL if there's nothing to do at request start */
	PHP_RSHUTDOWN(ext),	/* Replace with NULL if there's nothing to do at request end */
	PHP_MINFO(ext),
#if ZEND_MODULE_API_NO >= 20010901
	"0.1", /* Replace with version number for your extension */
#endif
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_EXT
ZEND_GET_MODULE(ext)
#endif

/* {{{ PHP_INI
 PHP_SAMPLE_PERSON_RES_NAME*/
/* Remove comments and fill if you need to have entries in php.ini
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("ext.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_ext_globals, ext_globals)
    STD_PHP_INI_ENTRY("ext.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_ext_globals, ext_globals)
PHP_INI_END()
*/
/* }}} */

/* {{{ php_ext_init_globals
 */
/* Uncomment this function if you have INI entries */
static void php_ext_init_globals(zend_ext_globals *ext_globals)
{
    //ccgi_dbus_init();
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(ext)
{
	/* If you have INI entries, uncomment these lines 
	REGISTER_INI_ENTRIES();
	*/
	ZEND_INIT_MODULE_GLOBALS(ext, php_ext_init_globals, NULL);
	return SUCCESS;
}
/* }}} */    

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(ext)
{
	/* uncomment this line if you have INI entries
	UNREGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(ext)
{
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(ext)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(ext)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "ext support", "enabled");
	php_info_print_table_end();

	/* Remove comments if you have entries in php.ini
	DISPLAY_INI_ENTRIES();
	*/
}
/* }}} */


PHP_FUNCTION(ext_sys_manage)
{
    ext_para_parser(ZEND_NUM_ARGS(), ext_argv);
    ext_sys_manage_handle(ZEND_NUM_ARGS(), ext_argv, return_value);
}

PHP_FUNCTION(ext_funcpublic) {
    ext_para_parser(ZEND_NUM_ARGS(), ext_argv);
    ext_funcpublic_handle(ZEND_NUM_ARGS(), ext_argv, return_value);
}

PHP_FUNCTION(ext_wireless) {
    ext_para_parser(ZEND_NUM_ARGS(), ext_argv);
    ext_wireless_handle(ZEND_NUM_ARGS(), ext_argv, return_value);
}

PHP_FUNCTION(ext_wtp) {
    ext_para_parser(ZEND_NUM_ARGS(), ext_argv);
    ext_wtp_handle(ZEND_NUM_ARGS(), ext_argv, return_value);
}

PHP_FUNCTION(ext_map) {
    ext_para_parser(ZEND_NUM_ARGS(), ext_argv);
    ext_map_handle(ZEND_NUM_ARGS(), ext_argv, return_value);
}

PHP_FUNCTION(ext_admin) {
    ext_para_parser(ZEND_NUM_ARGS(), ext_argv);
    ext_admin_handle(ZEND_NUM_ARGS(), ext_argv, return_value);
}

PHP_FUNCTION(ext_active) {
    ext_para_parser(ZEND_NUM_ARGS(), ext_argv);
    ext_active_handle(ZEND_NUM_ARGS(), ext_argv, return_value);
}

PHP_FUNCTION(ext_history) {
    ext_para_parser(ZEND_NUM_ARGS(), ext_argv);
    ext_show_history_handle(ZEND_NUM_ARGS(), ext_argv, return_value);
}

PHP_FUNCTION(ext_operate) {
    ext_para_parser(ZEND_NUM_ARGS(), ext_argv);
    ext_operate_handle(ZEND_NUM_ARGS(), ext_argv, return_value);
}


/* }}} */
