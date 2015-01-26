#ifndef _PHP_EXT_MAIN_H
#define _PHP_EXT_MAIN_H

//#include <dbus/dbus.h>

extern zend_module_entry ext_module_entry;
#define phpext_ext_ptr &ext_module_entry

#ifdef PHP_WIN32
#	define PHP_EXT_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_EXT_API __attribute__ ((visibility("default")))
#else
#	define PHP_EXT_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

PHP_MINIT_FUNCTION(ext);
PHP_MSHUTDOWN_FUNCTION(ext);
PHP_RINIT_FUNCTION(ext);
PHP_RSHUTDOWN_FUNCTION(ext);
PHP_MINFO_FUNCTION(ext);

PHP_FUNCTION(ext_test);
PHP_FUNCTION(ext_user);
PHP_FUNCTION(ext_vlan);
PHP_FUNCTION(ext_sys_manage);
PHP_FUNCTION(ext_wireless);
PHP_FUNCTION(ext_security_wlan);
PHP_FUNCTION(ext_wtp);
PHP_FUNCTION(ext_map);
PHP_FUNCTION(ext_admin);
PHP_FUNCTION(ext_active);
PHP_FUNCTION(ext_radio);
PHP_FUNCTION(ext_interface);
PHP_FUNCTION(ext_dhcp);
PHP_FUNCTION(ext_eag);
PHP_FUNCTION(ext_pdc);
PHP_FUNCTION(ext_rdc);
PHP_FUNCTION(ext_funcpublic);
PHP_FUNCTION(ext_vrrp);
PHP_FUNCTION(ext_eth_port);
PHP_FUNCTION(ext_route);
PHP_FUNCTION(ext_ebr);
PHP_FUNCTION(ext_ntp);
PHP_FUNCTION(ext_snmp);
PHP_FUNCTION(ext_bss);
PHP_FUNCTION(ext_station);
PHP_FUNCTION(ext_log);
PHP_FUNCTION(ext_history);
PHP_FUNCTION(ext_operate);



/* 
  	Declare any global variables you may need between the BEGIN
	and END macros here:     
*/
ZEND_BEGIN_MODULE_GLOBALS(ext)
ZEND_END_MODULE_GLOBALS(ext)

#ifdef ZTS
#define EXT_G(v) TSRMG(ext_globals_id, zend_ext_globals *, v)
#else
#define EXT_G(v) (ext_globals.v)
#endif

#endif	/* PHP_EXT_H */
