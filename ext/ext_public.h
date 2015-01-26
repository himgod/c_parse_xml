#ifndef _PHP_EXT_PUBLIC_H_
#define _PHP_EXT_PUBLIC_H_

//#include <dbus/dbus.h>

#define EXT_TYPE_DOUBLE     'd'
#define EXT_TYPE_STRING     's'    
#define EXT_TYPE_LONG       'l'
#define EXT_TYPE_INT 	    'i'
#define EXT_TYPE_LIST       'L'
#define EXT_TYPE_NONE_LIST  'N'

#define DBUS_BUSNAME        "ac.php"
//#define DBUS_OBJECT         "/dbus/php"
//#define DBUS_INTERFACE      "dbus.php"

#define EXT_EXIT_PARAM_FAILED       "Parameter Failed "            //Parameter obtain failed
#define EXT_EXIT_PARAM_NUM          "Parameter Number "            //Parameter number error 
#define EXT_EXIT_PARAM_FORMAT       "Parameter Format "            //Parameter format error
#define EXT_EXIT_MEMORY             "Out of Memroy "               //Parameter is empty
#define EXT_EXIT_DEBUG              "Not support"                  //Does not support this feature

#define EXT_MAX_ARGC            20
#define MAX_SLOT 				16
#define MAX_INSTANCE			16

/* ignore warnings for unused-but-set-variable in gcc 4.6
  *
  * New -Wunused-but-set-variable and -Wunused-but-set-parameter warnings
     were added for C, C++, Objective-C and Objective-C++.
     These warnings diagnose variables respective parameters which
     are only set in the code and never otherwise used. 
     Usually such variables are useless and often even the value assigned 
     to them is computed needlessly, sometimes expensively. 
     The -Wunused-but-set-variable warning is enabled by default by -Wall flag and
     -Wunused-but-set-parameter by -Wall -Wextra flags.
 */
#define IGNORE_UBSV	__attribute__((unused))

#define ext_syslog(format, args...) zend_error(E_NOTICE, "%s:%d:%s->"format, __FILE__, __LINE__, __func__, ##args)

#define ext_exit(format, args...) do{ \
             ext_syslog(format, ##args); exit(0);}while(0/*CONSTANT*/)


#define EXT_INTERNAL_LIST_PARAMETERS        int argc, zval ***argv, zval *return_value
#define EXT_LIST(name)                      void name(EXT_INTERNAL_LIST_PARAMETERS)

#define EXT_INTERNAL_FUNC_PARAMETERS        int argc, zval ***argv, zval *return_value
#define EXT_FUNCTION(name)                 void name(EXT_INTERNAL_FUNC_PARAMETERS)

#define SEM_ACTIVE_MASTER_SLOT_ID_PATH "/dbm/product/active_master_slot_id"

typedef int (*php_func_t)(int argc, zval *** argv, zval * return_value);

typedef struct ext_function {
    char *func;
    int param;
    int (*ac_func_t)(int argc, zval ***argv, zval *return_value);
}ext_func_handle_t;

int ext_object_construct(int, zval ***, zval *);
void ext_function_handle(int argc, zval ***argv, zval *return_value, int count, ext_func_handle_t *func_list);
void ext_parameter_parser(int, zval ***, unsigned int);
void ext_para_parser(unsigned int ht, zval ***argv);
void ext_para_get(int argc, zval ***argv, ...);

#endif /* _PHP_EXT_PUBLIC_H_ */
