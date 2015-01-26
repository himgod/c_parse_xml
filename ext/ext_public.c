#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
//#include <dbus/dbus.h>
#include "php.h"
#include "php_ini.h"
#include "ext_public.h"
//#include "ext_vlan.h"
//#include "ws_init_dbus.h"
//#include "wcpss/waw.h"

void ext_para_parser(unsigned int ht, zval ***argv)
{
    if(ht > EXT_MAX_ARGC)
        ext_exit(EXT_EXIT_PARAM_NUM);

    if(zend_get_parameters_array_ex(ht, argv) == FAILURE)
        ext_exit(EXT_EXIT_PARAM_FAILED);
}

void ext_function_handle(int argc, zval ***argv, zval *return_value, int count, ext_func_handle_t *func_list)
{
    char *func = NULL;
    unsigned int param = 0;
    int i;

    convert_to_string_ex(argv[0]);
    for(i = 0; i < count; i++)
    {
       func = func_list[i].func;
       param = func_list[i].param;

       if(!strncmp(Z_STRVAL_PP(argv[0]), func, strlen(func) + 1))
       {
           if(argc != param)
           {
               ext_exit("Does not match the number of parameters");
           }
           func_list[i].ac_func_t(param, argv, return_value);
           return;
       }
    }
    ext_exit("entry not found");
}   

void ext_para_get(int argc, zval ***argv, ...)
{
    va_list ap;
    va_start(ap, argv);

    double *d; 
    long *l;
    char **s;
    int * in;

    int i = 0, c;

    while(++i < argc) 
    {
        c = va_arg(ap, int);
        switch(c)
        {
            case EXT_TYPE_DOUBLE: 
                convert_to_double_ex(argv[i]);
                d = va_arg(ap, double*);
                *d = Z_DVAL_PP(argv[i]);
                break;
            case EXT_TYPE_LONG: 
                convert_to_long_ex(argv[i]);
                l = va_arg(ap, long*);
                *l = Z_LVAL_PP(argv[i]);
                break;
            case EXT_TYPE_INT: 
                convert_to_long_ex(argv[i]);
                in = va_arg(ap, int*);
                *in = Z_LVAL_PP(argv[i]);
                break;
            case EXT_TYPE_STRING: 
                convert_to_string_ex(argv[i]);
                s = va_arg(ap, char **);
                *s = Z_STRVAL_PP(argv[i]);
                break;
            default:
                ext_exit("wrong type");
        }
    }
    va_end(ap);
}

int ext_common_string_valid(const char *str, int length)
{
    int i;
    if(strlen(str) > length){
        ext_syslog("%s is too long, out of ranges", str);
        return FAILURE;
    }
    for(i = 0; i < strlen(str); i++)
    {
        if((isalpha(str[i])) || (isdigit(str[i])) || (str[i] == '_')) {
            continue;
        }
        else {
            return FAILURE;
        }
    }
    return SUCCESS;
}

