#ifndef _PHP_EXT_OPERATE_H
#define _PHP_EXT_OPERATE_H

#define    MINION_FILE_PATH    "/etc/salt/minion_id"

void ext_operate_handle(int argc, zval ***argv, zval *return_value);

EXT_FUNCTION (ext_operate_get_service_code);


#endif