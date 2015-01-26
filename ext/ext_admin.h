#ifndef _PHP_EXT_ADMIN_H_
#define _PHP_EXT_ADMIN_H_


void ext_admin_handle(int argc, zval ***argv, zval *return_value);

EXT_FUNCTION(ext_init_softac_config);
EXT_FUNCTION(ext_check_user_passwd);
EXT_FUNCTION(ext_get_userinfo_by_id);
EXT_FUNCTION(ext_update_userinfo_by_id_or_passwd);
EXT_FUNCTION(ext_get_admin_userinfo_count);
EXT_FUNCTION(ext_add_new_user_to_admin_user);
EXT_FUNCTION(ext_get_userinfo_by_name);



#endif /* _PHP_EXT_ADMIN_H_ */

