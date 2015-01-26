#ifndef _PHP_EXT_ACTIVE_H_
#define _PHP_EXT_ACTIVE_H_


void ext_active_handle(int argc, zval ***argv, zval *return_value);
EXT_FUNCTION(ext_get_object_active_after_id);
EXT_FUNCTION(ext_get_object_active_after_id_with_all_filter);
EXT_FUNCTION(ext_get_alert_with_filter);
EXT_FUNCTION(ext_archive_alert_by_activeid_apmac);
EXT_FUNCTION(ext_archive_all_alert);
EXT_FUNCTION(ext_add_upgrade_active_to_db);
EXT_FUNCTION(ext_ap_down_pubkey_step_info);
EXT_FUNCTION (ext_active_get_event_report_and_hint);

#endif /* _PHP_EXT_ACTIVE_H_ */

