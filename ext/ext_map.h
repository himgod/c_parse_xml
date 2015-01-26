#ifndef _EXT_MAP_H_
#define _EXT_MAP_H_

void ext_map_handle(int argc, zval ***argv, zval *return_value);
int get_map_list_from_config(struct map_conf * map_confs);
int set_selected_map_save_config(char * selectedname);
int add_modify_map_save_config(char * oldname, struct map_conf * new_map);
int set_map_scale_save_config(struct map_conf * new_map);
int remove_map_save_config(char * mapname);
int map_rename_save_config(char * oldname, char * newname);
EXT_FUNCTION(ext_map_list);
EXT_FUNCTION(ext_add_modify_map);
EXT_FUNCTION(ext_set_map_scale);
EXT_FUNCTION(ext_remove_map);
EXT_FUNCTION(ext_rename_map);
EXT_FUNCTION(ext_set_selected_map);

#endif
