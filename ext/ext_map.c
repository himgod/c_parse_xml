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

#include "afc_conf.h"

#include "ext_map.h"

#define MAP_DEBUG_ENABLE 1
ext_func_handle_t map_func_list[] = {
    {"map_list", 1, (php_func_t)ext_map_list},
    {"add_modify_map", 9, (php_func_t)ext_add_modify_map},
    {"set_map_scale", 6, (php_func_t)ext_set_map_scale},
    {"remove_map", 3, (php_func_t)ext_remove_map},
    {"rename_map", 4, (php_func_t)ext_rename_map},
    {"set_selected_map", 3, (php_func_t)ext_set_selected_map},
};

void ext_map_handle(int argc, zval ***argv, zval *return_value)
{
    int count = sizeof(map_func_list)/sizeof(map_func_list[0]);
    ext_function_handle(argc, argv, return_value, count, map_func_list);
}
int get_map_list_from_config(struct map_conf * map_confs)
{
    afc_config_s * afcconf = NULL;
	unsigned int mapid = 0;
	unsigned int tmpid = START_MAPID-1;

    afcconf = get_config_info();

    if(afcconf)
    {
        mapid = START_MAPID;
        while(mapid <= MAX_MAP_ID)
        {
            if(afcconf->maps[mapid] && map_confs)
            {
                tmpid++;
                memcpy(&map_confs[tmpid], afcconf->maps[mapid], sizeof(struct map_conf));
            }
            mapid++;
        }
        return tmpid;/*count*/
    }
    return 0;
}
int set_selected_map_save_config(char * selectedname)
{/* */
	afc_config_s * afcconf = NULL;
	struct map_conf * tmpmap = NULL;
	unsigned int mapid = 0;
	int ret = -1;

	if(!selectedname || !strcmp(selectedname, ""))
	{
        syslog(LOG_ERR, FUNC_LINE_FORMAT" input parameter invalid selectedname %s !", 
            FUNC_LINE_VALUE, selectedname?selectedname:"null");
	    return -1;
	}
    afcconf = get_config_info();

    if(afcconf)
    {
        mapid = START_MAPID;
        while(mapid <= MAX_MAP_ID)
        {
            tmpmap = afcconf->maps[mapid];
            if(!tmpmap)
            {
                break;/* emptys in the last */
            }
            if((selectedname && strcmp(selectedname, "")) && !strcmp(selectedname, tmpmap->name))
            {
                tmpmap->selected = TRUE;
            }
            else
            {
                tmpmap->selected = FALSE;
            }
            mapid++;
        }
           
        ret = save_config_info(afcconf);
        if(ret)
        {
            syslog(LOG_ERR, FUNC_LINE_FORMAT" failed to save config info when set selected map %s  , ret %d !"
                , FUNC_LINE_VALUE, selectedname, ret);
        }
    }
    else
    {
        syslog(LOG_ERR, FUNC_LINE_FORMAT" failed to get config info !", FUNC_LINE_VALUE);
        return -1;
    }
    return ret;
}
int add_modify_map_save_config(char * oldname, struct map_conf * new_map)
{/*when add new map or modify a map name or change picture for a map name call this function */
	afc_config_s * afcconf = NULL;
	struct map_conf * tmpmap = NULL;
	unsigned int mapid = 0;
	int ret = -1;

	if(!new_map || !strcmp(new_map->name, ""))
	{
        syslog(LOG_ERR, FUNC_LINE_FORMAT" input parameter invalid new_map %p !", FUNC_LINE_VALUE, new_map);
	    return -1;
	}
    afcconf = get_config_info();

    if(afcconf)
    {
        mapid = START_MAPID;
        while(mapid <= MAX_MAP_ID)
        {
            tmpmap = afcconf->maps[mapid];
            if(!tmpmap)
            {
                break;/* emptys in the last */
            }
            if((oldname && strcmp(oldname, "")) && !strcmp(oldname, tmpmap->name))
            {
                break;
            }
            if((!oldname||(!strcmp(oldname, ""))) && !strcmp(new_map->name, tmpmap->name))
            {
                break;
            }
#if MAP_DEBUG_ENABLE
            syslog(LOG_DEBUG, FUNC_LINE_FORMAT" newmap %s tmpmap[%d] %s !", FUNC_LINE_VALUE, 
                new_map->name, mapid, tmpmap->name);
#endif
            mapid++;
        }
        
        if(NULL == tmpmap)
        {
            afcconf->maps[mapid] = (struct map_conf *)malloc(sizeof(struct map_conf));
            if(afcconf->maps[mapid ])
            {
                memset(afcconf->maps[mapid], 0, sizeof(struct map_conf));
            }
            else
            {
                syslog(LOG_ERR, FUNC_LINE_FORMAT" malloc map node failed!", FUNC_LINE_VALUE);
                return -1;
            }
        }
        else if(mapid > MAX_MAP_ID)
        {
            syslog(LOG_ERR, FUNC_LINE_FORMAT" out of max map number !", FUNC_LINE_VALUE);
            return -2; /* map counts out of max num */
        }
        
        tmpmap = afcconf->maps[mapid];
        tmpmap->initscalemeter = new_map->initscalemeter;
        tmpmap->initscalewidth = new_map->initscalewidth;
        tmpmap->selected = new_map->selected;
        strncpy(tmpmap->name, new_map->name, MID_STRING_LEN-1);
        strncpy(tmpmap->url, new_map->url, LONG_STRING_LEN-1);
        strncpy(tmpmap->initscaleunit, new_map->initscaleunit, 7);
        
        
        ret = save_config_info(afcconf);
        if(ret)
        {
            syslog(LOG_ERR, FUNC_LINE_FORMAT" failed to save config info when add/modify map %s, ret %d !"
                , FUNC_LINE_VALUE, new_map->name, ret);
        }
    }
    else
    {
        syslog(LOG_ERR, FUNC_LINE_FORMAT" failed to get config info !", FUNC_LINE_VALUE);
        return -1;
    }
    return ret;
}
int set_map_scale_save_config(struct map_conf * new_map)
{/*when add new map or modify a map name or change picture for a map name call this function */
	afc_config_s * afcconf = NULL;
	struct map_conf * tmpmap = NULL;
	unsigned int mapid = 0;
	int ret = -1;

	if(!new_map || !strcmp(new_map->name, ""))
	{
        syslog(LOG_ERR, FUNC_LINE_FORMAT" input parameter invalid new_map %p !", FUNC_LINE_VALUE, new_map);
	    return -1;
	}
    afcconf = get_config_info();

    if(afcconf)
    {
        mapid = START_MAPID;
        while(mapid <= MAX_MAP_ID)
        {
            tmpmap = afcconf->maps[mapid];
            if(!tmpmap)
            {
                break;/* emptys in the last */
            }
#if MAP_DEBUG_ENABLE
            syslog(LOG_DEBUG, FUNC_LINE_FORMAT" newmap %s tmpmap[%d] %s !", FUNC_LINE_VALUE, 
                new_map->name, mapid, tmpmap->name);
#endif
            if(!strcmp(new_map->name, tmpmap->name))
            {
                break;
            }
            mapid++;
        }
        
        if((NULL == tmpmap)||(mapid > MAX_MAP_ID))
        {
            syslog(LOG_ERR, FUNC_LINE_FORMAT" failed to found map %s !", FUNC_LINE_VALUE, new_map->name);
            return -1; 
        }
        
        tmpmap->initscalemeter = new_map->initscalemeter;
        tmpmap->initscalewidth = new_map->initscalewidth;
        strncpy(tmpmap->initscaleunit, new_map->initscaleunit, 7);
        
        
        ret = save_config_info(afcconf);
        if(ret)
        {
            syslog(LOG_ERR, FUNC_LINE_FORMAT" failed to save config info when set scale for map %s, ret %d !"
                , FUNC_LINE_VALUE, new_map->name, ret);
        }
    }
    else
    {
        syslog(LOG_ERR, FUNC_LINE_FORMAT" failed to get config info !", FUNC_LINE_VALUE);
        return -1;
    }
    return ret;
}

int map_rename_save_config(char * oldname, char * newname)
{/* */
	afc_config_s * afcconf = NULL;
	struct map_conf * tmpmap = NULL;
	unsigned int mapid = 0;
	int ret = -1;

	if(!newname || !strcmp(newname, "")||(!oldname)||!strcmp(oldname, ""))
	{
        syslog(LOG_ERR, FUNC_LINE_FORMAT" input parameter invalid newname %s oldname %s !", 
            FUNC_LINE_VALUE, newname?newname:"null", oldname?oldname:"null");
	    return -1;
	}
    afcconf = get_config_info();

    if(afcconf)
    {
        mapid = START_MAPID;
        while(mapid <= MAX_MAP_ID)
        {
            tmpmap = afcconf->maps[mapid];
            if(!tmpmap)
            {
                break;/* emptys in the last */
            }
            if((oldname && strcmp(oldname, "")) && !strcmp(oldname, tmpmap->name))
            {
                break;
            }
            mapid++;
        }
        
        if(NULL == tmpmap||(mapid > MAX_MAP_ID))
        {
            syslog(LOG_ERR, FUNC_LINE_FORMAT" map not found when map rename!", FUNC_LINE_VALUE);
            return -1;
        }
        
        strncpy(tmpmap->name, newname, MID_STRING_LEN-1);
        
        
        ret = save_config_info(afcconf);
        if(ret)
        {
            syslog(LOG_ERR, FUNC_LINE_FORMAT" failed to save config info when map %s rename to %s , ret %d !"
                , FUNC_LINE_VALUE, oldname, newname, ret);
        }
    }
    else
    {
        syslog(LOG_ERR, FUNC_LINE_FORMAT" failed to get config info !", FUNC_LINE_VALUE);
        return -1;
    }
    return ret;
}

int remove_map_save_config(char * mapname)
{
    /*when remove an exists map call this function */
	afc_config_s * afcconf = NULL;
	struct map_conf * tmpmap = NULL;
	unsigned int mapid = 0;
	char cmd[LONG_STRING_LEN] = {0};
	int ret = -1;

	if(!mapname || !strcmp(mapname, ""))
	{
        syslog(LOG_ERR, FUNC_LINE_FORMAT" input parameter invalid mapname %p !", FUNC_LINE_VALUE, mapname);
	    return -1;
	}
    afcconf = get_config_info();

    if(afcconf)
    {
        mapid = START_MAPID;
        while(mapid <= MAX_MAP_ID)
        {
            tmpmap = afcconf->maps[mapid];
            if(!tmpmap)
            {
                break;/* emptys in the last */
            }
            if(!strcmp(mapname, tmpmap->name))
            {
                break;
            }
            mapid++;
        }
        
        if((NULL == tmpmap))
        {
            syslog(LOG_ERR, FUNC_LINE_FORMAT" map not found when remove map !", FUNC_LINE_VALUE);
            return -1;
        }
        
        while(mapid < MAX_MAP_ID && afcconf->maps[mapid])
        {
            afcconf->maps[mapid] = afcconf->maps[mapid+1];
            mapid++;
        }
        afcconf->maps[MAX_MAP_ID] = NULL;
        sprintf(cmd, "sudo rm %s", tmpmap->url);
        ret = system(cmd);
        if(ret)
		{
			syslog(LOG_ERR, FUNC_LINE_FORMAT"failed to call system(%s) ret %d !", FUNC_LINE_VALUE, cmd, ret);
		}
		destroy_map_node(tmpmap);
        
        ret = save_config_info(afcconf);
        if(ret)
        {
            syslog(LOG_ERR, FUNC_LINE_FORMAT" failed to save config info when remove map %s, ret %d !"
                , FUNC_LINE_VALUE, mapname, ret);
        }
    }
    else
    {
        syslog(LOG_ERR, FUNC_LINE_FORMAT" failed to get config info !", FUNC_LINE_VALUE);
        return -1;
    }
    return ret;
}

EXT_FUNCTION(ext_map_list)
{	
	int count = 0;
	int i = 0;
    int map_num = 0;
    struct map_conf map_confs[MAX_MAP_ID+1];
	
	zval *iter = NULL, *iter_array = NULL;
	MAKE_STD_ZVAL(iter);
	array_init(iter);
	zval *iter_len;
	MAKE_STD_ZVAL(iter_len);
	array_init(iter_len);
	memset(&map_confs, 0, sizeof(struct map_conf)*(MAX_MAP_ID+1));
#if 0
struct map_conf{
	char 	name[MID_STRING_LEN];/* map name */
	char	url[LONG_STRING_LEN];/* map picture url */
	char	initscaleunit[8];/* m, cm, km */
	unsigned int   initscalemeter;/* m/cm/km value */
	unsigned int  initscalewidth;/* the width of scale when zoom is 100% */
	BOOL    selected;/* selected map after page load */
};
#endif
	
	count = get_map_list_from_config((struct map_conf *)&map_confs);
	if(count)
	{
    	for (i = START_MAPID; i <= count; i++)
    	{
     	    if(strcmp(map_confs[i].name, "") && strcmp(map_confs[i].url, ""))
    	    {
                MAKE_STD_ZVAL(iter_array);
                array_init(iter_array);
                
        		add_assoc_string(iter_array, "name", map_confs[i].name, 1);
        		add_assoc_string(iter_array, "url", map_confs[i].url, 1);
        		add_assoc_string(iter_array, "initscaleunit", map_confs[i].initscaleunit, 1);
        		add_assoc_long(iter_array, "initscalemeter", (long)map_confs[i].initscalemeter);
        		add_assoc_long(iter_array, "initscalewidth", (long)map_confs[i].initscalewidth);
        		add_assoc_long(iter_array, "selected", (long)map_confs[i].selected);
        		add_next_index_zval(iter, iter_array);
        		map_num++;
    		}
    	}
	}
        
#if MAP_DEBUG_ENABLE
    syslog(LOG_DEBUG, "after for call get_map_list_from_config map_num %d\n", map_num);
#endif
	if (object_init(return_value) != SUCCESS)
    {
        RETURN_LONG(PHP_OBJ_INIT_FAIL);
    }
    
    add_assoc_long(iter_len, "map_num", (long)map_num);
    add_property_zval(return_value, "maps", iter_len);
    add_property_zval(return_value, "value", iter); 
}

EXT_FUNCTION(ext_add_modify_map)
{
	int ret = 0;
	char * admin = NULL;
    zval *iter_array;
    MAKE_STD_ZVAL(iter_array);
    array_init(iter_array);
    struct map_conf map_node;
    char * name = map_node.name;
    char * url  = map_node.url;
    char * initscaleunit = map_node.initscaleunit;
    char * oldname = NULL;
    memset(&map_node, 0, sizeof(struct map_conf));
	
	ext_para_get(argc, argv, EXT_TYPE_STRING, &oldname,
	    EXT_TYPE_STRING, &name, 
		EXT_TYPE_STRING, &url, 
		EXT_TYPE_STRING, &initscaleunit, 
		EXT_TYPE_LONG, &map_node.initscalemeter,
		EXT_TYPE_LONG, &map_node.initscalewidth,
		EXT_TYPE_LONG, &map_node.selected,
		EXT_TYPE_STRING, &admin);

	if(!name || ! url || !initscaleunit)
	{
		syslog(LOG_ERR, FUNC_LINE_FORMAT" get bad parameter name %s url %s initscalunit %s ", 
			FUNC_LINE_VALUE, name?name:"null", url?url:"null", initscaleunit?initscaleunit:"null");
		RETURN_LONG(-1);
	}
	strncpy(map_node.name, name, MID_STRING_LEN-1);
	strncpy(map_node.url, url, LONG_STRING_LEN-1);
	strncpy(map_node.initscaleunit, initscaleunit, 7);
	ret = add_modify_map_save_config(oldname, &map_node);
	RETURN_LONG(ret);
}

EXT_FUNCTION(ext_set_map_scale)
{
	int ret = 0;
	char * admin = NULL;
    zval *iter_array;
    MAKE_STD_ZVAL(iter_array);
    array_init(iter_array);
    struct map_conf map_node;
    char * name = map_node.name;
    char * initscaleunit = map_node.initscaleunit;
    memset(&map_node, 0, sizeof(struct map_conf));
	
	ext_para_get(argc, argv, EXT_TYPE_STRING, &name, 
		EXT_TYPE_STRING, &initscaleunit, 
		EXT_TYPE_LONG, &map_node.initscalemeter,
		EXT_TYPE_LONG, &map_node.initscalewidth,
		EXT_TYPE_STRING, &admin);

	if(!name || !initscaleunit)
	{
		syslog(LOG_ERR, FUNC_LINE_FORMAT" get bad parameter name %s initscalunit %s ", 
			FUNC_LINE_VALUE, name?name:"null", initscaleunit?initscaleunit:"null");
		RETURN_LONG(-1);
	}
	strncpy(map_node.name, name, MID_STRING_LEN-1);
	strncpy(map_node.initscaleunit, initscaleunit, 7);
	ret = set_map_scale_save_config(&map_node);
	RETURN_LONG(ret);
}

EXT_FUNCTION(ext_remove_map)
{
	int ret = 0;
	char * admin = NULL;
    zval *iter_array;
    MAKE_STD_ZVAL(iter_array);
    array_init(iter_array);
    char * name = NULL;
	
	ext_para_get(argc, argv,
	    EXT_TYPE_STRING, &name,
		EXT_TYPE_STRING, &admin);

	if(!name)
	{
		syslog(LOG_ERR, FUNC_LINE_FORMAT" get bad parameter name %s", 
			FUNC_LINE_VALUE, name?name:"null");
		RETURN_LONG(-1);
	}
	ret = remove_map_save_config(name);
	RETURN_LONG(ret);
}

EXT_FUNCTION(ext_rename_map)
{
	int ret = 0;
	char * admin = NULL;
    zval *iter_array;
    MAKE_STD_ZVAL(iter_array);
    array_init(iter_array);
    char * oldname = NULL;
    char * name = NULL;
	
	ext_para_get(argc, argv,
	    EXT_TYPE_STRING, &oldname,
	    EXT_TYPE_STRING, &name,
		EXT_TYPE_STRING, &admin);

	if(!name)
	{
		syslog(LOG_ERR, FUNC_LINE_FORMAT" get bad parameter oldname %s name %s", 
			FUNC_LINE_VALUE, oldname ? oldname:"null", name?name:"null");
		RETURN_LONG(-1);
	}
	ret = map_rename_save_config(oldname, name);
	RETURN_LONG(ret);
}
EXT_FUNCTION(ext_set_selected_map)
{
	int ret = 0;
	char * admin = NULL;
    zval *iter_array;
    MAKE_STD_ZVAL(iter_array);
    array_init(iter_array);
    char * name = NULL;
	
	ext_para_get(argc, argv,
	    EXT_TYPE_STRING, &name,
		EXT_TYPE_STRING, &admin);

	if(!name)
	{
		syslog(LOG_ERR, FUNC_LINE_FORMAT" get bad parameter name %s", 
			FUNC_LINE_VALUE, name?name:"null");
		RETURN_LONG(-1);
	}
	ret = set_selected_map_save_config(name);
	RETURN_LONG(ret);
}

