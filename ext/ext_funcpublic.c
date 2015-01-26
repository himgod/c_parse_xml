#include <stdlib.h>
#include <string.h>
#include <grp.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <syslog.h>
#include "php.h"
#include "wai_log.h"
#include "ext_public.h"
#include "ext_funcpublic.h"
//#include <security/pam_appl.h>
//#include "hmd/hmdpub.h"

#define FUNC_DEBUG_ENABLE 1

ext_func_handle_t public_func_list[] = {
    {"get_chain_head", 3, (php_func_t)ext_get_chain_head},
    {"delete_garbage_session_file", 3, (php_func_t)ext_delete_garbage_session_file},
};

void ext_funcpublic_handle(int argc, zval ***argv, zval *return_value)
{
    int count = sizeof(public_func_list)/sizeof(public_func_list[0]);
    ext_function_handle(argc, argv, return_value, count, public_func_list);
}


int php_load(struct php_langlist *l,int ch,FILE *fpp)               /*分隔文件fp中的变量，依次存入链表l*/
{
	struct php_langlist *p;
	int i;
	int n_ex=1;
	if((p=(struct php_langlist *)malloc(sizeof(struct php_langlist)+n_ex*128))==NULL)
	{
		return 0;
	}
	i=0;
	memset(p, 0, sizeof(struct php_langlist)+n_ex*128);

	while(ch!=';')                        /*";"变量及其值的结束标志*/
	{
		p->val[i]=ch;
		i++;
		if( i >= n_ex*128-1 )//如果长度超过LN,重新分派空间。
		{

			n_ex++;
			if((p=(struct php_langlist *)realloc(p,sizeof(struct php_langlist)+n_ex*128))==NULL)
			{
				return 0;
			}
		}
		ch=fgetc(fpp);
	}

	p->val[i]='\0';                     /*存入字符串结束标志'\0'*/

	p->next=l->next;                      /*将新的节点插入链表*/
	l->next=p;
	return 1;
}

void php_release(struct php_langlist *l)
{
  struct php_langlist *p1,*p2;
  if(NULL != l)
  {
	  p1=l; 							   /*p1指向头节点*/
	  p2=p1->next;						   /*p2指向头节点的下一个节点*/  
	  free(p1); 						   /*释放头节点*/
	  p1=p2;							   /*p1后移，指向下一个待释放的节点*/  
	  while(p1)
	  {
		p2=p1->next;					   /*p2指向待释放节点的下一节点*/
		free(p1);					  
		p1=p2;
	  }
  }
}

struct php_langlist *php_get_chain_head(int lan_type,char *file_name)          /*file_name表示资源文件的名字，返回链表的头*/
{
	FILE *fpp = NULL;	
	int fl = 0;                                 /*fl指示将临时数组插入哪个链表，fl=0,表示插入英文链表；fl=1表示插入中文链表*/
	struct php_langlist *le,*lc;
	char ch;
	if( NULL == file_name || strlen(file_name) == 0 )
	{
		return NULL;
	}

	if((fpp=fopen(file_name,"r"))==NULL)    /*以只读方式打开资源文件*/
	{
		return NULL;
	} 
	fl=0;                                  /*将fl初始化为0，第一次将临时数组插入英文链表*/
	if((le=(struct php_langlist *)malloc(sizeof(struct php_langlist)))==NULL)     /*初始化英文链表的头节点*/
	{
		fclose(fpp); 
   		return NULL;
  	}
	le->next=NULL;                       
	if((lc=(struct php_langlist *)malloc(sizeof(struct php_langlist)))==NULL)     /*初始化中文链表的头节点*/
	{
		fclose(fpp); 
		return NULL;
  	}
	lc->next=NULL;
	ch=fgetc(fpp);
	while(ch!=EOF)
	{
    	if(!fl)                             /*fl==0,将变量插入英文链表*/
	    {
    		if(php_load(le,ch,fpp)==0)
    		{
    			fclose(fpp); 
		  		return NULL;
    		}
      		fl=!fl;                           /*fl取反，保证变量可以交替插入中英文链表*/
    	}
    	else if(fl)                         /*fl==1,将变量插入中文链表*/
    	{
        	if(php_load(lc,ch,fpp)==0)
        	{
        		fclose(fpp); 
				return NULL;
        	}
           	fl=!fl;                      /*fl取反，保证变量可以交替插入中英文链表*/
		}                              
	    ch=fgetc(fpp);
    	while((ch==' ')||(ch=='\n') ||(0x0d==ch)||(0x0a==ch))        /*寻找下一个变量开始的位置*/
	    {
	    	ch=fgetc(fpp);
    	}
  	}
  	fclose(fpp);                           /*导出完成，关闭文件*/
	fpp = NULL;
  	if(0 == lan_type )              	   /*flag=="en"*/
  	{
    	php_release(lc);                        /*释放中文链表头*/	
		return le;							 /*返回英文链表头*/ 
  	}
  	else                                  /*flag=="ch"*/
  	{ 
   		php_release(le);                        /*释放英文链表头*/	
   		return lc;                           /*返回中文链表头*/
  	}
}       
#define GET_CHAIN_BY_FTYPE 0
EXT_FUNCTION(ext_get_chain_head)    
{
		char *language = NULL; 
#if GET_CHAIN_BY_FTYPE
    char *ftype = NULL;
#else 
    char * fpath = NULL;
#endif

    ext_para_get(argc, argv, EXT_TYPE_STRING, &language,
#if GET_CHAIN_BY_FTYPE
							 EXT_TYPE_STRING, &ftype);

	if((NULL == language) || (NULL == ftype)){
		RETURN_LONG(INPUT_PARA_NULL);
	}

#else
							 EXT_TYPE_STRING, &fpath);
	if((NULL == language) || (NULL == fpath)){
		RETURN_LONG(INPUT_PARA_NULL);
	}
#endif
	struct php_langlist *list = NULL, *p=NULL;;
	int lan_type = LANG_EN;

	if(0 == strcmp(language,"zh"))
	{
		lan_type = LANG_CH;
	}
	else if(0 == strcmp(language,"en"))
	{
		lan_type = LANG_EN;
	}
#if GET_CHAIN_BY_FTYPE
	if(0 == strcmp(ftype,"public"))
	{
		list = php_get_chain_head(lan_type, "/opt/www/htdocs/php/text/php_public.txt");
	}
	else if(0 == strcmp(ftype,"quick"))
	{
		list = php_get_chain_head(lan_type, "/opt/www/htdocs/php/text/php_quick.txt");
	}
	else if(0 == strcmp(ftype,"system"))
	{
		list = php_get_chain_head(lan_type, "/opt/www/htdocs/php/text/php_system.txt");
	}
	else if(0 == strcmp(ftype,"wired"))
	{
		list = php_get_chain_head(lan_type, "/opt/www/htdocs/php/text/php_wired.txt");
	}
	else if(0 == strcmp(ftype,"wireless"))
	{
		list = php_get_chain_head(lan_type, "/opt/www/htdocs/php/text/php_wireless.txt");
	}
	else if(0 == strcmp(ftype,"snmp"))
	{
		list = php_get_chain_head(lan_type, "/opt/www/htdocs/php/text/php_snmp.txt");
	}
	else if(0 == strcmp(ftype,"authenticate"))
	{
		list = php_get_chain_head(lan_type, "/opt/www/htdocs/php/text/php_authenticate.txt");
	}
	else if(0 == strcmp(ftype,"device"))
	{
		list = php_get_chain_head(lan_type, "/opt/www/htdocs/php/text/php_device.txt");
	}
#else
	list = php_get_chain_head(lan_type, fpath);
#endif

	char key[128]={ 0 },value[256]={ 0 },*temp = NULL;
	zval *iter_len, *iter, *iter_array;

	MAKE_STD_ZVAL(iter_len);
    array_init(iter_len);
	MAKE_STD_ZVAL(iter);
    array_init(iter);
	if(list)
	{
		int num = 0;
		for(p=list->next; p; p=p->next)
		{
			MAKE_STD_ZVAL(iter_array);
            array_init(iter_array);

			temp = strchr( p->val, '=' );
			if(temp)
			{
				memset(key, 0, sizeof(key));
				strncpy( key, p->val, temp - p->val );

				memset(value, 0, sizeof(value));
				strncpy( value, temp+1, strlen(p->val)-strlen(key)-1);
			}

			add_next_index_string(iter_array, key, 1);
			add_next_index_string(iter_array, value, 1);
            
			add_next_index_zval(iter, iter_array);
			num++;
		}
		add_next_index_long(iter_len, num);
	}
	else
	{
		add_next_index_long(iter_len, 0);
	}

	php_release(list);

	if(object_init(return_value) != SUCCESS){
        RETURN_LONG(PHP_OBJ_INIT_FAIL);
    }
    add_property_zval(return_value, "length", iter_len);
	add_property_zval(return_value, "value", iter);
}

EXT_FUNCTION(ext_delete_garbage_session_file)    
{
	char *sessionId = NULL;
	char *sessionPath = NULL;
	char cmd[128] = {0};
	int ret = 0;
	ext_para_get(argc, argv, EXT_TYPE_STRING, &sessionId, EXT_TYPE_STRING, &sessionPath);
	if(sessionId == NULL || NULL == sessionPath)
	{
		return;
	}
#if FUNC_DEBUG_ENABLE
	syslog(LOG_DEBUG, "delete %s/sess_%s", sessionPath, sessionId);
#endif
	sprintf(cmd, "find %s -type f |grep \"sess_%s\"| xargs -n 1 rm -f", sessionPath, sessionId);
//	sprintf(cmd, "sudo echo %s > tmp_recode", sessionId);
	ret = system(cmd);
	if(0 != ret)
	{
		syslog(LOG_ERR, "%s line %d system execute cmd %s failed, ret %#x!", __func__, __LINE__, cmd, ret);
	}
	RETURN_LONG((long)ret);
}

void delete_enter(char * string)
{
	int len = 0;
	len = strlen(string);
    int len_l = 0;
	if(string == NULL)
		return;
	char * tmp = string;
	while(*tmp != '\n')
	{
		len_l++;
		if(len_l >= len)
			return;
		tmp++;
	}
	*tmp = '\0';	
}
