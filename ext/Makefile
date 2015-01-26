EGREP = grep -E
SED = /bin/sed
#CONFIGURE_COMMAND = './configure' '--host=mips-linux-gnu'
CONFIGURE_COMMAND = './configure'
#CONFIGURE_OPTIONS = '--host=mips-linux-gnu'
CONFIGURE_OPTIONS = ''
SHLIB_SUFFIX_NAME = so
SHLIB_DL_SUFFIX_NAME = so
ZEND_EXT_TYPE = zend_extension

shared_objects_ext += ext_main.o
shared_objects_ext += ext_public.o 
#shared_objects_ext += ext_vlan.o
#shared_objects_ext += ext_user.o
shared_objects_ext += ext_sys_config.o
#shared_objects_ext += ext_security_wlan.o
shared_objects_ext += ext_wtp.o
shared_objects_ext += ext_map.o
shared_objects_ext += ext_history.o
shared_objects_ext += ext_operate.o
shared_objects_ext += ext_admin.o
shared_objects_ext += ext_active.o
#shared_objects_ext += ext_radio.o
#shared_objects_ext += ext_ip.o
#shared_objects_ext += ext_dhcp.o
#shared_objects_ext += ext_eag.o
#shared_objects_ext += ext_pdc.o
#shared_objects_ext += ext_rdc.o
shared_objects_ext += ext_funcpublic.o
shared_objects_ext += ext_wireless.o
#shared_objects_ext += ext_vrrp.o
#shared_objects_ext += ext_eth_port.o
#shared_objects_ext += ext_route.o
#shared_objects_ext += ext_ebr.o
#shared_objects_ext += ext_ntp.o
#shared_objects_ext += ext_snmp.o
#shared_objects_ext += ext_bss.o
#shared_objects_ext += ext_station.o
#shared_objects_ext += ext_syslog.o
shared_objects_ext += afc_conf.o

PHP_PECL_EXTENSI = ext
PHP_MODULES = $(phplibdir)/ext.so
PHP_ZEND_EX =
all_targets = $(PHP_MODULES) $(PHP_ZEND_EX)
install_targets = install-modules install-headers
libdir = ${exec_prefix}/lib
phplibdir = ./modules
phpincludedir = $(TOPSRC_DIR)/php/include/php
#CC = mips-linux-gnu-gcc
CC = gcc
CFLAGS_CLEAN = $(CFLAGS)
#CPP = mips-linux-gnu-gcc -E
CPP = gcc -E
CPPFLAGS = -DHAVE_CONFIG_H
AWROOTPATH = ${TOPSRC_DIR}
ACCAPIPATH = $(AWROOTPATH)/accapi
CFLAGS = -g -O2 -fPIC -Wall
CFLAGS += -I$(ACCAPIPATH)
#CFLAGS += -I$(ACCAPIPATH)/nm/app
#CFLAGS += -I$(ACCAPIPATH)/nm/app/snmp
#CFLAGS += -I$(ACCAPIPATH)/nm/app/eag
#CFLAGS += -I$(ACCAPIPATH)/nm/app/drp
#CFLAGS += -I$(ACCAPIPATH)/nm/app/firewall
#CFLAGS += -I$(ACCAPIPATH)/nm/app/manage
#CFLAGS += -I$(ACCAPIPATH)/nm/app/sample
#CFLAGS += -I$(ACCAPIPATH)/nm/app/dhcp
#CFLAGS += -I$(ACCAPIPATH)/nm/ip
#CFLAGS += -I$(ACCAPIPATH)/nm/public
#CFLAGS += -I$(ACCAPIPATH)/nm/switch
#CFLAGS += -I$(ACCAPIPATH)/nm/system
#CFLAGS += -I$(ACCAPIPATH)/nm/wlan
#CFLAGS += -I$(AWROOTPATH)/dbus-1.4.0 
#CFLAGS += -I$(AWROOTPATH)/dcli/src/pub
CFLAGS += -I$(AWROOTPATH)/php/include/php
CFLAGS += -I$(AWROOTPATH)/php/include/php/ext
CFLAGS += -I$(AWROOTPATH)/php/include/php/main
CFLAGS += -I$(AWROOTPATH)/php/include/php/TSRM
CFLAGS += -I$(AWROOTPATH)/php/include/php/Zend
CFLAGS += -I$(AWROOTPATH)/handlib
CFLAGS += -I$(AWROOTPATH)/dblib
CFLAGS += -I$(AWROOTPATH)/wcpss/wai
#CFLAGS += -I/opt/mipslibs/usr/include  
CFLAGS += -I/usr/include  
#CFLAGS += -I/opt/mipslibs/usr/include/libxml2
CFLAGS += -I/usr/include/libxml2
CFLAGS += -I/usr/include/dbus-1.0
CFLAGS += -I/usr/lib/i386-linux-gnu/dbus-1.0/include
EXTRA_LDFLAGS += -L$(AWROOTPATH)/auteware/files/opt/lib
#EXTRA_LDFLAGS += -L/opt/mipslibs/usr/lib
EXTRA_LDFLAGS += -L/usr/lib

EXTRA_LIBS += -ldbus-1
EXTRA_LIBS += -L$(AWROOTPATH)/handlib/ -lhandw
EXTRA_LIBS += -L$(AWROOTPATH)/dblib/ -ldbop
EXTRA_LIBS += -L$(AWROOTPATH)/wcpss/wai/ -lwai
#EXTRA_LIBS += -ldclipub
#EXTRA_LIBS += -lnm
EXTRA_LIBS += -L/usr/lib/i386-linux-gnu
EXTRA_LIBS += -lxml2
EXTRA_LIBS += -ldl
EXTRA_LIBS += -lz
#EXTRA_LIBS += -L/lib/i386-linux-gnu -lpam
#EXTRA_LIBS += -leagintf
#EXTRA_LIBS += -ldrpintf
#DBUS_OBJ_PATH=$(AWROOTPATH)/AuteCS/cgic205/
#ALL_DBUS_OBJS = $(DBUS_OBJ_PATH)ws_dcli_vlan.o $(DBUS_OBJ_PATH)ws_usrinfo.o
#$(DBUS_OBJ_PATH)ws_dcli_wlans.o $(DBUS_OBJ_PATH)ws_sta.o $(DBUS_OBJ_PATH)ws_dcli_bss.o $(DBUS_OBJ_PATH)ws_dcli_wqos.o \
#$(DBUS_OBJ_PATH)ws_dcli_portconf.o $(DBUS_OBJ_PATH)ws_security.o $(DBUS_OBJ_PATH)ws_nm_status.o \
#$(DBUS_OBJ_PATH)snmp_agent/ws_snmpd_engine.o $(DBUS_OBJ_PATH)ws_log_conf.o $(DBUS_OBJ_PATH)snmp_agent/ws_snmpd_trap_common.o
CXXFLAGS_CLEAN = $(CXXFLAGS)
INCLUDES = -I$(phpincludedir) -I$(phpincludedir)/main -I$(phpincludedir)/TSRM -I$(phpincludedir)/Zend -I$(phpincludedir)/ext -I$(phpincludedir)/ext/date/lib
CXX =
CXXFLAGS =
LFLAGS =
LDFLAGS =

COMMON_FLAGS = $(INCLUDES) $(EXTRA_INCLUDES) $(CPPFLAGS) $(PHP_FRAMEWORKPATH)

all: $(all_targets) 
	@echo "Build complete."
	@echo "-------------------------------"

clean:
	find $(AWROOTPATH)/php/ext/ -name \*.so | xargs rm -f
	find $(AWROOTPATH)/php/ext -name \*.o | xargs rm -f
	find $(AWROOTPATH)/php/ext -name .libs -a -type d|xargs rm -rf
	rm -f $(AWROOTPATH)/php/ext/modules/* 

ext_main.o: ./ext_main.c
	@echo "-------------------------------"
	@echo $(DHCP_CONFIG_HOSTCC)
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_main.c -o $@
ext_public.o: ./ext_public.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_public.c -o $@
ext_wireless.o: ./ext_wireless.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS) $(DBUS_INCLUDE) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS) -c ./ext_wireless.c -o $@
ext_vlan.o: ./ext_vlan.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_vlan.c -o $@
ext_user.o: ./ext_user.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_user.c -o $@
ext_sys_config.o: ./ext_sys_config.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_sys_config.c -o $@
ext_security_wlan.o: ./ext_security_wlan.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_security_wlan.c -o $@
ext_wtp.o: ./ext_wtp.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  $(DBUS_INCLUDE) -c ./ext_wtp.c -o $@	
ext_map.o: ./ext_map.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  $(DBUS_INCLUDE) -c ./ext_map.c -o $@	
ext_history.o: ./ext_history.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  $(DBUS_INCLUDE) -c ./ext_history.c -o $@	
ext_operate.o: ./ext_operate.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  $(DBUS_INCLUDE) -c ./ext_operate.c -o $@	
ext_admin.o: ./ext_admin.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  $(DBUS_INCLUDE) -c ./ext_admin.c -o $@	
ext_active.o: ./ext_active.c ./ext_active.h
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  $(DBUS_INCLUDE) -c ./ext_active.c -o $@	
ext_radio.o: ./ext_radio.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_radio.c -o $@
ext_ip.o: ./ext_ip.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_ip.c -o $@
ext_dhcp.o: ./ext_dhcp.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_dhcp.c -o $@
ext_eag.o: ./ext_eag.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_eag.c -o $@
ext_pdc.o: ./ext_eag.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_pdc.c -o $@
ext_rdc.o: ./ext_eag.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_rdc.c -o $@
ext_funcpublic.o: ./ext_funcpublic.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_funcpublic.c -o $@
ext_vrrp.o: ./ext_vrrp.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_vrrp.c -o $@
ext_eth_port.o: ./ext_eth_port.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_eth_port.c -o $@	
ext_route.o: ./ext_route.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_route.c -o $@	
ext_ebr.o: ./ext_ebr.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_ebr.c -o $@	
ext_ntp.o: ./ext_ntp.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_ntp.c -o $@
ext_snmp.o: ./ext_snmp.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_snmp.c -o $@
ext_bss.o: ./ext_bss.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_bss.c -o $@
ext_station.o: ./ext_station.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_station.c -o $@
ext_syslog.o: ./ext_syslog.c
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c ./ext_syslog.c -o $@
afc_conf.o: ./afc_conf.c afc_conf.h
	$(CC)  -I. $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  $(DBUS_INCLUDE) -c ./afc_conf.c -o $@	
					
$(phplibdir)/ext.so: ./ext.so
	cp ./ext.so $(phplibdir)

./ext.so: $(shared_objects_ext) $(EXT_SHARED_DEPENDENCIES)
	$(CC) $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS) $(LDFLAGS) -o $@ $(EXTRA_LDFLAGS) $(shared_objects_ext)  $(ALL_DBUS_OBJS) $(EXT_SHARED_LIBADD) $(EXTRA_LIBS) -shared

