#ifndef _EXT_DBUS_H_
#define _EXT_DBUS_H_

#define DBUS_DEBUG_ENABLE 0 

static int dbus_connection_init(DBusConnection ** hand_dbus_connection) {
	
	DBusError dbus_error;
#if DBUS_DEBUG_ENABLE
	int ret = 0;
#endif
	dbus_error_init(&dbus_error);
	
	if(NULL == hand_dbus_connection)
	{
		return -1;
	}
	if(NULL == *hand_dbus_connection) {
#if DBUS_DEBUG_ENABLE
		syslog(LOG_DEBUG, "before bus get  connection %p ", hand_dbus_connection);
#endif
	  	*hand_dbus_connection = dbus_bus_get_private(DBUS_BUS_SYSTEM, &dbus_error);
	  	if (*hand_dbus_connection == NULL) {
	    		if (dbus_error_is_set(&dbus_error)) {
	     	 		syslog(LOG_WARNING, "dbus_connection_init: dbus_bus_get_private(): %s", dbus_error.message);
	      			dbus_error_free(&dbus_error);
	 		}
	  						
	  		return -1;
	  	}
#if DBUS_DEBUG_ENABLE
		syslog(LOG_DEBUG, "dbus * connection %p ", *hand_dbus_connection);
#endif
#if DBUS_DEBUG_ENABLE
		ret = 
#endif
		dbus_bus_request_name (*hand_dbus_connection, "aw.new",
			0, &dbus_error);
			
#if DBUS_DEBUG_ENABLE
		syslog(LOG_DEBUG, "dbus_bus_request_name:%d",ret);
#endif
		
		if (dbus_error_is_set (&dbus_error)) {
			syslog(LOG_ERR,"dbus_bus_request_name(): %s",
			dbus_error.message);
			dbus_error_free(&dbus_error);
			
			dbus_connection_close(*hand_dbus_connection);
			*hand_dbus_connection = NULL;
			
			return -1;
		}
	}
	return 0;
}

static int uninit_dbus_connection(DBusConnection ** hand_dbus_connection)
{
	if(NULL == hand_dbus_connection)
	{
		return -1;
	}
	if(*hand_dbus_connection)
	{
		dbus_connection_close(*hand_dbus_connection);
		*hand_dbus_connection = NULL;
	}
	return 0;
}

#endif
