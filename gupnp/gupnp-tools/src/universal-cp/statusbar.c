/* * statusbar.c
 *
 *  Created on: May 19, 2009
 *      Author: vlillvis
 */

#include "statusbar.h"
#include "gui.h"
#include "device-treeview.h"
#include "user-login-setup-dialog.h"
static GtkWidget *statusbar;

void
statusbar_update (gboolean device_selected)
{
	    guint empty_identifier;
	    guint empty_context_id;
	    const gchar *empty_statusbar="";

	    empty_context_id = gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar),
		    	                                        empty_statusbar);
	    if (device_selected) {
		    GUPnPDeviceInfo *info;
		    GUPnPDeviceProxy *deviceProxy;

		    info = get_selected_device_info ();
		    deviceProxy = GUPNP_DEVICE_PROXY (info);

		    /* If SSL client exist, update status bar */
		    if (gupnp_device_proxy_get_ssl_client (deviceProxy)) {
			    const gchar *user= "Jaakko";
			    const gchar *end_text;
			    GString *loginname = g_string_new(user);

   		        get_current_username(loginname);
	 		    loginname = g_string_new(loginname->str);
	 		    if (strcmp (loginname->str, "") == 0) {
	 		    	end_text = " Using secure connection ";
	 		    } else {
	 		    	end_text = " is using secure connection";
	 		    }
	 		    GString * statusbar_output = g_string_append (loginname, end_text);
            	guint statusbar_output_id = gtk_statusbar_get_context_id (GTK_STATUSBAR(statusbar),
			 	   												          statusbar_output->str);
                gtk_statusbar_push (GTK_STATUSBAR(statusbar),
                		           statusbar_output_id,
        		                   statusbar_output->str);

            } else {
	       	    empty_identifier = gtk_statusbar_push(GTK_STATUSBAR(statusbar),
	    		                                      empty_context_id,
		                                              empty_statusbar);
            }
	    } else {
	        empty_identifier = gtk_statusbar_push (GTK_STATUSBAR(statusbar),
	    	    	                              empty_context_id,
		                                          empty_statusbar);
	    }
}

void
setup_statusbar (GladeXML *glade_xml)
{
        /* Dialog box */
        statusbar = glade_xml_get_widget (glade_xml, "statusbar");
        g_assert (statusbar != NULL);
}
