/* * statusbar.c
 *
 *  Created on: May 19, 2009
 *      Author: vlillvis
 */

#include "statusbar.h"
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
		guint user_name_context_id;
		guint user_identifier;
		const gchar *user_name="Secure connection for Username: Admin";

		user_name_context_id = gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar),
				                                  user_name);
		// TODO: Check whether connection is secured or not with library call...
		// if (wps_connection) {
		// TODO: find device name with library call...
        user_identifier = gtk_statusbar_push(GTK_STATUSBAR(statusbar),
        		                             user_name_context_id,
			                                 user_name);
        /* } else {
	       } // Clearing statusbar...
	       	    empty_identifier = gtk_statusbar_push(GTK_STATUSBAR(statusbar),
	    		                              empty_context_id,
		                                      empty_statusbar);
	    */
	} else {
	    empty_identifier = gtk_statusbar_push(GTK_STATUSBAR(statusbar),
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
