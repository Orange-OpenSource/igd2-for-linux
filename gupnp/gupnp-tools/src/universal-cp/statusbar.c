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
static GtkWidget *sslimage;

void
statusbar_update (gboolean device_selected)
{
	    const gchar *empty_statusbar="";

        guint statusbar_output_id = gtk_statusbar_get_context_id (GTK_STATUSBAR(statusbar),
                                                                  "username");
                                                                  
	    if (device_selected) {
		    GUPnPDeviceInfo *info;
		    GUPnPDeviceProxy *deviceProxy;

		    info = get_selected_device_info ();
		    deviceProxy = GUPNP_DEVICE_PROXY (info);

		    /* If SSL client exist, update status bar */
		    if (*(gupnp_device_proxy_get_ssl_client (deviceProxy))) {
                // update SSL lock, if SSL is used
                gtk_image_set_from_stock(GTK_IMAGE(sslimage), GTK_STOCK_DIALOG_AUTHENTICATION, GTK_ICON_SIZE_SMALL_TOOLBAR);
                
                // update logged in username, if any
			    GString *loginname = gupnp_device_proxy_get_username (deviceProxy);
                
                if (loginname && (strcmp (loginname->str, "") != 0))
                {
                    g_string_prepend(loginname, "Username: ");

                    gtk_statusbar_push (GTK_STATUSBAR(statusbar),
                    		           statusbar_output_id,
            		                   loginname->str);
                }
                if (loginname)
                    g_string_free(loginname, TRUE);

            } else {
                // clear ssl-lock image
                gtk_image_clear(GTK_IMAGE(sslimage));
	       	    gtk_statusbar_push(GTK_STATUSBAR(statusbar),
                                   statusbar_output_id,
                                   empty_statusbar);
            }
	    } else {
            // clear ssl-lock image
            gtk_image_clear(GTK_IMAGE(sslimage));
	        gtk_statusbar_push (GTK_STATUSBAR(statusbar),
                                statusbar_output_id,
                                empty_statusbar);
	    }
}

void
init_statusbar (GladeXML *glade_xml)
{
        /* Dialog box */
        statusbar = glade_xml_get_widget (glade_xml, "statusbar");
        g_assert (statusbar != NULL);
        sslimage = glade_xml_get_widget (glade_xml, "ssl-image");
        g_assert (sslimage != NULL);
        
        // initially clear sslimage. No SSL connection is created yet
        gtk_image_clear(GTK_IMAGE(sslimage));
}
