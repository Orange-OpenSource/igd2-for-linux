/**
 * This file is part of Nokia DeviceProtection v1 reference implementation
 * Copyright © 2010 Nokia Corporation and/or its subsidiary(-ies).
 * Contact:mika.saaranen@nokia.com
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program. If not, see http://www.gnu.org/licenses/.
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
                else // no username is logged in, clear the statusbar text
                {
                    gtk_statusbar_push (GTK_STATUSBAR(statusbar),
                                        statusbar_output_id,
                                        empty_statusbar);
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
