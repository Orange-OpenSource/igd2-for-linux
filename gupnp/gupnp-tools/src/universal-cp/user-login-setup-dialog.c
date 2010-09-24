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

#include <string.h>
#include <stdlib.h>
#include <config.h>
#include <glib.h>

#include "gui.h"
#include "user-login-setup-dialog.h"
#include "statusbar.h"
#include "main.h"

static GtkWidget *user_login_setup_dialog;
static GtkWidget *uls_dialog_username_entry;
static GtkWidget *uls_dialog_password_entry;


void
start_user_login_setup (GladeXML *glade_xml)
{
	    GUPnPDeviceInfo *info;
	    
	    info = get_selected_device_info ();
	    if (get_selected_device_info ()) {
            init_user_login_dialog_fields();
	        gtk_dialog_run (GTK_DIALOG (user_login_setup_dialog));
	        gtk_widget_hide (user_login_setup_dialog);
	    } else {
	    	/* Device must be selected before starting User login setup */
	        GtkWidget *info_dialog;

	    	info_dialog = gtk_message_dialog_new (GTK_WINDOW (user_login_setup_dialog),
	    	                                      GTK_DIALOG_MODAL,
	    	                                      GTK_MESSAGE_INFO,
	    	                                      GTK_BUTTONS_CLOSE,
	    	                                      "No Device selected for User login");
	    	gtk_dialog_run (GTK_DIALOG (info_dialog));
	        gtk_widget_destroy (info_dialog);
	    }
}

void
uls_dialog_login_clicked (GladeXML *glade_xml)
{
	    GUPnPDeviceProxyLogin *deviceProxyLogin;
	    GUPnPDeviceInfo *info;
	    GUPnPDeviceProxy *deviceProxy;
	    const gchar *username=NULL, *password=NULL;
	    gpointer user_data = NULL;

	    info = get_selected_device_info ();
    	deviceProxy = GUPNP_DEVICE_PROXY (info);
    	g_assert (deviceProxy != NULL);

    	username = gtk_entry_get_text (GTK_ENTRY(uls_dialog_username_entry));
    	password = gtk_entry_get_text (GTK_ENTRY(uls_dialog_password_entry));

    	if ((strcmp (username, "") == 0) || (strcmp (password, "") == 0)) {
	    	/* No username or password given for login */
	        GtkWidget *info_dialog;

	    	info_dialog = gtk_message_dialog_new (GTK_WINDOW (user_login_setup_dialog),
	    	                                      GTK_DIALOG_MODAL,
	    	                                      GTK_MESSAGE_INFO,
	    	                                      GTK_BUTTONS_CLOSE,
	    	                                      "Username or password missing! ");
	    	gtk_dialog_run (GTK_DIALOG (info_dialog));
	        gtk_widget_destroy (info_dialog);

	        return;
    	}

        // change cursor
        gdk_window_set_cursor (GTK_WIDGET(user_login_setup_dialog)->window, gdk_cursor_new(GDK_WATCH));

        deviceProxyLogin = gupnp_device_proxy_begin_login (deviceProxy,
                                                           username,
	                                                       password,
	                                                       continue_login_cb,
	                                                       user_data);
}

void
continue_login_cb (GUPnPDeviceProxy       *proxy,
                   GUPnPDeviceProxyLogin  *logindata,
                   GError                **error,
                   gpointer                user_data)
{       
        // change cursor back
        gdk_window_set_cursor (GTK_WIDGET(user_login_setup_dialog)->window, NULL);
                 
	    if ((*error) != NULL) {

	        GtkWidget *error_dialog;

	        error_dialog = gtk_message_dialog_new (GTK_WINDOW (user_login_setup_dialog),
	                                               GTK_DIALOG_MODAL,
	                                               GTK_MESSAGE_ERROR,
	                                               GTK_BUTTONS_CLOSE,
	                                               "User login failed.\n\nError %d: %s",
	                                               (*error)->code,
	                                               (*error)->message);
            gtk_dialog_run (GTK_DIALOG (error_dialog));
            gtk_widget_destroy (error_dialog);

           	g_error_free ((*error));

            gupnp_device_proxy_end_login (logindata, NULL);
            
            // gupnp_device_proxy_end_login must be called before statusbar_update, so that username is set correctly
            statusbar_update (TRUE);
            return;
        }

        if (gupnp_device_proxy_end_login(logindata, NULL)) {
            statusbar_update (TRUE);
            // User login successfully formed
            GtkWidget *info_dialog;
            info_dialog = gtk_message_dialog_new (GTK_WINDOW (user_login_setup_dialog),
                                                  GTK_DIALOG_MODAL,
                                                  GTK_MESSAGE_INFO,
                                                  GTK_BUTTONS_CLOSE,
                                                  "User login successfully performed");

            gtk_dialog_run (GTK_DIALOG (info_dialog));
            gtk_widget_destroy (info_dialog);
            
            // We could close the dialog here if we wanted
            //gtk_dialog_response(GTK_DIALOG (user_login_setup_dialog), GTK_RESPONSE_CLOSE);
        }
}

void
uls_dialog_logout_clicked (GladeXML *glade_xml)
{
		GUPnPDeviceProxyLogout *deviceProxyLogout;
		GUPnPDeviceInfo *info;
		GUPnPDeviceProxy *deviceProxy;
		gpointer user_data = NULL;

		info = get_selected_device_info ();
		deviceProxy = GUPNP_DEVICE_PROXY (info);
		g_assert (deviceProxy != NULL);

        // change cursor
        gdk_window_set_cursor (GTK_WIDGET(user_login_setup_dialog)->window, gdk_cursor_new(GDK_WATCH));

		deviceProxyLogout = gupnp_device_proxy_begin_logout (deviceProxy,
															 continue_logout_cb,
                                     	                     user_data);
}

void
continue_logout_cb (GUPnPDeviceProxy        *proxy,
					GUPnPDeviceProxyLogout  *logoutdata,
                    GError                 **error,
                    gpointer                 user_data)
{
        // change cursor back
        gdk_window_set_cursor (GTK_WIDGET(user_login_setup_dialog)->window, NULL);    
      
	    if ((*error) != NULL) {
	        GtkWidget *error_dialog;

	        error_dialog = gtk_message_dialog_new (GTK_WINDOW (user_login_setup_dialog),
	                                               GTK_DIALOG_MODAL,
	                                               GTK_MESSAGE_ERROR,
	                                               GTK_BUTTONS_CLOSE,
	                                               "User logout failed.\n\nError %d: %s",
	                                               (*error)->code,
	                                               (*error)->message);
            gtk_dialog_run (GTK_DIALOG (error_dialog));
            gtk_widget_destroy (error_dialog);

            g_error_free ((*error));

            gupnp_device_proxy_end_logout (logoutdata);
            
            statusbar_update (TRUE);
            return;
        }

        if (gupnp_device_proxy_end_logout (logoutdata)) {
            statusbar_update (TRUE);
            // User logout successfully formed
            GtkWidget *info_dialog;

            info_dialog = gtk_message_dialog_new (GTK_WINDOW (user_login_setup_dialog),
                                                  GTK_DIALOG_MODAL,
                                                  GTK_MESSAGE_INFO,
                                                  GTK_BUTTONS_CLOSE,
                                                  "User logout successfully performed");

            gtk_dialog_run (GTK_DIALOG (info_dialog));
            gtk_widget_destroy (info_dialog);
        }
}

void
continue_change_password_cb (GUPnPDeviceProxy                *proxy,
                             GUPnPDeviceProxyChangePassword  *passworddata,
                             GError                         **error,
                             gpointer                         user_data)
{
        const gchar *username = gtk_entry_get_text (GTK_ENTRY(uls_dialog_username_entry));
        GString *loginname = g_string_new(username);
    
        // change cursor back
        gdk_window_set_cursor (GTK_WIDGET(user_login_setup_dialog)->window, NULL);
     
        if ((*error) != NULL) {
    
            GtkWidget *error_dialog;
    
            error_dialog = gtk_message_dialog_new (GTK_WINDOW (user_login_setup_dialog),
                                                   GTK_DIALOG_MODAL,
                                                   GTK_MESSAGE_ERROR,
                                                   GTK_BUTTONS_CLOSE,
                                                   "Password change failed.\n\nError %d: %s",
                                                   (*error)->code,
                                                   (*error)->message);
            gtk_dialog_run (GTK_DIALOG (error_dialog));
            gtk_widget_destroy (error_dialog);
    
            g_error_free ((*error));
    
            gupnp_device_proxy_end_change_password (passworddata, loginname);
            
            statusbar_update (TRUE);
            return;
        }
    
        if (gupnp_device_proxy_end_change_password (passworddata, loginname)) {
            statusbar_update (TRUE);
            // Password successfully changed
        	GtkWidget *info_dialog;
    
            info_dialog = gtk_message_dialog_new (GTK_WINDOW (user_login_setup_dialog),
                                                  GTK_DIALOG_MODAL,
                                                  GTK_MESSAGE_INFO,
                                                  GTK_BUTTONS_CLOSE,
                                                  "Password successfully changed");
    
            gtk_dialog_run (GTK_DIALOG (info_dialog));
            gtk_widget_destroy (info_dialog);
        }
}

void
uls_dialog_change_password_clicked (GladeXML *glade_xml)
{
		GUPnPDeviceProxyChangePassword *deviceProxyChangePassword;
		const gchar *username=NULL, *password=NULL;
		gpointer user_data = NULL;

		username = gtk_entry_get_text (GTK_ENTRY(uls_dialog_username_entry));
	    password = gtk_entry_get_text (GTK_ENTRY(uls_dialog_password_entry));

	    if ((strcmp (username, "") == 0) || (strcmp (password, "") == 0)) {
	        /* No username or password given for login */
   	        GtkWidget *info_dialog;

   	    	info_dialog = gtk_message_dialog_new (GTK_WINDOW (user_login_setup_dialog),
   	    	                                      GTK_DIALOG_MODAL,
   	    	                                      GTK_MESSAGE_INFO,
   	    	                                      GTK_BUTTONS_CLOSE,
   	    	                                      "Username or password missing! ");
   	    	gtk_dialog_run (GTK_DIALOG (info_dialog));
   	        gtk_widget_destroy (info_dialog);

   	        return;
       	}

        GUPnPDeviceInfo *info = get_selected_device_info ();
        GUPnPDeviceProxy *deviceProxy = GUPNP_DEVICE_PROXY (info);
		g_assert (deviceProxy != NULL);

        // change cursor
        gdk_window_set_cursor (GTK_WIDGET(user_login_setup_dialog)->window, gdk_cursor_new(GDK_WATCH));

        deviceProxyChangePassword = gupnp_device_proxy_change_password (deviceProxy,
                                                                        username,
                                                                        password,
                                                                        continue_change_password_cb,
                                                                        user_data);
}

void
init_user_login_dialog_fields (void)
{
  if (g_getenv("GUPNP_PREFILL"))		// TEST
  {
        gtk_entry_set_text (GTK_ENTRY(uls_dialog_username_entry), "Administrator");
        gtk_entry_set_text (GTK_ENTRY(uls_dialog_password_entry), "admin password");
  }
  else
  {
        gtk_entry_set_text (GTK_ENTRY(uls_dialog_username_entry), "");
        gtk_entry_set_text (GTK_ENTRY(uls_dialog_password_entry), "");
  }
}

void
init_user_login_setup_dialog (GladeXML *glade_xml)
{
        /* Dialog box */
	    user_login_setup_dialog = glade_xml_get_widget (glade_xml, "user-login-setup-dialog");
        g_assert (user_login_setup_dialog != NULL);

        /* Entrys */
        uls_dialog_username_entry = glade_xml_get_widget (glade_xml, "user-login-setup-dialog-username-entry");
        uls_dialog_password_entry = glade_xml_get_widget (glade_xml, "user-login-setup-dialog-password-entry");
        g_assert (uls_dialog_username_entry != NULL);
        g_assert (uls_dialog_password_entry != NULL);
}

void
deinit_user_login_setup_dialog (void)
{
        gtk_widget_destroy (user_login_setup_dialog);
}
