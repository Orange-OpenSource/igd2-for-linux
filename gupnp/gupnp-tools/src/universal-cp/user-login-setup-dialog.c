/*
 * user-login-setup-dialog.c
 *
 *  Created on: Jun 4, 2009
 *      Author: vlillvis
 */

/*
 * user-administration-dialog.c
 *
 *  Created on: Jun 4, 2009
 *      Author: vlillvis
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
static GtkWidget *uls_dialog_username_label;
static GtkWidget *uls_dialog_password_label;
static GtkWidget *uls_dialog_username_entry;
static GtkWidget *uls_dialog_password_entry;
static GtkWidget *uls_dialog_change_password_button;
static GtkWidget *uls_dialog_logout_button;
static GtkWidget *uls_dialog_login_button;

const gchar *current_username="";

void
get_current_username(GString *current_user)
{
    GString *user = g_string_new(current_username);
	current_user->str = user->str;
}

void
start_user_login_setup (GladeXML *glade_xml)
{
	    GUPnPDeviceInfo *info;
	    init_user_login_dialog_fields();

	    info = get_selected_device_info ();
	    if (get_selected_device_info ()) {
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
	    const gchar *username = gtk_entry_get_text (GTK_ENTRY(uls_dialog_username_entry));
	    GString *loginname = g_string_new(username);

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

            gtk_widget_hide (user_login_setup_dialog);
           	g_error_free ((*error));

            gupnp_device_proxy_end_login (logindata, loginname);
            return;
        }

        if (gupnp_device_proxy_end_login(logindata, loginname)) {
            // User login successfully formed
        	// Save current username

        	current_username = loginname->str;

            GtkWidget *info_dialog;

            info_dialog = gtk_message_dialog_new (GTK_WINDOW (user_login_setup_dialog),
                                                  GTK_DIALOG_MODAL,
                                                  GTK_MESSAGE_INFO,
                                                  GTK_BUTTONS_CLOSE,
                                                  "User login successfully performed");

            gtk_dialog_run (GTK_DIALOG (info_dialog));
            gtk_widget_destroy (info_dialog);
    	    gtk_widget_hide (user_login_setup_dialog);
    	    statusbar_update (TRUE);
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

            gtk_widget_hide (user_login_setup_dialog);
            g_error_free ((*error));

            gupnp_device_proxy_end_logout (logoutdata);
            return;
        }

        if (gupnp_device_proxy_end_logout (logoutdata)) {
            // User logout successfully formed
            GtkWidget *info_dialog;

            info_dialog = gtk_message_dialog_new (GTK_WINDOW (user_login_setup_dialog),
                                                  GTK_DIALOG_MODAL,
                                                  GTK_MESSAGE_INFO,
                                                  GTK_BUTTONS_CLOSE,
                                                  "User logout successfully performed");

            gtk_dialog_run (GTK_DIALOG (info_dialog));
            gtk_widget_destroy (info_dialog);
    	    gtk_widget_hide (user_login_setup_dialog);
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

        gtk_widget_hide (user_login_setup_dialog);
        g_error_free ((*error));

        gupnp_device_proxy_end_change_password (passworddata, loginname);
        return;
    }

    if (gupnp_device_proxy_end_change_password (passworddata, loginname)) {
        // Password successfully changed
    	GtkWidget *info_dialog;

        info_dialog = gtk_message_dialog_new (GTK_WINDOW (user_login_setup_dialog),
                                              GTK_DIALOG_MODAL,
                                              GTK_MESSAGE_INFO,
                                              GTK_BUTTONS_CLOSE,
                                              "Password successfully changed");

        gtk_dialog_run (GTK_DIALOG (info_dialog));
        gtk_widget_destroy (info_dialog);
	    gtk_widget_hide (user_login_setup_dialog);
    }
}

void
uls_dialog_change_password_clicked (GladeXML *glade_xml)
{
		GUPnPDeviceProxyChangePassword *deviceProxyChangePassword;
		const gchar *username=NULL, *password=NULL;
		gpointer user_data = NULL;

	    const gchar *user= "Jaakko";
	    GString *loginname = g_string_new(user);
		username = gtk_entry_get_text (GTK_ENTRY(uls_dialog_username_entry));
	    password = gtk_entry_get_text (GTK_ENTRY(uls_dialog_password_entry));
	    GString *username_entry = g_string_new(username);

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

        get_current_username(loginname);
        if (strcmp (loginname->str, username_entry->str)) {
	         /* Given username should be current username */
	         GtkWidget *info_dialog;

	    	 info_dialog = gtk_message_dialog_new (GTK_WINDOW (user_login_setup_dialog),
	    	                                       GTK_DIALOG_MODAL,
	    	                                       GTK_MESSAGE_INFO,
	    	                                       GTK_BUTTONS_CLOSE,
	    	                                       "Password change is only possible for current user! ");
	    	 gtk_dialog_run (GTK_DIALOG (info_dialog));
	         gtk_widget_destroy (info_dialog);
	         return;
        }

        GUPnPDeviceInfo *info = get_selected_device_info ();
        GUPnPDeviceProxy *deviceProxy = GUPNP_DEVICE_PROXY (info);
		g_assert (deviceProxy != NULL);

        deviceProxyChangePassword = gupnp_device_proxy_change_password (deviceProxy,
                                                                        username,
                                                                        password,
                                                                        continue_change_password_cb,
                                                                        user_data);
}

void
init_user_login_dialog_fields (void)
{
        gtk_entry_set_text (GTK_ENTRY(uls_dialog_username_entry), "");
        gtk_entry_set_text (GTK_ENTRY(uls_dialog_password_entry), "");
}

void
init_user_login_setup_dialog (GladeXML *glade_xml)
{
        /* Dialog box */
	    user_login_setup_dialog = glade_xml_get_widget (glade_xml, "user-login-setup-dialog");
        g_assert (user_login_setup_dialog != NULL);

        /* Labels */
        uls_dialog_username_label = glade_xml_get_widget (glade_xml, "user-login-setup-dialog-username-label");
        uls_dialog_password_label = glade_xml_get_widget (glade_xml, "user-login-setup-dialog-password-label");
        g_assert (uls_dialog_username_label != NULL);
        g_assert (uls_dialog_password_label != NULL);

        /* Entrys */
        uls_dialog_username_entry = glade_xml_get_widget (glade_xml, "user-login-setup-dialog-username-entry");
        uls_dialog_password_entry = glade_xml_get_widget (glade_xml, "user-login-setup-dialog-password-entry");
        g_assert (uls_dialog_username_entry != NULL);
        g_assert (uls_dialog_password_entry != NULL);

		/* Buttons */
        uls_dialog_change_password_button = glade_xml_get_widget (glade_xml, "user-login-setup-dialog-change-password-button");
        uls_dialog_logout_button = glade_xml_get_widget (glade_xml, "user-login-setup-dialog-logout-button");
        uls_dialog_login_button = glade_xml_get_widget (glade_xml, "user-login-setup-dialog-login-button");
        g_assert (uls_dialog_change_password_button != NULL);
        g_assert (uls_dialog_logout_button != NULL);
        g_assert (uls_dialog_login_button != NULL);
}

void
deinit_user_login_setup_dialog (void)
{
        gtk_widget_destroy (user_login_setup_dialog);
}
