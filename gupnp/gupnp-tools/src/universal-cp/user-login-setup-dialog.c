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

#include "gui.h"
#include "user-login-setup-dialog.h"
#include "main.h"

static GtkWidget *user_login_setup_dialog;
static GtkWidget *uls_dialog_username_label;
static GtkWidget *uls_dialog_password_label;
static GtkWidget *uls_dialog_username_entry;
static GtkWidget *uls_dialog_password_entry;
static GtkWidget *uls_dialog_change_password_button;
static GtkWidget *uls_dialog_logout_button;
static GtkWidget *uls_dialog_login_button;

void
start_user_login_setup (GladeXML *glade_xml)
{
	    init_user_login_dialog_fields();
        gtk_dialog_run (GTK_DIALOG (user_login_setup_dialog));
        gtk_widget_hide (user_login_setup_dialog);
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
