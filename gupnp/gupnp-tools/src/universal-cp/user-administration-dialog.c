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
#include "user-administration-dialog.h"
#include "main.h"

/* User administration dialog */
static GtkWidget *user_admininistration_dialog;
static GtkWidget *ua_dialog_scrolled_window;
static GtkWidget *ua_dialog_table;
static GtkWidget *ua_dialog_username_label1;
static GtkWidget *ua_dialog_username_entry1;
static GtkWidget *ua_dialog_public_checkbutton1;
static GtkWidget *ua_dialog_basic_checkbutton1;
static GtkWidget *ua_dialog_admin_checkbutton1;
static GtkWidget *ua_dialog_add_button;
static GtkWidget *ua_dialog_remove_button;
static GtkWidget *ua_dialog_ok_button;

/* Add user dialog */
static GtkWidget *add_user_dialog;
static GtkWidget *add_user_dialog_username_label;
static GtkWidget *add_user_dialog_password_label;
static GtkWidget *add_user_dialog_role_label;
static GtkWidget *add_user_dialog_username_entry;
static GtkWidget *add_user_dialog_password_entry;
static GtkWidget *add_user_dialog_public_checkbutton;
static GtkWidget *add_user_dialog_basic_checkbutton;
static GtkWidget *add_user_dialog_admin_checkbutton;

/*
 * User administration dialog functions
 */
void
start_user_administration (GladeXML *glade_xml)
{
		guint nbr_of_users=1;
	    init_user_administration_dialog_fields();
	    // TODO: parsi XML:stä montako käyttäjää = montako riviä taulukkoon
	    // TODO: parsi XML:stä: username, nykyinen rooli

		/* ihan vain kokeiluja...
	    nbr_of_users=7;
	    add_new_user_to_table(1,"Pera",1);
	    add_new_user_to_table(2,"Jake",2);
	    add_new_user_to_table(3,"Make",3);
	    add_new_user_to_table(4,"Make",2);
	    add_new_user_to_table(5,"Make",0);
	    add_new_user_to_table(6,"Make",1);
	    */

	    gtk_window_resize (GTK_WINDOW (user_admininistration_dialog),
	                       130,
	                       (100+(nbr_of_users*30)));
        gtk_dialog_run (GTK_DIALOG (user_admininistration_dialog));
        gtk_widget_hide (user_admininistration_dialog);
}

void
add_new_user_to_table(guint row, const gchar *username, guint role)
{
        /* Add "Username" label to table */
        GtkWidget* new_username_label = gtk_label_new ("Username");
        gtk_table_attach (GTK_TABLE (ua_dialog_table),
    	    	          new_username_label,
    		              0,
                          1,
                          row,
                          row + 1,
                          GTK_EXPAND | GTK_FILL,
                          GTK_EXPAND | GTK_FILL,
                          0,
                          0);

        /* Add new Username to table   */
        GtkWidget* new_username = gtk_entry_new ();
        gtk_entry_set_text (GTK_ENTRY(new_username), username);
        gtk_entry_set_editable (GTK_ENTRY(new_username), FALSE);
        gtk_table_attach (GTK_TABLE (ua_dialog_table),
    	    	          new_username,
    		              1,
                          2,
                          row,
                          row + 1,
                          GTK_EXPAND | GTK_FILL,
                          GTK_EXPAND | GTK_FILL,
                          0,
                          0);

        /* Add new checkbuttons to table   */
        GtkWidget* new_public_checkbutton = gtk_check_button_new_with_label ("Public");
        GtkWidget* new_basic_checkbutton = gtk_check_button_new_with_label ("Basic");
        GtkWidget* new_admin_checkbutton = gtk_check_button_new_with_label ("Admin");

        // TODO: Set active role from xml
        if (role==0)
        	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(new_public_checkbutton), TRUE);
        if (role==1)
        	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(new_basic_checkbutton), TRUE);
		if (role==2)
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(new_admin_checkbutton), TRUE);

        gtk_table_attach (GTK_TABLE (ua_dialog_table),
        		          new_public_checkbutton,
    	    	          2,
                          3,
                          row,
                          row + 1,
                          GTK_EXPAND | GTK_FILL,
                          GTK_EXPAND | GTK_FILL,
                          0,
                          0);
        gtk_table_attach (GTK_TABLE (ua_dialog_table),
    	    	          new_basic_checkbutton,
    		              3,
                          4,
                          row,
                          row + 1,
                          GTK_EXPAND | GTK_FILL,
                          GTK_EXPAND | GTK_FILL,
                          0,
                          0);
        gtk_table_attach (GTK_TABLE (ua_dialog_table),
        		          new_admin_checkbutton,
    	    	          4,
                          5,
                          row,
                          row + 1,
                          GTK_EXPAND | GTK_FILL,
                          GTK_EXPAND | GTK_FILL,
                          0,
                          0);

        gtk_widget_show (new_username_label);
        gtk_widget_show (new_username);
        gtk_widget_show (new_public_checkbutton);
        gtk_widget_show (new_basic_checkbutton);
        gtk_widget_show (new_admin_checkbutton);

	    // TODO: Scrollbar ikkuna pitäisi saada jotenkin toimimaan, kun lisätään käyttäjiä..
	    // gtk_container_add (GTK_CONTAINER(ua_dialog_scrolled_window), ua_dialog_table);
	    // gtk_widget_show (ua_dialog_scrolled_window);
}
void
init_user_administration_dialog_fields (void)
{
        gtk_entry_set_editable (GTK_ENTRY(ua_dialog_username_entry1), FALSE);
	    gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(ua_dialog_admin_checkbutton1), TRUE);
	    gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(ua_dialog_basic_checkbutton1), FALSE);
	    gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(ua_dialog_public_checkbutton1), FALSE);

}

void
init_user_administration_dialog (GladeXML *glade_xml)
{
        /* Dialog box */
	    user_admininistration_dialog = glade_xml_get_widget (glade_xml, "user-administration-dialog");
        g_assert (user_admininistration_dialog != NULL);

        /* Scrolled window */
        ua_dialog_scrolled_window = glade_xml_get_widget (glade_xml, "ua-dialog-scrolledwindow");
	    g_assert (ua_dialog_scrolled_window != NULL);

		/* Table */
        ua_dialog_table = glade_xml_get_widget (glade_xml, "ua-dialog-table");
	    g_assert (ua_dialog_table != NULL);

        /* User name label */
        ua_dialog_username_label1 = glade_xml_get_widget (glade_xml, "ua-dialog-username-label1");
        g_assert (ua_dialog_username_label1 != NULL);

        /* User name entry */
        ua_dialog_username_entry1 = glade_xml_get_widget (glade_xml, "ua-username-entry1");
        g_assert (ua_dialog_username_entry1 != NULL);

        /* All check buttons */
        ua_dialog_public_checkbutton1 = glade_xml_get_widget (glade_xml, "username1-checkbutton1");
        ua_dialog_basic_checkbutton1 = glade_xml_get_widget (glade_xml, "username1-checkbutton2");
        ua_dialog_admin_checkbutton1 = glade_xml_get_widget (glade_xml, "username1-checkbutton3");
        g_assert (ua_dialog_public_checkbutton1 != NULL);
        g_assert (ua_dialog_basic_checkbutton1 != NULL);
        g_assert (ua_dialog_admin_checkbutton1 != NULL);

		/* Add button */
        ua_dialog_add_button = glade_xml_get_widget (glade_xml, "ua-dialog-add");
        g_assert (ua_dialog_add_button != NULL);

		/* Remove button */
        ua_dialog_remove_button = glade_xml_get_widget (glade_xml, "ua-dialog-remove");
        g_assert (ua_dialog_remove_button != NULL);

		/* OK button */
        ua_dialog_ok_button = glade_xml_get_widget (glade_xml, "ua-dialog-ok");
        g_assert (ua_dialog_ok_button != NULL);
}

void
deinit_user_administration_dialog (void)
{
        gtk_widget_destroy (user_admininistration_dialog);
}

void
ua_dialog_remove_user (GladeXML *glade_xml)
{
	    // TODO: remove selected user from table etc...
}

void
ua_dialog_role_setup (GladeXML *glade_xml)
{
	    // TODO: role change took place...
}

/*
 * Add User dialog functions
 */
void
start_add_user_dialog (GladeXML *glade_xml)
{
	    init_add_user_dialog_fields();
        gtk_dialog_run (GTK_DIALOG (add_user_dialog));
        gtk_widget_hide (add_user_dialog);
}


void
add_user_dialog_ok_pressed (GladeXML *glade_xml)
{
        // TODO: Collect data...
}

void
init_add_user_dialog_fields (void)
{
        gtk_entry_set_text (GTK_ENTRY(add_user_dialog_username_entry), "");
        gtk_entry_set_text (GTK_ENTRY(add_user_dialog_password_entry), "");
        gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(add_user_dialog_public_checkbutton), FALSE);
        gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(add_user_dialog_basic_checkbutton), FALSE);
        gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(add_user_dialog_admin_checkbutton), FALSE);
}

void
init_add_user_dialog (GladeXML *glade_xml)
{
	    /* Dialog box */
        add_user_dialog = glade_xml_get_widget (glade_xml, "add-user-dialog");
	    g_assert (add_user_dialog != NULL);

	    /* User name labels */
	    add_user_dialog_username_label = glade_xml_get_widget (glade_xml, "add-user-dialog-label-username");
	    add_user_dialog_password_label = glade_xml_get_widget (glade_xml, "add-user-dialog-label-password");
	    add_user_dialog_role_label = glade_xml_get_widget (glade_xml, "add-user-dialog-label-role");
	    g_assert (add_user_dialog_username_label != NULL);
	    g_assert (add_user_dialog_password_label != NULL);
	    g_assert (add_user_dialog_role_label != NULL);

	    /* Entrys */
	    add_user_dialog_username_entry = glade_xml_get_widget (glade_xml, "add-user-dialog-username");
	    add_user_dialog_password_entry = glade_xml_get_widget (glade_xml, "add-user-dialog-password");
        g_assert (add_user_dialog_username_entry != NULL);
	    g_assert (add_user_dialog_password_entry != NULL);

	    /* Check buttons */
	    add_user_dialog_public_checkbutton = glade_xml_get_widget (glade_xml, "add-user-dialog-public");
	    add_user_dialog_basic_checkbutton = glade_xml_get_widget (glade_xml, "add-user-dialog-basic");
	    add_user_dialog_admin_checkbutton = glade_xml_get_widget (glade_xml, "add-user-dialog-admin");
        g_assert (add_user_dialog_public_checkbutton != NULL);
	    g_assert (add_user_dialog_basic_checkbutton != NULL);
	    g_assert (add_user_dialog_admin_checkbutton != NULL);
}

void
deinit_add_user_dialog (void)
{
        gtk_widget_destroy (add_user_dialog);
}
