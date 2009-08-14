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
static GtkWidget *ua_dialog_table;
static GtkWidget *ua_dialog_add_button;
static GtkWidget *ua_dialog_remove_button;
static GtkWidget *ua_dialog_ok_button;
static GtkWidget *ua_dialog_radiobutton1;

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

/* */
guint nbr_of_users=0;

typedef enum
{
	     UNKNOWN_ROLE,
         ADMIN_ROLE,
         BASIC_ROLE,
         PUBLIC_ROLE
} userRole;


/*
 * User administration dialog functions
 */

static void clear_user_table()
{
        GList     *child_node;        
        GtkContainer *table = GTK_CONTAINER(ua_dialog_table);
        
        for (child_node = gtk_container_get_children (table);
             child_node;
             child_node = child_node->next) {
                GtkWidget *widget;

                widget = GTK_WIDGET (child_node->data);
     
                gtk_container_remove (table, widget);
        }
        
        ua_dialog_radiobutton1 = NULL;
}

static void add_users_to_table(gpointer key,
                       gpointer value,
                       gpointer user_data)
{
        guint row = nbr_of_users++;
        guint column = 0;
        gchar *username = key; 
    
        /* Add Selection radiobutton to table */
        GtkWidget* new_radiobutton;
        if (ua_dialog_radiobutton1 == NULL)
        {
            ua_dialog_radiobutton1 = gtk_radio_button_new(NULL);
            gtk_table_attach (GTK_TABLE (ua_dialog_table),
                              ua_dialog_radiobutton1,
                              column,
                              column + 1,
                              row,
                              row + 1,
                              GTK_EXPAND | GTK_FILL,
                              GTK_EXPAND | GTK_FILL,
                              0,
                              0);
            new_radiobutton = ua_dialog_radiobutton1;
        }
        else
        {
              new_radiobutton = gtk_radio_button_new_from_widget (GTK_RADIO_BUTTON (ua_dialog_radiobutton1));
              gtk_table_attach (GTK_TABLE (ua_dialog_table),
                              new_radiobutton,
                              column,
                              column + 1,
                              row,
                              row + 1,
                              GTK_EXPAND | GTK_FILL,
                              GTK_EXPAND | GTK_FILL,
                              0,
                              0);                   
        }
        column++;
                     
        /* Add "Username" label to table */
        GtkWidget* new_username_label = gtk_label_new ("Username");
        gtk_table_attach (GTK_TABLE (ua_dialog_table),
                          new_username_label,
                          column,
                          column + 1,
                          row,
                          row + 1,
                          GTK_EXPAND | GTK_FILL,
                          GTK_EXPAND | GTK_FILL,
                          0,
                          0);
        column++;

        /* Add new Username to table   */
        GtkWidget* new_username = gtk_entry_new ();
        gtk_entry_set_text (GTK_ENTRY(new_username), username);
        gtk_entry_set_editable (GTK_ENTRY(new_username), FALSE);
        gtk_table_attach (GTK_TABLE (ua_dialog_table),
                          new_username,
                          column,
                          column + 1,
                          row,
                          row + 1,
                          GTK_EXPAND | GTK_FILL,
                          GTK_EXPAND | GTK_FILL,
                          0,
                          0);
        column++;

        /* Add new checkbuttons to table   */
        GtkWidget* new_public_checkbutton = gtk_check_button_new_with_label ("Public");
        GtkWidget* new_basic_checkbutton = gtk_check_button_new_with_label ("Basic");
        GtkWidget* new_admin_checkbutton = gtk_check_button_new_with_label ("Admin");

        // Set roles
        if (strstr((char*)value, "Admin"))
            gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(new_admin_checkbutton), TRUE);
        if (strstr((char*)value, "Basic"))
            gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(new_basic_checkbutton), TRUE);
        if (strstr((char*)value, "Public"))
            gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(new_public_checkbutton), TRUE);            

        gtk_table_attach (GTK_TABLE (ua_dialog_table),
                          new_public_checkbutton,
                          column,
                          column + 1,
                          row,
                          row + 1,
                          GTK_EXPAND | GTK_FILL,
                          GTK_EXPAND | GTK_FILL,
                          0,
                          0);
        column++;
        gtk_table_attach (GTK_TABLE (ua_dialog_table),
                          new_basic_checkbutton,
                          column,
                          column + 1,
                          row,
                          row + 1,
                          GTK_EXPAND | GTK_FILL,
                          GTK_EXPAND | GTK_FILL,
                          0,
                          0);
        column++;
        gtk_table_attach (GTK_TABLE (ua_dialog_table),
                          new_admin_checkbutton,
                          column,
                          column + 1,
                          row,
                          row + 1,
                          GTK_EXPAND | GTK_FILL,
                          GTK_EXPAND | GTK_FILL,
                          0,
                          0);

        gtk_widget_show (new_radiobutton);
        gtk_widget_show (new_username_label);
        gtk_widget_show (new_username);
        gtk_widget_show (new_public_checkbutton);
        gtk_widget_show (new_basic_checkbutton);
        gtk_widget_show (new_admin_checkbutton);

        gtk_window_resize (GTK_WINDOW (user_admininistration_dialog),
                           130,
                           (100+(nbr_of_users*30)));     
}

static void 
get_ACL_cb(GUPnPDeviceProxy    *proxy,
           GUPnPDeviceProxyGetACLData *ACLData,
           GError             **error,
           gpointer             user_data)
{        
        nbr_of_users = 0;
        
        // user_data should contain ghashtable
        GHashTable *users = user_data;        
        g_hash_table_foreach(users, add_users_to_table, proxy);
}

static 
void update_users_table()
{
        GUPnPDeviceInfo *info = get_selected_device_info ();
        GUPnPDeviceProxy *deviceProxy = GUPNP_DEVICE_PROXY (info);
        g_assert (deviceProxy != NULL);
        
        GHashTable *users = g_hash_table_new (g_str_hash,
                                           g_str_equal);
        
        gupnp_device_proxy_get_ACL_data(deviceProxy, get_ACL_cb, users);    
}

 
void
start_user_administration (GladeXML *glade_xml)
{
	    init_user_administration_dialog_fields();     
        
        update_users_table();

        gtk_dialog_run (GTK_DIALOG (user_admininistration_dialog));
        
        gtk_widget_hide (user_admininistration_dialog);
}


void
init_user_administration_dialog_fields (void)
{
        clear_user_table();
}

void
init_user_administration_dialog (GladeXML *glade_xml)
{
        /* Dialog box */
	    user_admininistration_dialog = glade_xml_get_widget (glade_xml, "user-administration-dialog");
        g_assert (user_admininistration_dialog != NULL);

		/* Table */
        ua_dialog_table = glade_xml_get_widget (glade_xml, "ua-dialog-table");
	    g_assert (ua_dialog_table != NULL);

		/* Add button */
        ua_dialog_add_button = glade_xml_get_widget (glade_xml, "ua-dialog-add");
        g_assert (ua_dialog_add_button != NULL);

		/* Remove button */
        ua_dialog_remove_button = glade_xml_get_widget (glade_xml, "ua-dialog-remove");
        g_assert (ua_dialog_remove_button != NULL);

		/* OK button */
        ua_dialog_ok_button = glade_xml_get_widget (glade_xml, "ua-dialog-ok");
        g_assert (ua_dialog_ok_button != NULL);
        
        /* Firts radio button (because of group) */
        ua_dialog_radiobutton1 = NULL;
}

void
deinit_user_administration_dialog (void)
{
        gtk_widget_destroy (user_admininistration_dialog);
}

void
continue_remove_user_dialog_cb (GUPnPDeviceProxy            *proxy,
		                        GUPnPDeviceProxyRemoveUser  *removeuserdata,
                                GError                     **error,
                                gpointer                     user_data)
{

		if ((*error) != NULL) {
			GtkWidget *error_dialog;

			error_dialog = gtk_message_dialog_new (GTK_WINDOW (user_admininistration_dialog),
                                                   GTK_DIALOG_MODAL,
                                                   GTK_MESSAGE_ERROR,
                                                   GTK_BUTTONS_CLOSE,
                                                   "Removing  user failed.\n\nError %d: %s",
                                                   (*error)->code,
                                                   (*error)->message);
			gtk_dialog_run (GTK_DIALOG (error_dialog));
			gtk_widget_destroy (error_dialog);

			gtk_widget_hide (user_admininistration_dialog);
			g_error_free ((*error));

			gupnp_device_proxy_end_remove_user (removeuserdata);
			return;
		}

		if (gupnp_device_proxy_end_remove_user (removeuserdata)) {
			// User successfully removed
			GtkWidget *info_dialog;

			info_dialog = gtk_message_dialog_new (GTK_WINDOW (user_admininistration_dialog),
                                                  GTK_DIALOG_MODAL,
                                                  GTK_MESSAGE_INFO,
                                                  GTK_BUTTONS_CLOSE,
                                                  "User successfully removed");

			gtk_dialog_run (GTK_DIALOG (info_dialog));
			gtk_widget_destroy (info_dialog);
            
			gtk_widget_hide (user_admininistration_dialog);
		}
        update_users_table();
}

void
ua_dialog_remove_user (GladeXML *glade_xml)
{
	    GUPnPDeviceProxyRemoveUser *deviceProxyRemoveUser;
		gpointer user_data = NULL;
	    const gchar *username = NULL;

        GUPnPDeviceInfo *info = get_selected_device_info ();
        GUPnPDeviceProxy *deviceProxy = GUPNP_DEVICE_PROXY (info);
		g_assert (deviceProxy != NULL);

		// TODO: Get selected username from table.....
        GList     *child_node;        
        GtkContainer *table = GTK_CONTAINER(ua_dialog_table);
        
        for (child_node = gtk_container_get_children (table);
             child_node;
             child_node = child_node->next) {
                GtkWidget *widget;

                widget = GTK_WIDGET (child_node->data);
                if (GTK_IS_RADIO_BUTTON (widget) && gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
                {
                    // Yes I know this awful how this is done. But I don't know any better way to get 
                    // value for selected username. So that is why there are radiobuttons for every row,
                    // and lets just hope that username entry really is prev of prev of selected radiobutton...
                    GtkWidget *username_widget = GTK_WIDGET (child_node->prev->prev->data);
                    if (GTK_IS_ENTRY (username_widget))
                        username = gtk_entry_get_text (GTK_ENTRY (username_widget));
                }
        }

	    deviceProxyRemoveUser = gupnp_device_proxy_remove_user (deviceProxy,
	    		                                                username,
	    		                                                continue_remove_user_dialog_cb,
	                                                            user_data);
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
add_user_dialog_password_cb (GUPnPDeviceProxy                *proxy,
                             GUPnPDeviceProxyChangePassword  *passworddata,
                             GError                         **error,
                             gpointer                         user_data)
{

		const gchar *username = gtk_entry_get_text (GTK_ENTRY(add_user_dialog_username_entry));
		GString *loginname = g_string_new(username);

		if ((*error) != NULL) {
			GtkWidget *error_dialog;

			error_dialog = gtk_message_dialog_new (GTK_WINDOW (user_admininistration_dialog),
												   GTK_DIALOG_MODAL,
                                                   GTK_MESSAGE_ERROR,
                                                   GTK_BUTTONS_CLOSE,
                                                   "Adding new user failed.\n\nError %d: %s",
                                                   (*error)->code,
                                                   (*error)->message);
			gtk_dialog_run (GTK_DIALOG (error_dialog));
			gtk_widget_destroy (error_dialog);

			gtk_widget_hide (user_admininistration_dialog);
			g_error_free ((*error));

			gupnp_device_proxy_end_change_password (passworddata, loginname);
			return;
		}

		if (gupnp_device_proxy_end_change_password (passworddata, loginname)) {
			// Password successfully changed
			GtkWidget *info_dialog;
			userRole role;

			info_dialog = gtk_message_dialog_new (GTK_WINDOW (user_admininistration_dialog),
                                                  GTK_DIALOG_MODAL,
                                                  GTK_MESSAGE_INFO,
                                                  GTK_BUTTONS_CLOSE,
                                                  "New user successfully added");

			gtk_dialog_run (GTK_DIALOG (info_dialog));
			gtk_widget_destroy (info_dialog);
			gtk_widget_hide (user_admininistration_dialog);

			if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(add_user_dialog_admin_checkbutton)))
			    role = ADMIN_ROLE;
			else if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(add_user_dialog_basic_checkbutton)))
				role = BASIC_ROLE;
			else if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(add_user_dialog_public_checkbutton)))
				role = PUBLIC_ROLE;
			else
				role = UNKNOWN_ROLE;

			nbr_of_users++;
            
            // get acl and update
			//add_new_user_to_table(nbr_of_users, username, role);
		}
}

void
continue_add_user_dialog_cb (GUPnPDeviceProxy         *proxy,
		                     GUPnPDeviceProxyAddUser  *adduserdata,
                             GError                  **error,
                             gpointer                  user_data)
{
		if ((*error) != NULL) {
			GtkWidget *error_dialog;

			error_dialog = gtk_message_dialog_new (GTK_WINDOW (user_admininistration_dialog),
                                                   GTK_DIALOG_MODAL,
                                                   GTK_MESSAGE_ERROR,
                                                   GTK_BUTTONS_CLOSE,
                                                   "Adding new user failed.\n\nError %d: %s",
                                                   (*error)->code,
                                                   (*error)->message);
			gtk_dialog_run (GTK_DIALOG (error_dialog));
			gtk_widget_destroy (error_dialog);

			gtk_widget_hide (user_admininistration_dialog);
			g_error_free ((*error));

			gupnp_device_proxy_end_add_user (adduserdata);
			return;
		}

		if (gupnp_device_proxy_end_add_user (adduserdata)) {
			// User successfully added, change password
			GUPnPDeviceProxyChangePassword *deviceProxyChangePassword;
			const gchar *new_username = gtk_entry_get_text (GTK_ENTRY(add_user_dialog_username_entry));
			const gchar *new_password = gtk_entry_get_text (GTK_ENTRY(add_user_dialog_password_entry));

			GUPnPDeviceInfo *info = get_selected_device_info ();
			GUPnPDeviceProxy *deviceProxy = GUPNP_DEVICE_PROXY (info);
			g_assert (deviceProxy != NULL);

			deviceProxyChangePassword = gupnp_device_proxy_change_password (deviceProxy,
        		                                                            new_username,
                                                                            new_password,
                                                                            add_user_dialog_password_cb,
                                                                            user_data);
		}

}


void
add_user_dialog_ok_pressed (GladeXML *glade_xml)
{
	    GUPnPDeviceProxyAddUser *deviceProxyAddUser;
		gpointer user_data = NULL;
		GString *role_list = g_string_new("");

	    const gchar *new_username = gtk_entry_get_text (GTK_ENTRY(add_user_dialog_username_entry));
	    const gchar *new_password = gtk_entry_get_text (GTK_ENTRY(add_user_dialog_password_entry));

        // create role_list by appending rolenames
	    if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(add_user_dialog_admin_checkbutton)))
			g_string_append(role_list, "Admin ");
	    if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(add_user_dialog_basic_checkbutton)))
	    	g_string_append(role_list, "Basic ");
	    if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(add_user_dialog_public_checkbutton)))
	    	g_string_append(role_list, "Public ");

        // remove extra space from the end of rolelist
        g_string_set_size(role_list, role_list->len-1); 
   
        GUPnPDeviceInfo *info = get_selected_device_info ();
        GUPnPDeviceProxy *deviceProxy = GUPNP_DEVICE_PROXY (info);
		g_assert (deviceProxy != NULL);

	    deviceProxyAddUser = gupnp_device_proxy_add_user (deviceProxy,
	    		                                          new_username,
	    		                                          new_password,
	    		                                          role_list->str,
	    		                                          continue_add_user_dialog_cb,
	                                                      user_data);
                                                          
        g_string_free(role_list, TRUE);                                                          
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

