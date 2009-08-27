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
static GtkListStore *user_list_store;
static GtkWidget *user_list_tree_view;

/* Add user dialog */
static GtkWidget *add_user_dialog;
static GtkWidget *add_user_dialog_username_entry;
static GtkWidget *add_user_dialog_password_entry;
static GtkWidget *add_user_dialog_public_checkbutton;
static GtkWidget *add_user_dialog_basic_checkbutton;
static GtkWidget *add_user_dialog_admin_checkbutton;


static void init_add_user_dialog_fields (void);
static void init_user_administration_dialog_fields (void);


// user administration dialog treeview columns
enum
{
    COL_USER_NAME = 0,
    COL_ADMIN_TOGGLE,
    COL_BASIC_TOGGLE,
    COL_PUBLIC_TOGGLE,
    NUM_COLS
};

/*
 * User administration dialog functions
 */

static void clear_user_table()
{
        gtk_list_store_clear(user_list_store);
}

static void add_user_to_table(gpointer key,
                       gpointer value,
                       gpointer user_data)
{
        gchar *username = key;
        gboolean admin = FALSE;
        gboolean basic = FALSE;
        gboolean public = FALSE;
        GtkTreeIter   iter;
        
        if (value)
        {
            if (strstr((char*)value, "Admin"))
                admin = TRUE;
            if (strstr((char*)value, "Basic"))
                basic = TRUE;
            if (strstr((char*)value, "Public"))
                public = TRUE;    
        }         
        
        gtk_list_store_append(user_list_store, &iter);
        gtk_list_store_set (user_list_store, &iter,
                      COL_USER_NAME, username,
                      COL_ADMIN_TOGGLE, admin,
                      COL_BASIC_TOGGLE, basic,
                      COL_PUBLIC_TOGGLE, public,
                      -1);                   
        
        // sets data to treeview
        gtk_tree_view_set_model(GTK_TREE_VIEW(user_list_tree_view), GTK_TREE_MODEL(user_list_store));
}

static void 
get_ACL_cb(GUPnPDeviceProxy    *proxy,
           GUPnPDeviceProxyGetACLData *ACLData,
           GError             **error,
           gpointer             user_data)
{        
        // user_data should contain ghashtable
        GHashTable *users = user_data;        
        g_hash_table_foreach(users, add_user_to_table, proxy);
        g_hash_table_destroy(users);
}

static void 
update_users_table()
{
        GUPnPDeviceInfo *info = get_selected_device_info ();
        GUPnPDeviceProxy *deviceProxy = GUPNP_DEVICE_PROXY (info);
        g_assert (deviceProxy != NULL);
        
        clear_user_table();
        
        GHashTable *users = g_hash_table_new (g_str_hash,
                                           g_str_equal);
        
        gupnp_device_proxy_get_ACL_data(deviceProxy, get_ACL_cb, users);    
}

 
void
start_user_administration (GladeXML *glade_xml)
{
        GUPnPDeviceInfo *info;

        info = get_selected_device_info ();
        if (get_selected_device_info ()) {    
    	    init_user_administration_dialog_fields();     
            
            update_users_table();
    
            gtk_dialog_run (GTK_DIALOG (user_admininistration_dialog));
            gtk_widget_hide (user_admininistration_dialog);
         } else {
            /* Device must be selected before starting User administration */
            GtkWidget *info_dialog;

            info_dialog = gtk_message_dialog_new (GTK_WINDOW (user_admininistration_dialog),
                                                  GTK_DIALOG_MODAL,
                                                  GTK_MESSAGE_INFO,
                                                  GTK_BUTTONS_CLOSE,
                                                  "No Device selected for User Administration");
            gtk_dialog_run (GTK_DIALOG (info_dialog));
            gtk_widget_destroy (info_dialog);
        }        
    
}


static void
init_user_administration_dialog_fields (void)
{
        clear_user_table();
}


void set_toggle_value (gchar *path_string, gint column)
{  
    GtkTreeIter   iter;
    gtk_tree_model_get_iter_from_string (GTK_TREE_MODEL(user_list_store),
                                         &iter,
                                         path_string);
    gboolean old_value;
     
    // get old value
    gtk_tree_model_get (GTK_TREE_MODEL(user_list_store), &iter, column, &old_value, -1);
    
    // create new value
    GValue new_value = {0};
    g_value_init (&new_value, G_TYPE_BOOLEAN);
    g_value_set_boolean(&new_value, !old_value);
    
    // set new value                                    
    gtk_list_store_set_value (user_list_store,
                              &iter,
                              column,
                              &new_value);
}

void admin_toggled_callback (GtkCellRendererToggle *cell,
                             gchar                 *path_string,
                             gpointer               user_data)
{
        set_toggle_value(path_string, COL_ADMIN_TOGGLE);
}
void basic_toggled_callback (GtkCellRendererToggle *cell,
                             gchar                 *path_string,
                             gpointer               user_data)
{
        set_toggle_value(path_string, COL_BASIC_TOGGLE);
}
void public_toggled_callback (GtkCellRendererToggle *cell,
                             gchar                 *path_string,
                             gpointer               user_data)
{
        set_toggle_value(path_string, COL_PUBLIC_TOGGLE);
}

void
init_user_administration_dialog (GladeXML *glade_xml)
{
        /* Dialog box */
	    user_admininistration_dialog = glade_xml_get_widget (glade_xml, "user-administration-dialog");
        g_assert (user_admininistration_dialog != NULL);

        /* Treeview for showing users */
        user_list_tree_view = glade_xml_get_widget (glade_xml, "users-treeview");
        g_assert (user_list_tree_view != NULL);
        
        // only one row can be selected from treeview. 
        gtk_tree_selection_set_mode(gtk_tree_view_get_selection(GTK_TREE_VIEW(user_list_tree_view)),
                                    GTK_SELECTION_SINGLE);

        /* ListStore for actually containing users */
        user_list_store = gtk_list_store_new (NUM_COLS, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_BOOLEAN, G_TYPE_BOOLEAN);
        g_assert (user_list_store != NULL);

        /* Columns in treeview and renderers for showing cell contents */
        GtkTreeViewColumn   *col;
        GtkCellRenderer     *renderer;
        
        /* Column #1: "The User Name" */
        col = gtk_tree_view_column_new();
        gtk_tree_view_column_set_title(col, "User Name");
        gtk_tree_view_append_column(GTK_TREE_VIEW(user_list_tree_view), col);

        renderer = gtk_cell_renderer_text_new();
        gtk_tree_view_column_set_sizing(col, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
        gtk_tree_view_column_pack_start(col, renderer, TRUE);
        gtk_tree_view_column_add_attribute(col, renderer, "text", COL_USER_NAME);
        

        /* Column #2: "The Admin" */
        col = gtk_tree_view_column_new();
        gtk_tree_view_column_set_sizing(col, GTK_TREE_VIEW_COLUMN_FIXED);
        gtk_tree_view_column_set_fixed_width(col, 50);
        gtk_tree_view_column_set_title(col, "Admin");
        gtk_tree_view_append_column(GTK_TREE_VIEW(user_list_tree_view), col);

        renderer = gtk_cell_renderer_toggle_new();
        g_signal_connect(renderer, "toggled", (GCallback) admin_toggled_callback, NULL);
        g_object_set(renderer, "activatable", TRUE, NULL);
        gtk_tree_view_column_pack_start(col, renderer, FALSE);
        gtk_tree_view_column_add_attribute(col, renderer, "active", COL_ADMIN_TOGGLE);
        
        /* Column #3: "The Basic" */
        col = gtk_tree_view_column_new();
        gtk_tree_view_column_set_sizing(col, GTK_TREE_VIEW_COLUMN_FIXED);
        gtk_tree_view_column_set_fixed_width(col, 50);
        gtk_tree_view_column_set_title(col, "Basic");
        gtk_tree_view_append_column(GTK_TREE_VIEW(user_list_tree_view), col);
        
        renderer = gtk_cell_renderer_toggle_new();
        g_signal_connect(renderer, "toggled", (GCallback) basic_toggled_callback, NULL);
        g_object_set(renderer, "activatable", TRUE, NULL);
        gtk_tree_view_column_pack_start(col, renderer, FALSE);
        gtk_tree_view_column_add_attribute(col, renderer, "active", COL_BASIC_TOGGLE);
        
        /* Column #3: "The Public" */
        col = gtk_tree_view_column_new();
        gtk_tree_view_column_set_sizing(col, GTK_TREE_VIEW_COLUMN_FIXED);
        gtk_tree_view_column_set_fixed_width(col, 50);
        gtk_tree_view_column_set_title(col, "Public");
        gtk_tree_view_append_column(GTK_TREE_VIEW(user_list_tree_view), col);

        renderer = gtk_cell_renderer_toggle_new();
        g_signal_connect(renderer, "toggled", (GCallback) public_toggled_callback, NULL);
        g_object_set(renderer, "activatable", TRUE, NULL);
        gtk_tree_view_column_pack_start(col, renderer, FALSE);
        gtk_tree_view_column_add_attribute(col, renderer, "active", COL_PUBLIC_TOGGLE);
}

void
deinit_user_administration_dialog (void)
{
        g_object_unref(user_list_store);
        gtk_widget_destroy (user_admininistration_dialog);
}

static void
continue_remove_user_dialog_cb (GUPnPDeviceProxy            *proxy,
		                        GUPnPDeviceProxyRemoveUser  *removeuserdata,
                                GError                     **error,
                                gpointer                     user_data)
{
        // change cursor back
        gdk_window_set_cursor (GTK_WIDGET(user_admininistration_dialog)->window, NULL);

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

			g_error_free ((*error));

			gupnp_device_proxy_end_remove_user (removeuserdata);
		}
		else if (gupnp_device_proxy_end_remove_user (removeuserdata)) {
			// User successfully removed
			GtkWidget *info_dialog;

			info_dialog = gtk_message_dialog_new (GTK_WINDOW (user_admininistration_dialog),
                                                  GTK_DIALOG_MODAL,
                                                  GTK_MESSAGE_INFO,
                                                  GTK_BUTTONS_CLOSE,
                                                  "User successfully removed");

			gtk_dialog_run (GTK_DIALOG (info_dialog));
			gtk_widget_destroy (info_dialog);
		}
        update_users_table();
}

void
ua_dialog_remove_user (GladeXML *glade_xml)
{
        GtkTreeSelection *selection;
        GtkTreeIter iter;
        GtkTreeModel *model;
        char *username = NULL;

        GUPnPDeviceProxyRemoveUser *deviceProxyRemoveUser;
        gpointer user_data = NULL;

        GUPnPDeviceInfo *info = get_selected_device_info ();
        GUPnPDeviceProxy *deviceProxy = GUPNP_DEVICE_PROXY (info);
        g_assert (deviceProxy != NULL);

        // change cursor
        gdk_window_set_cursor (GTK_WIDGET(user_admininistration_dialog)->window, gdk_cursor_new(GDK_WATCH));
            
        // get selected row and value of username column in treeview
        selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(user_list_tree_view));
        if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
            gtk_tree_model_get(model, &iter, COL_USER_NAME, &username,  -1);
        }
    
        if (username)
        {
            deviceProxyRemoveUser = gupnp_device_proxy_remove_user (deviceProxy,
                                                                    username,
                                                                    continue_remove_user_dialog_cb,
                                                                    user_data);
        }
        else
        {
            // change cursor back
            gdk_window_set_cursor (GTK_WIDGET(user_admininistration_dialog)->window, NULL);            
            
            GtkWidget *error_dialog;

            error_dialog = gtk_message_dialog_new (GTK_WINDOW (user_admininistration_dialog),
                                                   GTK_DIALOG_MODAL,
                                                   GTK_MESSAGE_ERROR,
                                                   GTK_BUTTONS_CLOSE,
                                                   "User must be selected.");
            gtk_dialog_run (GTK_DIALOG (error_dialog));
            gtk_widget_destroy (error_dialog);
            
            return;          
        }
            
        g_free(username);
}


static void
add_roles_cb( GUPnPDeviceProxy    *proxy,
                 GUPnPDeviceProxySetRoles *rolesdata,
                 GError             **error,
                 gpointer             user_data)
{
        // change cursor back
        gdk_window_set_cursor (GTK_WIDGET(user_admininistration_dialog)->window, NULL);    
    
        if ((*error) != NULL) {
            GtkWidget *error_dialog;

            error_dialog = gtk_message_dialog_new (GTK_WINDOW (user_admininistration_dialog),
                                                   GTK_DIALOG_MODAL,
                                                   GTK_MESSAGE_ERROR,
                                                   GTK_BUTTONS_CLOSE,
                                                   "Adding user roles failed.\n\nError %d: %s",
                                                   (*error)->code,
                                                   (*error)->message);
            gtk_dialog_run (GTK_DIALOG (error_dialog));
            gtk_widget_destroy (error_dialog);

            g_error_free ((*error));

            gupnp_device_proxy_end_add_roles (rolesdata);
        }
        else if (gupnp_device_proxy_end_add_roles (rolesdata)) {
            // Success
            GtkWidget *info_dialog;

            info_dialog = gtk_message_dialog_new (GTK_WINDOW (user_admininistration_dialog),
                                                  GTK_DIALOG_MODAL,
                                                  GTK_MESSAGE_INFO,
                                                  GTK_BUTTONS_CLOSE,
                                                  "Roles successfully changed");

            gtk_dialog_run (GTK_DIALOG (info_dialog));
            gtk_widget_destroy (info_dialog);
        }
        update_users_table();        
}


static void
remove_roles_cb( GUPnPDeviceProxy    *proxy,
                 GUPnPDeviceProxySetRoles *rolesdata,
                 GError             **error,
                 gpointer             user_data)
{
        // we are not so interested of what happens during removing roles, because in current
        // implementation add_roles is called right after removing. Adding should tell if setting
        // roles succeeds or not.
        
        if ((*error) != NULL) {
            GtkWidget *error_dialog;

            error_dialog = gtk_message_dialog_new (GTK_WINDOW (user_admininistration_dialog),
                                                   GTK_DIALOG_MODAL,
                                                   GTK_MESSAGE_ERROR,
                                                   GTK_BUTTONS_CLOSE,
                                                   "Removeing user roles failed.\n\nError %d: %s",
                                                   (*error)->code,
                                                   (*error)->message);
            gtk_dialog_run (GTK_DIALOG (error_dialog));
            gtk_widget_destroy (error_dialog);
            g_error_free ((*error));
        } 
        gupnp_device_proxy_end_remove_roles (rolesdata);    
}


void
ua_dialog_set_roles (GladeXML *glade_xml)
{
        // 1: Send removeRoles to device about roles which aren't selected for selected user
        // 2: Send addRoles to device about roles which are selected for selected user
        
        GUPnPDeviceProxySetRoles *deviceProxySetRoles;
        gpointer user_data = NULL;
        const gchar *username = NULL;
        GString *remove_role_list = g_string_new("");  // this contains roles which are NOT selected
        GString *add_role_list = g_string_new(""); // this contains roles which ARE selected
 
        // change cursor
        gdk_window_set_cursor (GTK_WIDGET(user_admininistration_dialog)->window, gdk_cursor_new(GDK_WATCH)); 
        
        GtkTreeSelection *selection;
        GtkTreeIter iter;
        GtkTreeModel *model;
        gboolean admin;
        gboolean basic;
        gboolean public;
        // Get the selected row from treeview and the values of role checkboxes on that row
        selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(user_list_tree_view));
        if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
            gtk_tree_model_get(model, &iter,
                               COL_USER_NAME, &username,
                               COL_ADMIN_TOGGLE, &admin,
                               COL_BASIC_TOGGLE, &basic,
                               COL_PUBLIC_TOGGLE, &public,
                               -1);
        }        
        
        // user must be selected
        if (username == NULL)
        {
            // change cursor back
            gdk_window_set_cursor (GTK_WIDGET(user_admininistration_dialog)->window, NULL);            
            
            GtkWidget *error_dialog;

            error_dialog = gtk_message_dialog_new (GTK_WINDOW (user_admininistration_dialog),
                                                   GTK_DIALOG_MODAL,
                                                   GTK_MESSAGE_ERROR,
                                                   GTK_BUTTONS_CLOSE,
                                                   "User must be selected.");
            gtk_dialog_run (GTK_DIALOG (error_dialog));
            gtk_widget_destroy (error_dialog);
            
            return;          
        }
        
        if (admin) g_string_append(add_role_list, "Admin ");
        else       g_string_append(remove_role_list, "Admin ");
        if (basic) g_string_append(add_role_list, "Basic ");
        else       g_string_append(remove_role_list, "Basic ");
        if (public) g_string_append(add_role_list, "Public ");
        else       g_string_append(remove_role_list, "Public ");        

        // remove extra space from the end of rolelist
        g_string_set_size(add_role_list, add_role_list->len-1);
        g_string_set_size(remove_role_list, remove_role_list->len-1);  
  
        GUPnPDeviceInfo *info = get_selected_device_info ();
        GUPnPDeviceProxy *deviceProxy = GUPNP_DEVICE_PROXY (info);
        g_assert (deviceProxy != NULL);

        deviceProxySetRoles = gupnp_device_proxy_remove_roles (deviceProxy,
                                                          username,
                                                          remove_role_list->str,
                                                          remove_roles_cb,
                                                          user_data);
                                                          
        deviceProxySetRoles = gupnp_device_proxy_add_roles (deviceProxy,
                                                          username,
                                                          add_role_list->str,
                                                          add_roles_cb,
                                                          user_data);        

        g_string_free(add_role_list, TRUE);
        g_string_free(remove_role_list, TRUE);
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
        
        update_users_table();
}

static void
add_user_dialog_password_cb (GUPnPDeviceProxy                *proxy,
                             GUPnPDeviceProxyChangePassword  *passworddata,
                             GError                         **error,
                             gpointer                         user_data)
{

		const gchar *username = gtk_entry_get_text (GTK_ENTRY(add_user_dialog_username_entry));
		GString *loginname = g_string_new(username);

        // change cursor back
        gdk_window_set_cursor (GTK_WIDGET(user_admininistration_dialog)->window, NULL);

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

			g_error_free ((*error));

			gupnp_device_proxy_end_change_password (passworddata, loginname);
			return;
		}

		if (gupnp_device_proxy_end_change_password (passworddata, loginname)) {
			// Password successfully changed
			GtkWidget *info_dialog;

			info_dialog = gtk_message_dialog_new (GTK_WINDOW (user_admininistration_dialog),
                                                  GTK_DIALOG_MODAL,
                                                  GTK_MESSAGE_INFO,
                                                  GTK_BUTTONS_CLOSE,
                                                  "New user successfully added");
                                                  
            gtk_dialog_run (GTK_DIALOG (info_dialog));
            gtk_widget_destroy (info_dialog);
		}
}

static void
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

			g_error_free ((*error));

			gupnp_device_proxy_end_add_user (adduserdata);
			return;
		}

		if (gupnp_device_proxy_end_add_user (adduserdata)) {
            // don't do anything. Password is set back there where adding new user is started
		}
}


void
add_user_dialog_ok_pressed (GladeXML *glade_xml)
{
	    GUPnPDeviceProxyAddUser *deviceProxyAddUser;
        GUPnPDeviceProxyChangePassword *deviceProxyChangePassword;
		gpointer user_data = NULL;
		GString *role_list = g_string_new("");

        // change cursor
        gdk_window_set_cursor (GTK_WIDGET(user_admininistration_dialog)->window, gdk_cursor_new(GDK_WATCH));

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
        

        deviceProxyChangePassword = gupnp_device_proxy_change_password (deviceProxy,
                                                                        new_username,
                                                                        new_password,
                                                                        add_user_dialog_password_cb,
                                                                        user_data);
                                                          
        g_string_free(role_list, TRUE);
       
}

static void
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

