/*
 * wps-dialog.c
 *
 *  Created on: May 5, 2009
 *      Author: vlillvis
 */

#include <string.h>
#include <stdlib.h>
#include <config.h>

#include "gui.h"
#include "device-treeview.h"
#include "wps-dialog.h"
#include "icons.h"
#include "main.h"

static GtkWidget *wps_dialog;
static GtkWidget *wps_cp_name_label;
static GtkWidget *wps_cp_pin_label;
static GtkWidget *wps_dialog_name_entry;
static GtkWidget *wps_dialog_pin_entry;
static GtkWidget *wps_dialog_checkbutton;
static GtkWidget *wps_dialog_progressbar;

static GUPnPDeviceProxyWps *deviceProxyWps;

void
on_start_wps_setup_activate (GladeXML *glade_xml)
{
	begin_wps_dialog();
}

void
begin_wps_dialog (void)
{
	    GUPnPDeviceInfo *info;
	    GUPnPDeviceProxy *deviceProxy;
	    GUPnPDeviceProxyWps *deviceProxyWps;
	    gpointer wps_user_data=NULL;

	    init_wps_dialog_fields();

	    info = get_selected_device_info ();
        deviceProxy = GUPNP_DEVICE_PROXY (info);
        g_assert (deviceProxy != NULL);

        GString *cp_name = g_string_new("Universal Control Point");

        deviceProxyWps = gupnp_device_proxy_begin_wps (deviceProxy,
                                                       cp_name,
            	                                       continue_wps_cb,
            		                                   wps_user_data);
        gtk_dialog_run (GTK_DIALOG (wps_dialog));
        gtk_widget_hide (wps_dialog);
}

void
continue_wps_cb (GUPnPDeviceProxy    *proxy,
		         GString             *name,
                 GUPnPDeviceProxyWps *wps,
                 GError             **error,
                 gpointer             user_data)
{

    if ((*error) != NULL) {

    	GtkWidget *error_dialog;

        error_dialog = gtk_message_dialog_new (GTK_WINDOW (wps_dialog),
                                               GTK_DIALOG_MODAL,
                                               GTK_MESSAGE_ERROR,
                                               GTK_BUTTONS_CLOSE,
                                               "WPS setup failed.\n\nError %d: %s",
                                               (*error)->code,
                                               (*error)->message);

        gtk_dialog_run (GTK_DIALOG (error_dialog));
        gtk_widget_destroy (error_dialog);

        gtk_widget_hide (wps_dialog);
        g_error_free ((*error));

	} else {
		g_assert (wps_dialog_progressbar != NULL);
		g_assert (wps_dialog_name_entry != NULL);
		g_assert (name != NULL);
	    gtk_progress_bar_pulse (GTK_PROGRESS_BAR(wps_dialog_progressbar));
	    gtk_entry_set_text (GTK_ENTRY (wps_dialog_name_entry), name->str);
	    deviceProxyWps = wps;

    	GtkWidget *info_dialog;

        info_dialog = gtk_message_dialog_new (GTK_WINDOW (wps_dialog),
                                               GTK_DIALOG_MODAL,
                                               GTK_MESSAGE_INFO,
                                               GTK_BUTTONS_CLOSE,
                                               "Successful WPS setup phase...");

        gtk_dialog_run (GTK_DIALOG (info_dialog));
        gtk_widget_destroy (info_dialog);
        //gtk_widget_hide (wps_dialog);

	}
}

void
wps_invocation (void)
{
	const gchar *device_pin;
    gpointer wps_user_data=NULL;

    device_pin = gtk_entry_get_text (GTK_ENTRY(wps_dialog_pin_entry));
    GString *pin_to_device = g_string_new(device_pin);

    gupnp_device_proxy_continue_wps (deviceProxyWps,
    		                         pin_to_device,
								     wps_user_data);
}

void
wps_dialog_push_button(GtkToggleButton *button,
					   gpointer   user_data)
{
    gboolean togglebutton_active;

    togglebutton_active = gtk_toggle_button_get_active (button);
    if (togglebutton_active) {
        gtk_entry_set_text (GTK_ENTRY(wps_dialog_pin_entry), "");
	    gtk_entry_set_editable (GTK_ENTRY(wps_dialog_pin_entry), FALSE);
    } else {
        gtk_entry_set_text (GTK_ENTRY(wps_dialog_pin_entry), "");
	    gtk_entry_set_editable (GTK_ENTRY(wps_dialog_pin_entry), TRUE);
	}
}

void
init_wps_dialog_fields (void)
{
    gtk_entry_set_text (GTK_ENTRY(wps_dialog_name_entry), "");
    gtk_entry_set_text (GTK_ENTRY(wps_dialog_pin_entry), "");
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(wps_dialog_progressbar),0);
}

void
init_wps_dialog (GladeXML *glade_xml)
{
        /* Dialog box */
        wps_dialog = glade_xml_get_widget (glade_xml, "wps-dialog");
        g_assert (wps_dialog != NULL);

		/* Entry */
        wps_dialog_name_entry = glade_xml_get_widget (glade_xml,
                                              "wps-dialog-name-entry");
        g_assert (wps_dialog_name_entry != NULL);

        wps_dialog_pin_entry = glade_xml_get_widget (glade_xml,
                                              "wps-dialog-pin-entry");
        g_assert (wps_dialog_pin_entry != NULL);

        /* All the labels */
        wps_cp_name_label = glade_xml_get_widget (glade_xml,
                                              "wps-dialog-name-label");
        g_assert (wps_cp_name_label != NULL);
        wps_cp_pin_label = glade_xml_get_widget (glade_xml,
                                              "wps-dialog-pin-label");
        g_assert (wps_cp_pin_label != NULL);

        /* Check button */
        wps_dialog_checkbutton = glade_xml_get_widget (glade_xml,
                                              "wps-dialog-checkbutton");
        g_assert (wps_dialog_checkbutton != NULL);

        /* Progressbar */
        wps_dialog_progressbar = glade_xml_get_widget (glade_xml,
                                              "wps-dialog-progressbar");
        g_assert (wps_dialog_progressbar != NULL);

}

void
deinit_wps_dialog (void)
{
        gtk_widget_destroy (wps_dialog);
}

