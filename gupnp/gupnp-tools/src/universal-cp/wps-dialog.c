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
	    gpointer wps_user_data;

	    init_wps_dialog_fields();

	    info = get_selected_device_info ();
        deviceProxy = GUPNP_DEVICE_PROXY (info);
        g_assert (deviceProxy != NULL);

        deviceProxyWps = gupnp_device_proxy_begin_wps (deviceProxy,
            	                                       continue_wps_cb,
            		                                   wps_user_data);
}

void
continue_wps_cb (GUPnPDeviceProxy    *proxy,
                 GUPnPDeviceProxyWps *wps,
                 gpointer             user_data)
{

	gchar *device_name="";
	//gchar *device_pin="";

	init_wps_dialog_fields();
	// TODO: miten M1,M2,M4...Done vaiheet erotellaan?
    //gtk_progress_bar_pulse (GTK_PROGRESS_BAR(wps_dialog_progressbar));
    gtk_entry_set_text (GTK_ENTRY (wps_dialog_name_entry), device_name);

    gtk_dialog_run (GTK_DIALOG (wps_dialog));
    gtk_widget_hide (wps_dialog);

}

void
wps_invocation (void)
{
	const gchar *device_pin;
    // GUPnPDeviceProxyWps *deviceProxyWps;
    //gpointer wps_user_data;

    device_pin = gtk_entry_get_text (GTK_ENTRY(wps_dialog_pin_entry));
    /*
    gupnp_device_proxy_continue_wps (deviceProxyWps,
								     device_pin,
								     wps_user_data);
*/
    gtk_entry_set_text (GTK_ENTRY(wps_dialog_name_entry), device_pin);


    //gtk_dialog_run (GTK_DIALOG (wps_dialog));
	//gtk_widget_destroy (wps_dialog);
}

void
wps_dialog_push_button(GtkToggleButton *button,
					   gpointer   user_data)
{
    gchar *text="";
    gboolean togglebutton_active;

    togglebutton_active = gtk_toggle_button_get_active (button);
    if (togglebutton_active) {
        gtk_entry_set_text (GTK_ENTRY(wps_dialog_pin_entry), text);
	    gtk_entry_set_editable (GTK_ENTRY(wps_dialog_pin_entry), FALSE);
    } else {
        gtk_entry_set_text (GTK_ENTRY(wps_dialog_pin_entry), text);
	    gtk_entry_set_editable (GTK_ENTRY(wps_dialog_pin_entry), TRUE);
	}
}

void
init_wps_dialog_fields (void)
{
	gchar *device_name="";
	gchar *device_pin="";

    gtk_entry_set_text (GTK_ENTRY(wps_dialog_name_entry), device_name);
    gtk_entry_set_text (GTK_ENTRY(wps_dialog_pin_entry), device_pin);
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

