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

#include "gui.h"
#include "device-treeview.h"
#include "wps-dialog.h"
#include "statusbar.h"
#include "icons.h"
#include "main.h"
//#include "gupnp-device-proxy.h"

#define TEST_FILL
extern void hostapd_printf(const char *fmt, ...);	// TEST

static GtkWidget *wps_dialog;
static GtkWidget *wps_cp_name_label;
static GtkWidget *wps_cp_pin_label;
static GtkWidget *wps_dialog_name_entry;
static GtkWidget *wps_dialog_pin_entry;
static GtkWidget *wps_dialog_checkbutton;
static GtkWidget *wps_dialog_progressbar;
static GUPnPDeviceProxyWps *setup_time_wps;	// TODO: ugly way to store it there, but .... fix this more re-entrant manner

static GtkWidget *pin_info_dialog;
static GtkWidget *pbc_info_dialog;
static GtkWidget *m2d_info_dialog;

static gboolean togglebutton_active;
static gboolean pbc_in_progess;
static gboolean wps_authentication_in_progress;
static gboolean wps_allow_setup_ready;

void clear_in_progress_flags( void )
{
	pbc_in_progess                     = FALSE;
    wps_authentication_in_progress     = FALSE;
	wps_allow_setup_ready              = FALSE;
}

void
on_start_wps_setup_pin_activate ( GladeXML *glade_xml )
{
		pin_info_dialog = m2d_info_dialog  = NULL;
		wps_authentication_in_progress     = TRUE;
//      wps_allow_setup_ready              = TRUE; // don't allow SetupReady=TRUE to continiue hadshake M2....M8
		pbc_in_progess = FALSE;
        wps_pin_setup_begin();
}

void
on_start_wps_setup_pbc_activate ( GladeXML *glade_xml )
{
		pbc_info_dialog = m2d_info_dialog  = NULL;
		wps_authentication_in_progress     = TRUE;
        wps_allow_setup_ready              = TRUE;
		pbc_in_progess = TRUE;
        wps_pbc_setup_begin();
}

void
begin_wps_dialog ( void )
{
        GUPnPDeviceInfo *info;
        GUPnPDeviceProxy *deviceProxy;
//      GUPnPDeviceProxyWps *deviceProxyWps;
//      gpointer wps_user_data=NULL;

        if ( m2d_info_dialog ) {
		  gtk_widget_destroy ( m2d_info_dialog );
		  m2d_info_dialog = NULL;
		}
        init_wps_dialog_fields();

        info = get_selected_device_info ();

        if ( info )
        {
                deviceProxy = GUPNP_DEVICE_PROXY ( info );
                g_assert ( deviceProxy != NULL );
                gtk_entry_set_text ( GTK_ENTRY ( wps_dialog_name_entry ), gupnp_device_info_get_friendly_name(info) );

				hostapd_printf("%s: continue handshake: M2...M8", __func__ );

				gtk_dialog_run ( GTK_DIALOG ( wps_dialog ) );
				gtk_widget_show_all( wps_dialog );
//              gtk_widget_hide ( wps_dialog );
        }
        else
        {
                /* Device must be selected before starting WPS setup from connection menu */
                GtkWidget *info_dialog;

                info_dialog = gtk_message_dialog_new ( GTK_WINDOW ( wps_dialog ),
                                                       GTK_DIALOG_MODAL,
                                                       GTK_MESSAGE_INFO,
                                                       GTK_BUTTONS_CLOSE,
                                                       "No Device selected for WPS setup" );

                gtk_dialog_run ( GTK_DIALOG ( info_dialog ) );
                gtk_widget_destroy ( info_dialog );
				clear_in_progress_flags();
        }
}

void
continue_wps_m2d_cb ( GUPnPDeviceProxy        *proxy,
					  GUPnPDeviceProxyWps     *wps,
					  GString                 *device_name,
					  GError                 **error,
					  gpointer                 user_data )
{
        if ( pbc_info_dialog ) {
		  gtk_widget_destroy ( pbc_info_dialog );
		  pbc_info_dialog = NULL;
		}
        if ( pin_info_dialog ) {
		  gtk_widget_destroy ( pin_info_dialog );
		  pin_info_dialog = NULL;
		}

		if ( ( *error ) != NULL )
        {

                GtkWidget *error_dialog;

                error_dialog = gtk_message_dialog_new ( GTK_WINDOW ( wps_dialog ),
                                                        GTK_DIALOG_MODAL,
                                                        GTK_MESSAGE_ERROR,
                                                        GTK_BUTTONS_CLOSE,
                                                        "WPS setup failed.\n\nError %d: %s",
                                                        ( *error )->code,
                                                        ( *error )->message );

                gtk_dialog_run ( GTK_DIALOG ( error_dialog ) );
                gtk_widget_destroy ( error_dialog );

                gtk_widget_hide ( wps_dialog );
                g_error_free ( ( *error ) );
                gupnp_device_proxy_end_wps ( wps );
				clear_in_progress_flags();

                return;
        }

        g_assert ( wps_dialog_progressbar != NULL );
        g_assert ( wps_dialog_name_entry != NULL );
		setup_time_wps = wps;	// gupnp_device_proxy_continue_wps needs this ...

		gtk_progress_bar_set_fraction ( GTK_PROGRESS_BAR ( wps_dialog_progressbar ),1 );

		m2d_info_dialog = gtk_message_dialog_new ( GTK_WINDOW ( wps_dialog ),
												GTK_DIALOG_DESTROY_WITH_PARENT,
												GTK_MESSAGE_INFO,
												GTK_BUTTONS_OK,
												"WPS setup: phase 1:M2D successfully performed" );
		g_signal_connect_swapped( m2d_info_dialog,
								  "response",
								  G_CALLBACK( gtk_widget_destroy ),
								  m2d_info_dialog );
		gtk_widget_show_all( m2d_info_dialog );

//		gtk_dialog_run ( GTK_DIALOG ( m2d_info_dialog ) );
//		gtk_widget_destroy ( m2d_info_dialog );
//		gtk_widget_hide ( m2d_info_dialog );

//		if ( wps->method == GUPNP_DEVICE_WPS_METHOD_PIN )
		statusbar_update ( TRUE );

		if ( ! pbc_in_progess )	// if PIN method ...
		  begin_wps_dialog();
		if ( user_data == (gpointer)1 )
		  on_state_variable_changed_setup_ready( proxy,"TRUE");

}

void
continue_wps_cb_phase2 ( GUPnPDeviceProxy    *proxy,
						  GUPnPDeviceProxyWps *wps,
						  GString             *device_name,
						  GError             **error,
						  gpointer             user_data )
{
        if ( m2d_info_dialog ) {
		  gtk_widget_destroy ( m2d_info_dialog );
		  m2d_info_dialog = NULL;
		}

        wps_authentication_in_progress = FALSE;
        if ( ( *error ) != NULL )
        {

                GtkWidget *error_dialog;

                error_dialog = gtk_message_dialog_new ( GTK_WINDOW ( wps_dialog ),
                                                        GTK_DIALOG_MODAL,
                                                        GTK_MESSAGE_ERROR,
                                                        GTK_BUTTONS_CLOSE,
                                                        "WPS setup failed.\n\nError %d: %s",
                                                        ( *error )->code,
                                                        ( *error )->message );

                gtk_dialog_run ( GTK_DIALOG ( error_dialog ) );
                gtk_widget_destroy ( error_dialog );

                gtk_widget_hide ( wps_dialog );
                g_error_free ( ( *error ) );
                gupnp_device_proxy_end_wps ( wps );
				clear_in_progress_flags();

                return;
        }

        g_assert ( wps_dialog_progressbar != NULL );
        g_assert ( wps_dialog_name_entry != NULL );

        if ( gupnp_device_proxy_end_wps ( wps ) )
        {
                // WPS setup successfully formed
                gtk_progress_bar_set_fraction ( GTK_PROGRESS_BAR ( wps_dialog_progressbar ),1 );

                GtkWidget *info_dialog;

				clear_in_progress_flags();
                info_dialog = gtk_message_dialog_new ( GTK_WINDOW ( wps_dialog ),
                                                       GTK_DIALOG_MODAL,
                                                       GTK_MESSAGE_INFO,
                                                       GTK_BUTTONS_OK,
                                                       "WPS setup: phase 2: M2..M8 successfully performed" );

                gtk_dialog_run ( GTK_DIALOG ( info_dialog ) );
                gtk_widget_destroy ( info_dialog );
                gtk_widget_hide ( wps_dialog );

                statusbar_update ( TRUE );
        }
        else
        {
                g_assert ( device_name != NULL );
                // Display Device name for user
                gtk_entry_set_text ( GTK_ENTRY ( wps_dialog_name_entry ), device_name->str );
                gtk_progress_bar_set_fraction ( GTK_PROGRESS_BAR ( wps_dialog_progressbar ),0.3 );
        }
}

void
gupnp_device_proxy_continue_wps (GUPnPDeviceProxyWps        *wps,
                                 GString                    *pin,
								 GUPnPDeviceProxyWpsCallback callback,
                                 gpointer                    user_data);

void
on_state_variable_changed_setup_ready(	GUPnPServiceProxy *proxy,
										char *            str_value)
{
  if ( wps_authentication_in_progress )
  {
	hostapd_printf("%s: SetupReady=%s: pbc_in_progess=%s", __func__, str_value, pbc_in_progess ? "TRUE " : "FALSE");
	if ( wps_allow_setup_ready )	// if already in this phase, don't do it twice
	{
	  if ( strcmp("TRUE", str_value) == 0 )
	  {
		wps_allow_setup_ready = FALSE;	// prevent another start, if not started through UI-menu
		hostapd_printf("%s: continue handshake: M2...M8", __func__ );
		gupnp_device_proxy_continue_wps ( setup_time_wps,
										  NULL,
										  continue_wps_cb_phase2,
										  NULL );
	  }
	  else
	  {
		// we ignore FALSE -value
	  }
	}
	else
	{
	  // SetupReady ignore there if this is not a PBC -setup
	}
  }
}

#define	MAX_PIN_LENGTH	10

void
wps_pin_invocation( GUPnPDeviceProxyWps *	deviceProxyWps,
					char *					pin_code )
{
        const gchar *device_pin;
		GString		*dev_pin;
        GUPnPDeviceInfo *info;
        GUPnPDeviceProxy *deviceProxy;

        device_pin = gtk_entry_get_text ( GTK_ENTRY ( wps_dialog_pin_entry ) );

        info = get_selected_device_info ();
        deviceProxy = GUPNP_DEVICE_PROXY ( info );
        g_assert ( deviceProxy != NULL );

		if ( strcmp ( device_pin, "" ) == 0 )
		{
				/* Device PIN must be added with this WPS setup method */
				GtkWidget *info_dialog;

				info_dialog = gtk_message_dialog_new ( GTK_WINDOW ( wps_dialog ),
														GTK_DIALOG_MODAL,
														GTK_MESSAGE_INFO,
														GTK_BUTTONS_CLOSE,
														"Device PIN is missing" );

				gtk_dialog_run ( GTK_DIALOG ( info_dialog ) );
				gtk_widget_destroy ( info_dialog );
				clear_in_progress_flags();
				return;	// TEST
		}
		dev_pin = g_string_new( device_pin );	// pick up PIN feed in by User
		
        gtk_widget_hide ( wps_dialog );	// hide the dialog asking PIN
        gtk_widget_destroy ( wps_dialog );

		gupnp_device_proxy_continue_wps ( setup_time_wps,
										  dev_pin,
										  continue_wps_cb_phase2,
										  NULL );
}

void
wps_pin_setup_begin ( void )
{
        const gchar *device_pin;
        gpointer wps_user_data=NULL;
        GUPnPDeviceInfo *info;
        GUPnPDeviceProxy *deviceProxy;
        GUPnPDeviceProxyWps *deviceProxyWps;
        guint method;

        device_pin = gtk_entry_get_text ( GTK_ENTRY ( wps_dialog_pin_entry ) );

        info = get_selected_device_info ();
        if ( info )
        {
			  deviceProxy = GUPNP_DEVICE_PROXY ( info );
			  g_assert ( deviceProxy != NULL );

			  method = GUPNP_DEVICE_WPS_METHOD_PIN;

			  /* Device PIN must be added with this WPS setup method */
	  //		GtkWidget *pin_info_dialog;


			  pin_info_dialog = gtk_message_dialog_new ( GTK_WINDOW ( wps_dialog ),
													  GTK_DIALOG_DESTROY_WITH_PARENT,
													  GTK_MESSAGE_INFO,
//													  GTK_BUTTONS_OK,
													  GTK_BUTTONS_NONE,
													  "Request for PIN generation sent.\n"
													  "Waiting for device .." );
			  g_signal_connect_swapped( pin_info_dialog,
										"response",
										G_CALLBACK( gtk_widget_destroy ),
										pin_info_dialog );
			  gtk_widget_show_all( pin_info_dialog );

			  setup_time_wps =
			  deviceProxyWps = gupnp_device_proxy_begin_wps (
							  deviceProxy,
							  method,
							  "",
							  "",
							  continue_wps_m2d_cb,
							  wps_user_data );
//			  gtk_widget_destroy ( pin_info_dialog );
		}
        else
        {
                /* Device must be selected before starting WPS setup from connection menu */
                GtkWidget *info_dialog;

                info_dialog = gtk_message_dialog_new ( GTK_WINDOW ( wps_dialog ),
                                                       GTK_DIALOG_MODAL,
                                                       GTK_MESSAGE_INFO,
                                                       GTK_BUTTONS_CLOSE,
                                                       "No Device selected for WPS setup" );

				clear_in_progress_flags();
                gtk_dialog_run ( GTK_DIALOG ( info_dialog ) );
                gtk_widget_destroy ( info_dialog );
        }
}

void
wps_pbc_setup_begin ( void )
{
        const gchar *device_pin;
        gpointer wps_user_data=NULL;
        GUPnPDeviceInfo *info;
        GUPnPDeviceProxy *deviceProxy;
        GUPnPDeviceProxyWps *deviceProxyWps;
        guint method;

        device_pin = gtk_entry_get_text ( GTK_ENTRY ( wps_dialog_pin_entry ) );

        info = get_selected_device_info ();
		if ( info )
		{
			deviceProxy = GUPNP_DEVICE_PROXY ( info );
			g_assert ( deviceProxy != NULL );

			method = GUPNP_DEVICE_WPS_METHOD_PUSHBUTTON;

			/* Device PIN must be added with this WPS setup method */
	//		GtkWidget *pbc_info_dialog;

			pbc_info_dialog = gtk_message_dialog_new ( GTK_WINDOW ( wps_dialog ),
														GTK_DIALOG_DESTROY_WITH_PARENT,
														GTK_MESSAGE_INFO,
//														GTK_BUTTONS_OK,
														GTK_BUTTONS_NONE,
														"Request for Push-Button Configuration sent.\n"
														"Waiting for device .." );
			g_signal_connect_swapped( pbc_info_dialog,
									  "response",
									  G_CALLBACK( gtk_widget_destroy ),
									  pbc_info_dialog );
			gtk_widget_show_all( pbc_info_dialog );
			setup_time_wps =
			deviceProxyWps = gupnp_device_proxy_begin_wps ( deviceProxy,
															method,
															"",
															device_pin,
															continue_wps_m2d_cb,
															wps_user_data );
//			  gtk_widget_destroy ( pin_info_dialog );
		}
        else
        {
			/* Device must be selected before starting WPS setup from connection menu */
			GtkWidget *info_dialog;

			info_dialog = gtk_message_dialog_new ( GTK_WINDOW ( wps_dialog ),
													GTK_DIALOG_MODAL,
													GTK_MESSAGE_INFO,
													GTK_BUTTONS_CLOSE,
													"No Device selected for WPS setup" );

			clear_in_progress_flags();
			gtk_dialog_run ( GTK_DIALOG ( info_dialog ) );
			gtk_widget_destroy ( info_dialog );
        }
}

void
wps_dialog_push_button ( GtkToggleButton *button,
                         gpointer   user_data )
{
        togglebutton_active = gtk_toggle_button_get_active ( button );
        if ( togglebutton_active )
        {
                gtk_entry_set_text ( GTK_ENTRY ( wps_dialog_pin_entry ), "" );
                gtk_entry_set_editable ( GTK_ENTRY ( wps_dialog_pin_entry ), FALSE );
        }
        else
        {
                gtk_entry_set_text ( GTK_ENTRY ( wps_dialog_pin_entry ), "" );
                gtk_entry_set_editable ( GTK_ENTRY ( wps_dialog_pin_entry ), TRUE );
        }
}

void
init_wps_dialog_fields ( void )
{
        gtk_entry_set_text ( GTK_ENTRY ( wps_dialog_name_entry ), "" );
        gtk_entry_set_text ( GTK_ENTRY ( wps_dialog_pin_entry ), "" );
        gtk_progress_bar_set_fraction ( GTK_PROGRESS_BAR ( wps_dialog_progressbar ),0 );
}

void
init_wps_dialog ( GladeXML *glade_xml )
{
        /* Dialog box */
        wps_dialog = glade_xml_get_widget ( glade_xml, "wps-dialog" );
        g_assert ( wps_dialog != NULL );

        /* Entry */
        wps_dialog_name_entry = glade_xml_get_widget ( glade_xml,
                                "wps-dialog-name-entry" );
        g_assert ( wps_dialog_name_entry != NULL );

        wps_dialog_pin_entry = glade_xml_get_widget ( glade_xml,
                               "wps-dialog-pin-entry" );
        g_assert ( wps_dialog_pin_entry != NULL );
        /* All the labels */
        wps_cp_name_label = glade_xml_get_widget ( glade_xml,
                            "wps-dialog-name-label" );
        g_assert ( wps_cp_name_label != NULL );
        wps_cp_pin_label = glade_xml_get_widget ( glade_xml,
                           "wps-dialog-pin-label" );
        g_assert ( wps_cp_pin_label != NULL );

        /* Check button */
        wps_dialog_checkbutton = glade_xml_get_widget ( glade_xml,
                                 "wps-dialog-checkbutton" );
        g_assert ( wps_dialog_checkbutton != NULL );

        /* Progressbar */
        wps_dialog_progressbar = glade_xml_get_widget ( glade_xml,
                                 "wps-dialog-progressbar" );
        g_assert ( wps_dialog_progressbar != NULL );

}

void
deinit_wps_dialog ( void )
{
        gtk_widget_destroy ( wps_dialog );
}

