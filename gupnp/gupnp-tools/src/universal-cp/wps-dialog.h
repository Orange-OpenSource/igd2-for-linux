/*
 * wps-dialog.h
 *
 *  Created on: May 5, 2009
 *      Author: vlillvis
 */

#ifndef WPSDIALOG_H_
#define WPSDIALOG_H_

#include <libgupnp/gupnp-control-point.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

void
continue_wps_cb (GUPnPDeviceProxy    *proxy,
                 GString             *name,
                 GUPnPDeviceProxyWps *wps,
                 GError             **error,
                 gpointer             user_data);

void
begin_wps_dialog (void);

void
wps_dialog_push_button(GtkToggleButton *button,
					   gpointer   user_data);

void
init_wps_dialog_fields (void);

void
init_wps_dialog      (GladeXML *glade_xml);

void
deinit_wps_dialog    (void);

#endif /* WPSDIALOG_H_ */
