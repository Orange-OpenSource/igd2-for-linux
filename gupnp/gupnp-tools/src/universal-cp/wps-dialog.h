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

#ifndef WPSDIALOG_H_
#define WPSDIALOG_H_

#include <libgupnp/gupnp-control-point.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

void
on_state_variable_changed_setup_ready(	GUPnPServiceProxy *proxy,
										char *            str_value);

void
continue_wps_cb (GUPnPDeviceProxy    *proxy,
                 GUPnPDeviceProxyWps *wps,
                 GString             *device_name,
                 GError             **error,
                 gpointer             user_data);

void
begin_wps_dialog (void);

void
wps_pin_setup_begin();

void
wps_pbc_setup_begin();

void
wps_dialog_push_button(GtkToggleButton *button,
					   gpointer         user_data);

void
init_wps_dialog_fields (void);

void
init_wps_dialog      (GladeXML *glade_xml);

void
deinit_wps_dialog    (void);

#endif /* WPSDIALOG_H_ */
