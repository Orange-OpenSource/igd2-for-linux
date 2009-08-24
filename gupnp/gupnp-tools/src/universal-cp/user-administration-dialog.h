/*
 * user-administration-dialog.h
 *
 *  Created on: Jun 4, 2009
 *      Author: vlillvis
 */

#ifndef USERADMINISTRATIONDIALOG_H_
#define USERADMINISTRATIONDIALOG_H_

#include <libgupnp/gupnp-control-point.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

void
init_user_administration_dialog (GladeXML *glade_xml);

void
deinit_user_administration_dialog (void);

void
init_add_user_dialog (GladeXML *glade_xml);

void
deinit_add_user_dialog (void);

#endif /* USERADMINISTRATIONDIALOG_H_ */
