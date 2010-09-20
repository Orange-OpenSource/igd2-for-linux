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

#ifndef STATUSBAR_H_
#define STATUSBAR_H_

#include <glade/glade.h>
#include <gtk/gtkstatusbar.h>

void
statusbar_update (gboolean device_selected);

void
init_statusbar (GladeXML *glade_xml);

#endif /* STATUSBAR_H_ */
