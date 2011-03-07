/**
 * This file is part of Nokia DeviceProtection v1 reference implementation
 * Copyright © 2010 Nokia Corporation and/or its subsidiary(-ies).
 * Contact:mika.saaranen@nokia.com
 * Developer(s): jaakko.pasanen@tieto.com, opensource@tieto.com
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

#ifndef USERLOGINSETUPDIALOG_H_
#define USERLOGINSETUPDIALOG_H_

void
init_user_login_dialog_fields (void);

void
init_user_login_setup_dialog (GladeXML *glade_xml);

void
deinit_user_login_setup_dialog (void);

void
continue_login_cb (GUPnPDeviceProxy       *proxy,
                   GUPnPDeviceProxyLogin  *logindata,
                   GError                **error,
                   gpointer                user_data);

void
continue_logout_cb (GUPnPDeviceProxy        *proxy,
					GUPnPDeviceProxyLogout  *logoutdata,
                    GError                 **error,
                    gpointer                 user_data);

#endif /* USERLOGINSETUPDIALOG_H_ */
