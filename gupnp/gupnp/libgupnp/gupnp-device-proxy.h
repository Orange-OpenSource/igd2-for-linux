/*
 * Copyright (C) 2006, 2007 OpenedHand Ltd.
 *
 * Author: Jorn Baayen <jorn@openedhand.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef __GUPNP_DEVICE_PROXY_H__
#define __GUPNP_DEVICE_PROXY_H__

#include "gupnp-device-info.h"

G_BEGIN_DECLS

GType
gupnp_device_proxy_get_type (void) G_GNUC_CONST;

#define GUPNP_TYPE_DEVICE_PROXY \
                (gupnp_device_proxy_get_type ())
#define GUPNP_DEVICE_PROXY(obj) \
                (G_TYPE_CHECK_INSTANCE_CAST ((obj), \
                 GUPNP_TYPE_DEVICE_PROXY, \
                 GUPnPDeviceProxy))
#define GUPNP_DEVICE_PROXY_CLASS(obj) \
                (G_TYPE_CHECK_CLASS_CAST ((obj), \
                 GUPNP_TYPE_DEVICE_PROXY, \
                 GUPnPDeviceProxyClass))
#define GUPNP_IS_DEVICE_PROXY(obj) \
                (G_TYPE_CHECK_INSTANCE_TYPE ((obj), \
                 GUPNP_TYPE_DEVICE_PROXY))
#define GUPNP_IS_DEVICE_PROXY_CLASS(obj) \
                (G_TYPE_CHECK_CLASS_TYPE ((obj), \
                 GUPNP_TYPE_DEVICE_PROXY))
#define GUPNP_DEVICE_PROXY_GET_CLASS(obj) \
                (G_TYPE_INSTANCE_GET_CLASS ((obj), \
                 GUPNP_TYPE_DEVICE_PROXY, \
                 GUPnPDeviceProxyClass))

#define GUPNP_DEVICE_WPS_METHOD_PIN             0x01
#define GUPNP_DEVICE_WPS_METHOD_PUSHBUTTON      0x02

typedef struct _GUPnPDeviceProxyPrivate GUPnPDeviceProxyPrivate;

/**
 * GUPnPDeviceProxy:
 *
 * This struct contains private data only, and should be accessed using the
 * functions below.
 */
typedef struct {
        GUPnPDeviceInfo parent;

        GUPnPDeviceProxyPrivate *priv;
} GUPnPDeviceProxy;

typedef struct {
        GUPnPDeviceInfoClass parent_class;

        /* future padding */
        void (* _gupnp_reserved1) (void);
        void (* _gupnp_reserved2) (void);
        void (* _gupnp_reserved3) (void);
        void (* _gupnp_reserved4) (void);
} GUPnPDeviceProxyClass;

typedef struct _GUPnPDeviceProxyWps GUPnPDeviceProxyWps;

/**
 * GUPnPDeviceProxyWpsCallback:
 * @proxy: The #GUPnPDeviceProxy @wps is called from
 * @action: The #GUPnPDevoceProxyWps in progress
 * @user_data: User data
 *
 * Callback notifying that @wps on @proxy has done the next step.
 **/
typedef void (* GUPnPDeviceProxyWpsCallback) (
                                     GUPnPDeviceProxy    *proxy,
                                     GUPnPDeviceProxyWps *wps,
                                     GString             *device_name,
                                     GError             **error,
                                     gpointer             user_data);

GUPnPDeviceProxyWps *
gupnp_device_proxy_begin_wps(GUPnPDeviceProxy           *proxy,
                             guint                       method,
                             const gchar                *client_name,
                             const gchar                *pin,
                             GUPnPDeviceProxyWpsCallback callback,
                             gpointer                    user_data);


void
gupnp_device_proxy_cancel_wps (GUPnPDeviceProxyWps *wps);

gboolean
gupnp_device_proxy_end_wps (GUPnPDeviceProxyWps *wps);

G_END_DECLS

#endif /* __GUPNP_DEVICE_PROXY_H__ */
