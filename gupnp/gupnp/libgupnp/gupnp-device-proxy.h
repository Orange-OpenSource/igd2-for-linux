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
#include "gupnp-ssl-client.h"

G_BEGIN_DECLS

#define GUPNP_DP_PRF_ROUNDS    5000
#define GUPNP_DP_SALT_BYTES    16
#define GUPNP_DP_STORED_BYTES  16
#define GUPNP_DP_NONCE_BYTES   16
#define GUPNP_DP_AUTH_BYTES    16


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
typedef struct _GUPnPDeviceProxyLogin GUPnPDeviceProxyLogin;
typedef struct _GUPnPDeviceProxyLogout GUPnPDeviceProxyLogout;
typedef struct _GUPnPDeviceProxyChangePassword GUPnPDeviceProxyChangePassword;
typedef struct _GUPnPDeviceProxyAddUser GUPnPDeviceProxyAddUser;
typedef struct _GUPnPDeviceProxyRemoveUser GUPnPDeviceProxyRemoveUser;
typedef struct _GUPnPDeviceProxySetRoles GUPnPDeviceProxySetRoles;
typedef struct _GUPnPDeviceProxyGetACLData GUPnPDeviceProxyGetACLData;

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

/**
 * GUPnPDeviceProxyLoginCallback:
 * @proxy: The #GUPnPDeviceProxy login is called
 * @logindata: The #GUPnPDeviceProxyLogin in progress
 * @user_data: User data
 *
 * Callback notifying that logging in on @proxy has done the next step.
 **/
typedef void (* GUPnPDeviceProxyLoginCallback) (
                                     GUPnPDeviceProxy    *proxy,
                                     GUPnPDeviceProxyLogin *logindata,
                                     GError             **error,
                                     gpointer             user_data);


/**
 * GUPnPDeviceProxyLogoutCallback:
 * @proxy: The #GUPnPDeviceProxy logout is called
 * @logindata: The #GUPnPDeviceProxyLogout in progress
 * @user_data: User data
 *
 * Callback notifying that logging out on @proxy has done the next step.
 **/
typedef void (* GUPnPDeviceProxyLogoutCallback) (
                                     GUPnPDeviceProxy    *proxy,
                                     GUPnPDeviceProxyLogout *logoutdata,
                                     GError             **error,
                                     gpointer             user_data);


/**
 * GUPnPDeviceProxyChangePasswordCallback:
 * @proxy: The #GUPnPDeviceProxy change password is called
 * @changepassworddata: The #GUPnPDeviceProxyChangePassword in progress
 * @user_data: User data
 *
 * Callback notifying that change password on @proxy has done the next step.
 **/
typedef void (* GUPnPDeviceProxyChangePasswordCallback) (
                                     GUPnPDeviceProxy    *proxy,
                                     GUPnPDeviceProxyChangePassword *passworddata,
                                     GError             **error,
                                     gpointer             user_data);
                                     
/**
 * GUPnPDeviceProxyAddUserCallback:
 * @proxy: The #GUPnPDeviceProxy add user is called
 * @adduserdata: The #GUPnPDeviceProxyAddUser in progress
 * @user_data: User data
 *
 * Callback notifying that add user on @proxy has done the next step.
 **/
typedef void (* GUPnPDeviceProxyAddUserCallback) (
                                     GUPnPDeviceProxy    *proxy,
                                     GUPnPDeviceProxyAddUser *adduserdata,
                                     GError             **error,
                                     gpointer             user_data);
                                     
/**
 * GUPnPDeviceProxyRemoveUserCallback:
 * @proxy: The #GUPnPDeviceProxy add user is called
 * @removeuserdata: The #GUPnPDeviceProxySetRoles in progress
 * @user_data: User data
 *
 * Callback notifying that remove user on @proxy has done the next step.
 **/
typedef void (* GUPnPDeviceProxyRemoveUserCallback) (
                                     GUPnPDeviceProxy    *proxy,
                                     GUPnPDeviceProxyRemoveUser *removeuserdata,
                                     GError             **error,
                                     gpointer             user_data);  

/**
 * GUPnPDeviceProxySetRolesCallback:
 * @proxy: The #GUPnPDeviceProxy add user is called
 * @adduserdata: The #GUPnPDeviceProxySetRoles in progress
 * @user_data: User data
 *
 * Callback notifying that add or remove roles on @proxy has done the next step.
 **/
typedef void (* GUPnPDeviceProxySetRolesCallback) (
                                     GUPnPDeviceProxy    *proxy,
                                     GUPnPDeviceProxySetRoles *rolesdata,
                                     GError             **error,
                                     gpointer             user_data);

/**
 * GUPnPDeviceProxyGetACLDataCallback:
 * @proxy: The #GUPnPDeviceProxy add user is called
 * @adduserdata: The #GUPnPDeviceProxyGetACLData in progress
 * @user_data: User data
 *
 * Callback notifying that get ACL on @proxy has done the next step.
 **/
typedef void (* GUPnPDeviceProxyGetACLDataCallback) (
                                     GUPnPDeviceProxy    *proxy,
                                     GUPnPDeviceProxyGetACLData *ACLData,
                                     GError             **error,
                                     gpointer             user_data);


GUPnPDeviceProxyWps *
gupnp_device_proxy_begin_wps(GUPnPDeviceProxy           *proxy,
                             guint                       method,
                             const gchar                *client_name,
                             const gchar                *pin,
                             GUPnPDeviceProxyWpsCallback callback,
                             gpointer                    user_data);

GError *
gupnp_device_proxy_wps_get_error (GUPnPDeviceProxyWps *deviceProxyWps);

void
gupnp_device_proxy_cancel_wps (GUPnPDeviceProxyWps *wps);

gboolean
gupnp_device_proxy_end_wps (GUPnPDeviceProxyWps *wps);

gboolean
gupnp_device_proxy_init_ssl (GUPnPDeviceProxy *proxy,
                             GError          **error);


void
gupnp_device_proxy_set_root_proxy(GUPnPDeviceProxy *proxy,
                                  GUPnPDeviceProxy *root);


int
gupnp_device_proxy_create_and_init_ssl_client (GUPnPDeviceProxy           *proxy,
                                        const char *url);

void
gupnp_device_proxy_set_ssl_client           (GUPnPDeviceProxy           *proxy,
                                        GUPnPSSLClient *client);

GUPnPSSLClient **
gupnp_device_proxy_get_ssl_client           (GUPnPDeviceProxy           *proxy);

void
gupnp_device_proxy_set_username (GUPnPDeviceProxy *proxy, const gchar *username);

GString *
gupnp_device_proxy_get_username (GUPnPDeviceProxy *proxy);

GError *
gupnp_device_proxy_login_get_error (GUPnPDeviceProxyLogin *deviceProxyLogin);

GUPnPDeviceProxyLogin *
gupnp_device_proxy_begin_login (GUPnPDeviceProxy           *proxy,
                                const gchar                *username,
                                const gchar                *password,
                                GUPnPDeviceProxyLoginCallback callback,
                                gpointer                    user_data);

gboolean
gupnp_device_proxy_end_login (GUPnPDeviceProxyLogin *logindata, GString *loginname);


GError *
gupnp_device_proxy_logout_get_error (GUPnPDeviceProxyLogout *deviceProxyLogout);

GUPnPDeviceProxyLogout *
gupnp_device_proxy_begin_logout (GUPnPDeviceProxy           *proxy,
                                 GUPnPDeviceProxyLogoutCallback callback,
                                 gpointer                    user_data);

gboolean
gupnp_device_proxy_end_logout (GUPnPDeviceProxyLogout *logoutdata);

GError *
gupnp_device_proxy_change_password_get_error (GUPnPDeviceProxyChangePassword *deviceProxyChangePassword);

GUPnPDeviceProxyChangePassword *
gupnp_device_proxy_change_password (GUPnPDeviceProxy                       *proxy,
                                    const gchar                            *username,
                                    const gchar                            *password,
                                    GUPnPDeviceProxyChangePasswordCallback  callback,
                                    gpointer                                user_data);

gboolean
gupnp_device_proxy_end_change_password (GUPnPDeviceProxyChangePassword *passworddata, GString *loginname);

GUPnPDeviceProxyAddUser *
gupnp_device_proxy_add_user (GUPnPDeviceProxy           *proxy,
                             const gchar                *username,
                             const gchar                *password,  
                             GUPnPDeviceProxyAddUserCallback callback,
                             gpointer                    user_data);
                             
gboolean
gupnp_device_proxy_end_add_user (GUPnPDeviceProxyAddUser *adduserdata);                             

GUPnPDeviceProxyRemoveUser *
gupnp_device_proxy_remove_user (GUPnPDeviceProxy           *proxy,
                             const gchar                *username,  
                             GUPnPDeviceProxyRemoveUserCallback callback,
                             gpointer                    user_data);

gboolean
gupnp_device_proxy_end_remove_user (GUPnPDeviceProxyRemoveUser *removeuserdata);


GUPnPDeviceProxySetRoles *
gupnp_device_proxy_add_roles (GUPnPDeviceProxy           *proxy,
                             const gchar                *username,
                             const gchar                *rolelist,      
                             GUPnPDeviceProxySetRolesCallback callback,
                             gpointer                    user_data);
                             
gboolean
gupnp_device_proxy_end_add_roles (GUPnPDeviceProxySetRoles *addrolesdata);                             

GUPnPDeviceProxySetRoles *
gupnp_device_proxy_remove_roles (GUPnPDeviceProxy           *proxy,
                             const gchar                *username,
                             const gchar                *rolelist,  
                             GUPnPDeviceProxySetRolesCallback callback,
                             gpointer                    user_data);

gboolean
gupnp_device_proxy_end_remove_roles (GUPnPDeviceProxySetRoles *removerolesdata);

GUPnPDeviceProxyGetACLData *
gupnp_device_proxy_get_ACL_data (GUPnPDeviceProxy           *proxy,
                             GUPnPDeviceProxyGetACLDataCallback callback,
                             gpointer                    user_data);

gboolean
gupnp_device_proxy_end_get_ACL_data (GUPnPDeviceProxyGetACLData *ACLData);


G_END_DECLS

#endif /* __GUPNP_DEVICE_PROXY_H__ */
