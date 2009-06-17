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

/**
 * SECTION:gupnp-device-proxy
 * @short_description: Proxy class for remote devices.
 *
 * #GUPnPDeviceProxy allows for retrieving proxies for a device's subdevices
 * and services. #GUPnPDeviceProxy implements the #GUPnPDeviceInfo interface.
 */

#include <glib.h>
#include <string.h>
#include <wpsutil/registrar_state_machine.h>
#include <wpsutil/base64mem.h>

#include "gupnp-device-proxy.h"
#include "gupnp-device-info-private.h"
#include "gupnp-resource-factory-private.h"
#include "xml-util.h"

G_DEFINE_TYPE (GUPnPDeviceProxy,
               gupnp_device_proxy,
               GUPNP_TYPE_DEVICE_INFO);

struct _GUPnPDeviceProxyPrivate {
        GUPnPDeviceProxy *root_proxy;

        GUPnPSSLClient *ssl_client; // this is used for SSL connections
};

struct _GUPnPDeviceProxyWps {
        GUPnPDeviceProxy  *proxy;
        GUPnPServiceProxy *device_prot_service;

        GUPnPDeviceProxyWpsCallback callback;

        gpointer user_data;

        GError *error;

        GString *device_name;
        GString *client_name;
        GString *pin;

        guint    method;
        gboolean done;

        // WPSutil structures
        WPSuRegistrarSM   *wpsu_rsm;
        WPSuRegistrarInput wpsu_input;
        unsigned char     *wpsu_registrar_send_msg;
        int                wpsu_registrar_send_msg_len;
        unsigned char      uuid[WPSU_MAX_UUID_LEN];
};

struct _GUPnPDeviceProxyLogin {
        GUPnPDeviceProxy  *proxy;
        GUPnPServiceProxy *device_prot_service;

        GUPnPDeviceProxyLoginCallback callback;

        gpointer user_data;

        GError *error;

        GString *username;
        GString *password;

        GString *salt;
        GString *challenge;

        gboolean done;
};

// this is actually quite useless, because Logout (currently doesn't do anything else than send
// UserLogout-action which has no parameters. So CP could just send that action as normal, but 
// lets add similar interface for logout than login if Logout changes in future.
// And this is beatifully symmetrical with Login :)
struct _GUPnPDeviceProxyLogout {
        GUPnPDeviceProxy  *proxy;
        GUPnPServiceProxy *device_prot_service;

        GUPnPDeviceProxyLogoutCallback callback;

        gpointer user_data;

        GError *error;

        gboolean done;
};


enum {
        PROP_0,
        PROP_SESSION,
};

GError *
gupnp_device_proxy_login_get_error (GUPnPDeviceProxyLogin *deviceProxyLogin)
{
        g_assert (deviceProxyLogin != NULL);
        return deviceProxyLogin->error;
}

GError *
gupnp_device_proxy_logout_get_error (GUPnPDeviceProxyLogout *deviceProxyLogout)
{
        g_assert (deviceProxyLogout != NULL);
        return deviceProxyLogout->error;
}

GError *
gupnp_device_proxy_wps_get_error (GUPnPDeviceProxyWps *deviceProxyWps)
{
        g_assert (deviceProxyWps != NULL);
        return deviceProxyWps->error;
}


static GUPnPDeviceInfo *
gupnp_device_proxy_get_device (GUPnPDeviceInfo *info,
                               xmlNode         *element)
{
        GUPnPDeviceProxy     *proxy, *device;
        GUPnPResourceFactory *factory;
        GUPnPContext         *context;
        XmlDocWrapper        *doc;
        const char           *location;
        const SoupURI        *url_base;

        proxy = GUPNP_DEVICE_PROXY (info);

        factory = gupnp_device_info_get_resource_factory (info);
        context = gupnp_device_info_get_context (info);
        doc = _gupnp_device_info_get_document (info);
        location = gupnp_device_info_get_location (info);
        url_base = gupnp_device_info_get_url_base (info);

        device = gupnp_resource_factory_create_device_proxy (factory,
                                                             context,
                                                             doc,
                                                             element,
                                                             NULL,
                                                             location,
                                                             url_base);


        // Add root deviceproxy information for new proxy
        // if older proxy here ('proxy'), doesn't already have root_proxy defined,
        // then it is the root_proxy for 'device'
        // (actually I'm not 100% sure if this root_proxy is even the root, or is it the
        // last leaf proxy. But it works at least if there are most of 3 levels of devices.
        if (proxy->priv->root_proxy)
            gupnp_device_proxy_set_root_proxy(device,proxy->priv->root_proxy);
        else
            gupnp_device_proxy_set_root_proxy(device,proxy);


        return GUPNP_DEVICE_INFO (device);
}

static GUPnPServiceInfo *
gupnp_device_proxy_get_service (GUPnPDeviceInfo *info,
                                xmlNode         *element)
{
        GUPnPDeviceProxy     *proxy;
        GUPnPResourceFactory *factory;
        GUPnPServiceProxy    *service;
        GUPnPContext         *context;
        XmlDocWrapper        *doc;
        const char           *location, *udn;
        const SoupURI        *url_base;

        proxy = GUPNP_DEVICE_PROXY (info);

        factory = gupnp_device_info_get_resource_factory (info);
        context = gupnp_device_info_get_context (info);
        doc = _gupnp_device_info_get_document (info);
        udn = gupnp_device_info_get_udn (info);
        location = gupnp_device_info_get_location (info);
        url_base = gupnp_device_info_get_url_base (info);

        service = gupnp_resource_factory_create_service_proxy (factory,
                                                               context,
                                                               doc,
                                                               element,
                                                               udn,
                                                               NULL,
                                                               location,
                                                               url_base);

        // set device proxy for GUPnPServiceProxy
        gupnp_service_proxy_set_device_proxy(service, proxy);

        return GUPNP_SERVICE_INFO (service);
}

static void
gupnp_device_proxy_init (GUPnPDeviceProxy *proxy)
{
        proxy->priv = G_TYPE_INSTANCE_GET_PRIVATE (proxy,
                                                   GUPNP_TYPE_DEVICE_PROXY,
                                                   GUPnPDeviceProxyPrivate);

        proxy->priv->root_proxy = NULL;
        proxy->priv->ssl_client = NULL;
}

static void
gupnp_device_proxy_class_init (GUPnPDeviceProxyClass *klass)
{
        g_type_class_add_private (klass, sizeof (GUPnPDeviceProxyPrivate));

        GUPnPDeviceInfoClass *info_class;
        info_class = GUPNP_DEVICE_INFO_CLASS (klass);

        GObjectClass *object_class;
        object_class = G_OBJECT_CLASS (klass);

        info_class->get_device  = gupnp_device_proxy_get_device;
        info_class->get_service = gupnp_device_proxy_get_service;
}

void
gupnp_device_proxy_set_root_proxy(GUPnPDeviceProxy *proxy,
                                  GUPnPDeviceProxy *root)
{
    proxy->priv->root_proxy = g_object_ref( root );
}



/* Functions related to the device protection:1 service */

static void
wps_got_response_null (GUPnPServiceProxy       *proxy,
                       GUPnPServiceProxyAction *action,
                       gpointer                 user_data)
{
}

/* Received response to wps message */
// static void
// wps_got_response (SoupSession             *session,
//                   SoupMessage             *msg,
//                   GUPnPDeviceProxyWps     *wps)
// {
//         // TODO: wps state machine
//
//         wps->callback(wps->proxy, wps->name, wps, wps->user_data);
// }
static void
wps_got_response (GUPnPServiceProxy       *proxy,
                  GUPnPServiceProxyAction *action,
                  gpointer                 user_data)
{
        g_warning("Oh noes, a response!");

        GUPnPDeviceProxyWps *wps = user_data;
        char *out_message;
        GError *error = NULL;
        int err;
        int status;

        if (!gupnp_service_proxy_end_action (proxy,
                                             action,
                                            &error,
                                             "OutMessage",
                                             G_TYPE_STRING,
                                             &out_message,
                                             NULL))
        {
                wps->error = error;
                g_warning("Error: %s", wps->error->message);
                wps->callback(wps->proxy, wps, wps->device_name, &wps->error, wps->user_data);
                return;
        }

        if (wps->error != NULL || out_message == NULL)
        {
                g_warning("Error: %s", wps->error->message);
                wps->callback(wps->proxy, wps, wps->device_name, &wps->error, wps->user_data);
                return;
        }

        int b64_msg_len = strlen(out_message);
        unsigned char *binary_message=(unsigned char *)g_malloc(b64_msg_len);
        int outlen;
        wpsu_base64_to_bin (b64_msg_len, (const unsigned char *)out_message, &outlen, binary_message, b64_msg_len);

        wpsu_update_registrar_sm(wps->wpsu_rsm,
                                 binary_message, outlen,
                                 &wps->wpsu_registrar_send_msg,
                                 &wps->wpsu_registrar_send_msg_len,
                                 &status, &err);

        int maxb64len = 2 * wps->wpsu_registrar_send_msg_len;
        int b64len;
        unsigned char *base64msg = (unsigned char *)g_malloc(maxb64len);

        wpsu_bin_to_base64(wps->wpsu_registrar_send_msg_len, wps->wpsu_registrar_send_msg, &b64len, base64msg, maxb64len);

        switch (status)
        {
        case WPSU_SM_R_SUCCESS:
                g_warning("DeviceProtection introduction last message received!\n");
                gupnp_service_proxy_begin_action(wps->device_prot_service,
                                                 "SendSetupMessage",
                                                 wps_got_response_null,
                                                 wps,
                                                 "ProtocolType",
                                                 G_TYPE_STRING,
                                                 "WPS",
                                                 "InMessage",
                                                 G_TYPE_STRING,
                                                 base64msg,
                                                 NULL);
                wps->done = TRUE;
                wps->callback(wps->proxy, wps, wps->device_name, &wps->error, wps->user_data);
                break;

        case WPSU_SM_R_SUCCESSINFO:
                g_warning("DeviceProtection introduction last message received M2D!\n");
                g_warning("Message: %s", base64msg);
                // Send last ack, TODO: change callback, we don't want to process the response
                gupnp_service_proxy_begin_action(wps->device_prot_service,
                                                 "SendSetupMessage",
                                                 wps_got_response_null,
                                                 wps,
                                                 "ProtocolType",
                                                 G_TYPE_STRING,
                                                 "WPS",
                                                 "InMessage",
                                                 G_TYPE_STRING,
                                                 base64msg,
                                                 NULL);

                WPSuRegistrarOutput *sm_output;
                sm_output = wpsu_get_registrar_sm_output(wps->wpsu_rsm, &err);
                wps->device_name = g_string_new(sm_output->EnrolleeInfo.DeviceName);

                g_warning("Device name: %s", wps->device_name->str);
                wps->callback(wps->proxy, wps, wps->device_name, &wps->error, wps->user_data);

                break;

        case WPSU_SM_R_FAILURE:
                wps->error = g_error_new(GUPNP_SERVER_ERROR,
                                         GUPNP_SERVER_ERROR_OTHER,
                                         "DeviceProtection introduction error in state machine. Terminating...");
                g_warning("Error: %s", wps->error->message);

                gupnp_service_proxy_begin_action(wps->device_prot_service,
                                "SendSetupMessage",
                                wps_got_response_null,
                                wps,
                                "ProtocolType",
                                G_TYPE_STRING,
                                "WPS",
                                "InMessage",
                                G_TYPE_STRING,
                                base64msg,
                                NULL);
                wps->callback(wps->proxy, wps, wps->device_name, &wps->error, wps->user_data);
                break;

        case WPSU_SM_R_FAILUREEXIT:
                wps->error = g_error_new(GUPNP_SERVER_ERROR,
                                         GUPNP_SERVER_ERROR_OTHER,
                                         "DeviceProtection introduction error in state machine. Terminating...");
                g_warning("Error: %s", wps->error->message);

                wps->callback(wps->proxy, wps, wps->device_name, &wps->error, wps->user_data);
                break;

        default:
                gupnp_service_proxy_begin_action(wps->device_prot_service,
                                "SendSetupMessage",
                                wps_got_response,
                                wps,
                                "ProtocolType",
                                G_TYPE_STRING,
                                "WPS",
                                "InMessage",
                                G_TYPE_STRING,
                                base64msg,
                                NULL);
                break;
        }

        g_free(binary_message);
        g_free(base64msg);
}

GUPnPServiceProxy *
find_device_protection_service (GUPnPDeviceProxy *proxy)
{
        GList *service;
        GUPnPServiceProxy *serv = NULL;
        const char *service_type;
        service = gupnp_device_info_list_services(GUPNP_DEVICE_INFO(proxy));

        while (service)
        {
                service_type = gupnp_service_info_get_service_type (GUPNP_SERVICE_INFO (service->data));
                if (g_strcmp0 ("urn:schemas-upnp-org:service:DeviceProtection:1", service_type) == 0)
                {
                        serv = GUPNP_SERVICE_PROXY (service->data);
                        service = g_list_remove_link (service, service);
                }
                else
                {
                        g_warning("No match: %s", service_type);
                        g_object_unref (service->data);
                        service = g_list_delete_link (service, service);
                }
        }

        return serv;
}

GUPnPDeviceProxyWps *
gupnp_device_proxy_begin_wps (GUPnPDeviceProxy           *proxy,
                              guint                       method,
                              const gchar                *client_name,
                              const gchar                *pin,
                              GUPnPDeviceProxyWpsCallback callback,
                              gpointer                    user_data)
{
        // TODO: send m1 to device and register callback
        GUPnPDeviceProxyWps *wps;
        int error;

        g_return_val_if_fail (GUPNP_IS_DEVICE_PROXY (proxy), NULL);
        g_return_val_if_fail (callback, NULL);
        g_return_val_if_fail (client_name, NULL);

        wps = g_slice_new (GUPnPDeviceProxyWps);
        wps->proxy = proxy;
        wps->callback = callback;
        wps->user_data = user_data;
        wps->error = NULL;
        wps->device_prot_service = find_device_protection_service (proxy);
        wps->client_name = g_string_new(client_name);
        wps->pin = g_string_new(pin);
        wps->method = method;
        wps->done = FALSE;

        if (wps->method == GUPNP_DEVICE_WPS_METHOD_PUSHBUTTON)
        {
                wps->error = g_error_new(GUPNP_SERVER_ERROR,
                                         GUPNP_SERVER_ERROR_OTHER,
                                         "Push button method not yet supported.");
                g_warning("Error: %s", wps->error->message);
                return wps;
        }

        if (wps->device_prot_service == NULL)
        {
                wps->error = g_error_new(GUPNP_SERVER_ERROR,
                                         GUPNP_SERVER_ERROR_OTHER,
                                         "No device protection service found.");
                g_warning("Error: %s", wps->error->message);
                return wps;
        }

        strncpy((char *)wps->uuid, gupnp_device_info_get_udn (GUPNP_DEVICE_INFO (proxy)), WPSU_MAX_UUID_LEN);
        wps->uuid[WPSU_MAX_UUID_LEN-1] = 0;

        error = wpsu_registrar_input_add_device_info (&wps->wpsu_input,
                                                       wps->pin->str, //device_pin
                                                       NULL,
                                                       NULL,
                                                       NULL,
                                                       NULL,
                                                       wps->client_name->str,
                                                       NULL,
                                                       0,
                                                       NULL,
                                                       0,
                                                       wps->uuid,
                                                       WPSU_MAX_UUID_LEN,
                                                       NULL,
                                                       0,
                                                       NULL,
                                                       0,
                                                       WPSU_CONF_METHOD_LABEL,
                                                       0);

        if (error != WPSU_E_SUCCESS)
        {
                wps->error = g_error_new(GUPNP_SERVER_ERROR,
                                         GUPNP_SERVER_ERROR_OTHER,
                                         "Failed to create WPS input.");
                g_warning("%s", wps->error->message);
                return wps;
        }

        wps->wpsu_rsm = wpsu_create_registrar_sm_enrollment(&error);
        if (error != WPSU_E_SUCCESS)
        {
                wps->error = g_error_new(GUPNP_SERVER_ERROR,
                                         GUPNP_SERVER_ERROR_OTHER,
                                         "Failed to create registrat state machine.");
                g_warning("%s", wps->error->message);
                return wps;
        }

        wpsu_start_registrar_sm(wps->wpsu_rsm, &wps->wpsu_input, &error);
        if (error != WPSU_E_SUCCESS)
        {
                wps->error = g_error_new(GUPNP_SERVER_ERROR,
                                         GUPNP_SERVER_ERROR_OTHER,
                                         "Failed to start registrar state machine.");
                g_warning("%s", wps->error->message);
                return wps;
        }

        gupnp_service_proxy_begin_action(wps->device_prot_service,
                                         "SendSetupMessage",
                                         wps_got_response,
                                         wps,
                                         "ProtocolType",
                                         G_TYPE_STRING,
                                         "WPS",
                                         "InMessage",
                                         G_TYPE_STRING,
                                         "",
                                         NULL);

        return wps;
}

// useless?
GUPnPDeviceProxyWps *
gupnp_device_proxy_continue_wps (GUPnPDeviceProxyWps        *wps,
                                 GString                    *pin,
                                 gpointer                    user_data)
{
        // TODO: wps messages m2..m8
        int error = wpsu_registrar_input_add_device_info (&wps->wpsu_input,
                                                       pin->str,
                                                       NULL,
                                                       NULL,
                                                       NULL,
                                                       NULL,
                                                       wps->client_name->str,
                                                       NULL,
                                                       0,
                                                       NULL,
                                                       0,
                                                       wps->uuid,
                                                       WPSU_MAX_UUID_LEN,
                                                       NULL,
                                                       0,
                                                       NULL,
                                                       0,
                                                       WPSU_CONF_METHOD_LABEL,
                                                       0);

        if (error != WPSU_E_SUCCESS)
        {
                wps->error = g_error_new(GUPNP_SERVER_ERROR,
                                         GUPNP_SERVER_ERROR_OTHER,
                                         "Failed to create WPS input.");
                g_warning("%s", wps->error->message);
                return wps;
        }

        gupnp_service_proxy_begin_action(wps->device_prot_service,
                                         "SendSetupMessage",
                                         wps_got_response,
                                         wps,
                                         "ProtocolType",
                                         G_TYPE_STRING,
                                         "WPS",
                                         "InMessage",
                                         G_TYPE_STRING,
                                         "",
                                         NULL);

        return wps;
}

void
gupnp_device_proxy_cancel_wps (GUPnPDeviceProxyWps *wps)
{
        g_warning("Canceling wps setup not yet supported.");
}

gboolean
gupnp_device_proxy_end_wps (GUPnPDeviceProxyWps *wps)
{
        // TODO: end wps setup
        gint err;

        gboolean done = wps->done;
        g_object_unref(wps->proxy);
        g_string_free(wps->client_name, TRUE);
        g_string_free(wps->pin, TRUE);
        //g_string_free(wps->device_name, TRUE);

        wpsu_registrar_input_free(&wps->wpsu_input);
        wpsu_cleanup_registrar_sm(wps->wpsu_rsm, &err);

        g_free(wps);

        return done;
}

gboolean
gupnp_device_proxy_init_ssl (GUPnPDeviceProxy *proxy,
                             GError          **error)
{
        g_assert (proxy != NULL);

        if ( proxy->priv->ssl_client != NULL )
        {
            return TRUE;
        }

        GUPnPServiceProxy *found_device = find_device_protection_service (proxy);
        if (found_device == NULL) // no device protection service found for the device
        {
            *error = g_error_new(GUPNP_SERVER_ERROR,
                                 GUPNP_SERVER_ERROR_OTHER,
                                 "No device protection service found.");
            return FALSE;
        }
        else
        {
            const char *URL = gupnp_service_info_get_control_url (GUPNP_SERVICE_INFO(found_device));
            g_object_unref (found_device);

            // create ssl
            int ret = gupnp_device_proxy_create_and_init_ssl_client (proxy,
                              URL, GUPNP_SSL_PORT);

            if (ret != 0)
            {
                *error = g_error_new(GUPNP_SERVER_ERROR,
                                     GUPNP_SERVER_ERROR_OTHER,
                                     "Failed to create SSL client or failed to connect server.");
                return FALSE;
            }
        }

        return TRUE;
}


/**
 * gupnp_context_create_and_init_ssl_client
 * @context: A #GUPnPContext
 * @url: Address of server. Address is changed into HTTPS address
 * @port: Port number on which client will connect on server
 *
 * Create and initialize ssl client of proxy. Connects to server.
 **/
int
gupnp_device_proxy_create_and_init_ssl_client (GUPnPDeviceProxy *proxy,
                              const char *url, int port)
{
        g_assert (proxy != NULL);

        char *https_url;
        int ret = 0;

        if (proxy->priv->ssl_client == NULL)
            proxy->priv->ssl_client = g_slice_new(GUPnPSSLClient);//malloc(sizeof(GUPnPSSLClient));
        else
            return -1;

        ssl_create_https_url(url, port, &https_url);
        if (https_url == NULL)
        {
            g_warning("Failed to create https url from '%s' and port %d",url,port);
            return -1;
        }

        ret = ssl_init_client(proxy->priv->ssl_client,"./certstore/",NULL,NULL,NULL,NULL, "GUPNP Client");
        if (ret != 0)
        {
            g_warning("Failed init SSL client");
            return ret;
        }

        // create SSL session (connection to server)
        ret = ssl_create_client_session(proxy->priv->ssl_client, https_url, NULL, NULL);
        if (ret != 0)
        {
            g_warning("Failed create SSL session to '%s'",https_url);
            return ret;
        }

        return 0;
}


/**
 * gupnp_context_set_ssl_client
 * @context: A #GUPnPContext
 * @client: A #GUPnPSSLClient
 *
 * Sets ssl client of proxy.
 **/
void
gupnp_device_proxy_set_ssl_client (GUPnPDeviceProxy *proxy,
                              GUPnPSSLClient *client)
{
        g_assert (proxy != NULL);

        if (proxy->priv->ssl_client == NULL)
            proxy->priv->ssl_client = g_slice_new(GUPnPSSLClient);//malloc(sizeof(GUPnPSSLClient));

        memcpy(proxy->priv->ssl_client, client, sizeof(GUPnPSSLClient));
}

/**
 * gupnp_device_proxy_get_ssl_client
 * @proxy: A #GUPnPDeviceProxy
 *
 * Get the ssl-client that GUPnP is using.
 *
 * Return value: The #GUPnPSSLClient used by GUPnP. Do not unref this when
 * finished.
 **/
GUPnPSSLClient *
gupnp_device_proxy_get_ssl_client (GUPnPDeviceProxy *proxy)
{
        g_assert (proxy != NULL);

        if (proxy->priv->root_proxy)
            return proxy->priv->root_proxy->priv->ssl_client;
}





/*      UserLogin stuff       */

/**
 * Create authenticator value used in UserLogin
 * Authenticator contains the Base64 encoding of the first 20 bytes of SHA-256(STORED || Challenge).
 *
 * This function is taken from libupnp deviceprotection.c and modified bit.
 *
 * @param bin_stored Binary value of STORED.
 * @param bin_stored_len Length of STORED in bytes
 * @param b64_challenge Base64 encoded value of Challenge.
 * @param b64_authenticator Pointer to string where authenticator is created. User needs to use free() for this
 * @param auth_len Pointer to integer which is set to contain length of created authenticator
 * @return 0 if succeeded to create authenticato. Something else if error
 */
static int createAuthenticator(const unsigned char *bin_stored, int bin_stored_len, const char *b64_challenge, char **b64_authenticator, int *auth_len)
{
    if (bin_stored == NULL)
    {
        return -1;
    }
    // challenge from base64 to binary
    int b64msglen = strlen(b64_challenge);
    unsigned char *bin_challenge = (unsigned char *)malloc(b64msglen);
    if (bin_challenge == NULL)
    {
        return -1;
    }
    int bin_challenge_len;
    wpsu_base64_to_bin(b64msglen, (const unsigned char *)b64_challenge, &bin_challenge_len, bin_challenge, b64msglen);


    // concatenate stored || challenge
    int bin_concat_len = bin_stored_len + bin_challenge_len;
    unsigned char *bin_concat = (unsigned char *)malloc(bin_concat_len);
    if (bin_concat == NULL)
    {
        if (bin_challenge) free(bin_challenge);
        return -1;
    }
    memcpy(bin_concat, bin_stored, bin_stored_len);
    memcpy(bin_concat + bin_stored_len, bin_challenge, bin_challenge_len);

    // release useless stuff
    if (bin_challenge) free(bin_challenge);

    // crete hash from concatenation
    unsigned char hash[2*bin_concat_len];
    int hashlen = wpsu_sha256(bin_concat, bin_concat_len, hash);
    if (hashlen < 0)
    {
        if (bin_concat) free(bin_concat);
        *b64_authenticator = NULL;
        return hashlen;
    }

    // encode required amount of first bytes of created hash as base64 authenticator
    int maxb64len = 2*GUPNP_DP_AUTH_BYTES;
    *auth_len = 0;
    *b64_authenticator = (char *)malloc(maxb64len);
    wpsu_bin_to_base64(GUPNP_DP_AUTH_BYTES, hash, auth_len, (unsigned char *)*b64_authenticator, maxb64len);

    if (bin_concat) free(bin_concat);
    return 0;
}

// this is called when library receives response for UserLogin-action
static void
login_response (GUPnPServiceProxy       *proxy,
                GUPnPServiceProxyAction *action,
                gpointer                 user_data)
{
        GUPnPDeviceProxyLogin *logindata = user_data;
        GError *error = NULL;

        if (!gupnp_service_proxy_end_action (proxy,
                                             action,
                                            &error,
                                             NULL))
        {
                logindata->error = error;
                g_warning("Error: %s", logindata->error->message);
        }
        else
        {
            logindata->done = TRUE;
        }
        logindata->callback(logindata->proxy, logindata, &logindata->error, logindata->user_data);
}

// this is called when library receives response for GetUserLoginChallenge-action
static void
login_challenge_response (GUPnPServiceProxy       *proxy,
                          GUPnPServiceProxyAction *action,
                          gpointer                 user_data)
{
        GUPnPDeviceProxyLogin *logindata = user_data;
        char *salt;
        char *challenge;
        gchar* nameUPPER;
        GError *error = NULL;
        int err;

        if (!gupnp_service_proxy_end_action (proxy,
                                             action,
                                            &error,
                                             "Salt",
                                             G_TYPE_STRING,
                                             &salt,
                                             "Challenge",
                                             G_TYPE_STRING,
                                             &challenge,
                                             NULL))
        {
                logindata->error = error;
                g_warning("Error: %s", logindata->error->message);
                logindata->callback(logindata->proxy, logindata, &logindata->error, logindata->user_data);
                return;
        }

        if (logindata->error != NULL || salt == NULL || challenge == NULL)
        {
                g_warning("Error: %s", logindata->error->message);
                logindata->callback(logindata->proxy, logindata, &logindata->error, logindata->user_data);
                return;
        }
        else
        {
                // create STORED. Needed values are salt, username (in uppercase) and password
                // salt from base64 to binary
                int b64_msg_len = strlen(salt);
                unsigned char *bin_salt=(unsigned char *)g_malloc(b64_msg_len);
                int bin_salt_len;
                wpsu_base64_to_bin (b64_msg_len, (const unsigned char *)salt, &bin_salt_len, bin_salt, b64_msg_len);

                // username to utf8 uppercase
                nameUPPER = g_utf8_strup(logindata->username->str, logindata->username->len);
                if (!nameUPPER)
                {
                    logindata->error = g_error_new(GUPNP_SERVER_ERROR,
                                                   GUPNP_SERVER_ERROR_OTHER,
                                                   "Failed to convert username to uppercase");
                    g_warning("%s", logindata->error->message);
                    logindata->callback(logindata->proxy, logindata, &logindata->error, logindata->user_data);
                    return;
                }

                // concatenate NAME and binary salt
                glong name_len = g_utf8_strlen(nameUPPER, -1);                
                glong namesalt_len = name_len + bin_salt_len;  // should it matter if salt_len is greater than 16. It shouldn't happen, but...
                unsigned char namesalt[namesalt_len];

                memcpy(namesalt, nameUPPER, name_len);
                memcpy(namesalt+name_len, bin_salt, bin_salt_len);


                // create STORED
                unsigned char bin_stored[GUPNP_DP_STORED_BYTES];
                err = wpsu_pbkdf2(logindata->password->str, logindata->password->len, namesalt,
                                namesalt_len, GUPNP_DP_PRF_ROUNDS, GUPNP_DP_STORED_BYTES, bin_stored);

                if (err != 0)
                {
                    logindata->error = g_error_new(GUPNP_SERVER_ERROR,
                                                   GUPNP_SERVER_ERROR_OTHER,
                                                   "Failed to create STORED");
                    g_warning("%s", logindata->error->message);
                    logindata->callback(logindata->proxy, logindata, &logindata->error, logindata->user_data);
                    return;
                }


                // create Authenticator
                char *b64_authenticator = NULL;
                int auth_len = 0;
                err = createAuthenticator(bin_stored, GUPNP_DP_STORED_BYTES, challenge, &b64_authenticator, &auth_len);

                if (err != 0)
                {
                    logindata->error = g_error_new(GUPNP_SERVER_ERROR,
                                                   GUPNP_SERVER_ERROR_OTHER,
                                                   "Failed to create Authenticator");
                    g_warning("%s", logindata->error->message);
                    logindata->callback(logindata->proxy, logindata, &logindata->error, logindata->user_data);
                    return;
                }

                // send UserLogin
                gupnp_service_proxy_begin_action(logindata->device_prot_service,
                                                 "UserLogin",
                                                 login_response,
                                                 logindata,
                                                 "Challenge",
                                                 G_TYPE_STRING,
                                                 challenge,
                                                 "Authenticator",
                                                 G_TYPE_STRING,
                                                 b64_authenticator,
                                                 NULL);

                g_free(b64_authenticator);
        }
}


// Begin login-process by calling this
GUPnPDeviceProxyLogin *
gupnp_device_proxy_begin_login (GUPnPDeviceProxy           *proxy,
                                const gchar                *username,
                                const gchar                *password,
                                GUPnPDeviceProxyLoginCallback callback,
                                gpointer                    user_data)
{
        GUPnPDeviceProxyLogin *logindata;
        int error;
        GError *gerror;

        g_return_val_if_fail (GUPNP_IS_DEVICE_PROXY (proxy), NULL);
        g_return_val_if_fail (callback, NULL);
        g_return_val_if_fail (username, NULL);
        g_return_val_if_fail (password, NULL);

        // we need to have SSL
        // so let's create it
        gupnp_device_proxy_init_ssl (proxy, &gerror);

        if (gupnp_device_proxy_get_ssl_client(proxy) == NULL)
        {           
                logindata->error = g_error_new(GUPNP_SERVER_ERROR,
                             GUPNP_SERVER_ERROR_OTHER,
                             "For logging in SSL connection is needed.");
                g_warning("Error: %s", logindata->error->message);
                return logindata;
        }


        logindata = g_slice_new (GUPnPDeviceProxyLogin);
        logindata->proxy = proxy;
        logindata->callback = callback;
        logindata->user_data = user_data;
        logindata->error = NULL;
        logindata->device_prot_service = find_device_protection_service (proxy);
        logindata->username = g_string_new(username);
        logindata->password = g_string_new(password);
        logindata->salt = NULL;
        logindata->challenge = NULL;
        logindata->done = FALSE;


        if (logindata->device_prot_service == NULL)
        {
                logindata->error = g_error_new(GUPNP_SERVER_ERROR,
                                         GUPNP_SERVER_ERROR_OTHER,
                                         "No device protection service found.");
                g_warning("Error: %s", logindata->error->message);
                return logindata;
        }



        gupnp_service_proxy_begin_action(logindata->device_prot_service,
                                         "GetUserLoginChallenge",
                                         login_challenge_response,
                                         logindata,
                                         "Name",
                                         G_TYPE_STRING,
                                         username,
                                         NULL);

        return logindata;
}

// End login-process by calling this. Returns if logging is succeeded. Username which was logged in,
// is returned in  loginname
gboolean
gupnp_device_proxy_end_login (GUPnPDeviceProxyLogin *logindata, GString *loginname)
{
        // copy username logged in to loginname
        if (loginname)
            g_string_assign(loginname, logindata->username->str);

        gboolean done = logindata->done;

        g_object_unref(logindata->proxy);

        g_string_free(logindata->username, TRUE);
        g_string_free(logindata->password, TRUE);

        //g_free(logindata); TODO: kaatuu tähän?

        return done;
}



/*   Logout  */

// this is called when library receives response for UserLogout-action
static void
logout_response (GUPnPServiceProxy       *proxy,
                GUPnPServiceProxyAction *action,
                gpointer                 user_data)
{
        GUPnPDeviceProxyLogout *logoutdata = user_data;
        GError *error = NULL;

        if (!gupnp_service_proxy_end_action (proxy,
                                             action,
                                            &error,
                                             NULL))
        {
                logoutdata->error = error;
                g_warning("Error: %s", logoutdata->error->message);
        }
        else
        {
            logoutdata->done = TRUE;
        }
        logoutdata->callback(logoutdata->proxy, logoutdata, &logoutdata->error, logoutdata->user_data);
}

// Begin logout-process by calling this
GUPnPDeviceProxyLogout *
gupnp_device_proxy_begin_logout (GUPnPDeviceProxy           *proxy,
                                 GUPnPDeviceProxyLogoutCallback callback,
                                 gpointer                    user_data)
{
        GUPnPDeviceProxyLogout *logoutdata;
        int error;
        GError *gerror;

        g_return_val_if_fail (GUPNP_IS_DEVICE_PROXY (proxy), NULL);
        g_return_val_if_fail (callback, NULL);

        // we need to have SSL
        // so let's create it (if not created already
        gupnp_device_proxy_init_ssl (proxy, &gerror);

        if (gupnp_device_proxy_get_ssl_client(proxy) == NULL)
        {           
                logoutdata->error = g_error_new(GUPNP_SERVER_ERROR,
                             GUPNP_SERVER_ERROR_OTHER,
                             "For logging out SSL connection is needed.");
                g_warning("Error: %s", logoutdata->error->message);
                return logoutdata;
        }


        logoutdata = g_slice_new (GUPnPDeviceProxyLogout);
        logoutdata->proxy = proxy;
        logoutdata->callback = callback;
        logoutdata->user_data = user_data;
        logoutdata->error = NULL;
        logoutdata->device_prot_service = find_device_protection_service (proxy);
        logoutdata->done = FALSE;


        if (logoutdata->device_prot_service == NULL)
        {
                logoutdata->error = g_error_new(GUPNP_SERVER_ERROR,
                                         GUPNP_SERVER_ERROR_OTHER,
                                         "No device protection service found.");
                g_warning("Error: %s", logoutdata->error->message);
                return logoutdata;
        }



        gupnp_service_proxy_begin_action(logoutdata->device_prot_service,
                                         "UserLogout",
                                         logout_response,
                                         logoutdata,
                                         NULL);

        return logoutdata;
}


gboolean
gupnp_device_proxy_end_logout (GUPnPDeviceProxyLogout *logoutdata)
{
        gboolean done = logoutdata->done;

        g_object_unref(logoutdata->proxy);

        return done;
}
