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

struct _GUPnPDeviceProxyWps {
        GUPnPDeviceProxy  *proxy;
        GUPnPServiceProxy *device_prot_service;

        GUPnPDeviceProxyWpsCallback callback;

        gpointer user_data;

        GError *error;

        GString *name;

        // WPSutil structures
        WPSuRegistrarSM   *wpsu_rsm;
        WPSuRegistrarInput wpsu_input;
        unsigned char     *wpsu_registrar_send_msg;
        int                wpsu_registrar_send_msg_len;
        unsigned char uuid[WPSU_MAX_UUID_LEN];
};

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

        return GUPNP_SERVICE_INFO (service);
}

static void
gupnp_device_proxy_init (GUPnPDeviceProxy *proxy)
{
}

static void
gupnp_device_proxy_class_init (GUPnPDeviceProxyClass *klass)
{
        GUPnPDeviceInfoClass *info_class;

        info_class = GUPNP_DEVICE_INFO_CLASS (klass);

        info_class->get_device  = gupnp_device_proxy_get_device;
        info_class->get_service = gupnp_device_proxy_get_service;
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
                wps->callback(wps->proxy, wps->name, wps, &wps->error, wps->user_data);
                return;
        }

        if (wps->error != NULL || out_message == NULL)
        {
                g_warning("Error: %s", wps->error->message);
                wps->callback(wps->proxy, wps->name, wps, &wps->error, wps->user_data);
                return;
        }

        int b64_msg_len = strlen(out_message);
        unsigned char *binary_message=(unsigned char *)malloc(b64_msg_len);
        int outlen;
        wpsu_base64_to_bin (b64_msg_len, (const unsigned char *)out_message, &outlen, binary_message, b64_msg_len);

        wpsu_update_registrar_sm(wps->wpsu_rsm,
                                 binary_message, outlen,
                                 &wps->wpsu_registrar_send_msg,
                                 &wps->wpsu_registrar_send_msg_len,
                                 &status, &err);

        int maxb64len = 2 * wps->wpsu_registrar_send_msg_len;
        int b64len;
        unsigned char *base64msg = (unsigned char *)malloc(maxb64len);
        g_warning("2");

        wpsu_bin_to_base64(wps->wpsu_registrar_send_msg_len, wps->wpsu_registrar_send_msg, &b64len, base64msg, maxb64len);
        g_warning("3");

        switch (status)
        {
        case WPSU_SM_R_SUCCESS:
                g_warning("DeviceProtection introduction last message received!\n");
                //EndWPSIntroductionViaUpnp();
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
                                                 "DeviceProtection:1",
                                                 "InMessage",
                                                 G_TYPE_STRING,
                                                 base64msg,
                                                 NULL);

                WPSuRegistrarOutput *smOutput;
                smOutput = wpsu_get_registrar_sm_output(wps->wpsu_rsm, &err);
                wps->name = g_string_new(smOutput->EnrolleeInfo.DeviceName);

                g_warning("Device name: %s", wps->name->str);
                wps->callback(wps->proxy, wps->name, wps, &wps->error, wps->user_data);

                break;

        case WPSU_SM_R_FAILURE:
                g_warning("DeviceProtection introduction error in state machine. Terminating...\n");

                //EndWPSIntroductionViaUpnp();
                break;

        case WPSU_SM_R_FAILUREEXIT:
                g_warning("DeviceProtection introduction error in state machine. Terminating...\n");

                break;
                
        default:
                //ContinueWPSIntroductionViaUpnp();
                break;
        }

        wps->callback(wps->proxy, wps->name, wps, &wps->error, wps->user_data);
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
                              GString                    *client_name,
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
        // device pin null, we just want the device info for now
        error = wpsu_registrar_input_add_device_info (&wps->wpsu_input,
                                                       "", //device_pin
                                                       NULL,
                                                       NULL,
                                                       NULL,
                                                       NULL,
                                                       client_name->str,
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
        wpsu_start_registrar_sm(wps->wpsu_rsm, &wps->wpsu_input, &error);

        g_warning("wps: initial message");
        gupnp_service_proxy_begin_action(wps->device_prot_service,
                                         "SendSetupMessage",
                                         wps_got_response,
                                         wps,
                                         "ProtocolType",
                                         G_TYPE_STRING,
                                         "DeviceProtection:1",
                                         "InMessage",
                                         G_TYPE_STRING,
                                         "",
                                         NULL);

        return wps;
}

GUPnPDeviceProxyWps *
gupnp_device_proxy_continue_wps (GUPnPDeviceProxyWps        *wps,
                                 GString                     pin,
                                 gpointer                    user_data)
{
        // TODO: wps messages m2..m8

        return wps;
}

void
gupnp_device_proxy_cancel_wps (GUPnPDeviceProxyWps *wps)
{
        // TODO: abort wps setup
}

gboolean
gupnp_device_proxy_end_wps (GUPnPDeviceProxyWps *wps)
{
        // TODO: end wps setup

        return TRUE;
}