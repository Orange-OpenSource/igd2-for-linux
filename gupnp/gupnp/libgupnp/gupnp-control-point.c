/*
 * Copyright (C) 2006, 2007, 2008 OpenedHand Ltd.
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
 * SECTION:gupnp-control-point
 * @short_description: Class for resource discovery.
 *
 * #GUPnPControlPoint handles device and service discovery. After creating
 * a control point and activating it using gssdp_resource_browser_set_active(),
 * the ::device-proxy-available, ::service-proxy-available,
 * ::device-proxy-unavailable and ::service-proxy-unavailable signals will
 * be emitted whenever the availability of a device or service matching
 * the specified discovery target changes.
 */

#include <string.h>

#include "gupnp-control-point.h"
#include "gupnp-context-private.h"
#include "gupnp-resource-factory-private.h"
#include "http-headers.h"
#include "xml-util.h"

G_DEFINE_TYPE (GUPnPControlPoint,
               gupnp_control_point,
               GSSDP_TYPE_RESOURCE_BROWSER);

struct _GUPnPControlPointPrivate {
        GUPnPResourceFactory *factory;

        GList *devices;
        GList *services;

        GHashTable *doc_cache;

        GList *pending_gets;
};

enum {
        PROP_0,
        PROP_RESOURCE_FACTORY,
};

enum {
        DEVICE_PROXY_AVAILABLE,
        DEVICE_PROXY_UNAVAILABLE,
        SERVICE_PROXY_AVAILABLE,
        SERVICE_PROXY_UNAVAILABLE,
        SIGNAL_LAST
};

static guint signals[SIGNAL_LAST];

typedef struct {
        GUPnPControlPoint *control_point;

        char *udn;
        char *service_type;
        char *description_url;
        char *secure_description_url;

        SoupMessage *message;
} GetDescriptionURLData;

static void
get_description_url_data_free (GetDescriptionURLData *data)
{
        data->control_point->priv->pending_gets =
                g_list_remove (data->control_point->priv->pending_gets, data);

        g_free (data->udn);
        g_free (data->service_type);
        g_free (data->description_url);

        g_slice_free (GetDescriptionURLData, data);
}

static void
gupnp_control_point_init (GUPnPControlPoint *control_point)
{
        control_point->priv =
                G_TYPE_INSTANCE_GET_PRIVATE (control_point,
                                             GUPNP_TYPE_CONTROL_POINT,
                                             GUPnPControlPointPrivate);

        control_point->priv->doc_cache =
                g_hash_table_new_full (g_str_hash,
                                       g_str_equal,
                                       g_free,
                                       NULL);
}

/* Return TRUE if value == user_data */
static gboolean
find_doc (gpointer key,
          gpointer value,
          gpointer user_data)
{
        return (value == user_data);
}

/* xmlDoc wrapper finalized */
static void
doc_finalized (gpointer user_data,
               GObject *where_the_object_was)
{
        GUPnPControlPoint *control_point;

        control_point = GUPNP_CONTROL_POINT (user_data);

        g_hash_table_foreach_remove (control_point->priv->doc_cache,
                                     find_doc,
                                     where_the_object_was);
}

/* Release weak reference on xmlDoc wrapper */
static void
weak_unref_doc (gpointer key,
                gpointer value,
                gpointer user_data)
{
        g_object_weak_unref (G_OBJECT (value), doc_finalized, user_data);
}

static void
gupnp_control_point_dispose (GObject *object)
{
        GUPnPControlPoint *control_point;
        GObjectClass *object_class;

        control_point = GUPNP_CONTROL_POINT (object);

        if (control_point->priv->factory) {
                g_object_unref (control_point->priv->factory);
                control_point->priv->factory = NULL;
        }

        while (control_point->priv->devices) {
                // Remove SSL here
                GUPnPDeviceInfo *info;
                GUPnPDeviceProxy *proxy;

                info = GUPNP_DEVICE_INFO (control_point->priv->devices->data);
                proxy = GUPNP_DEVICE_PROXY (info);

                /* delete SSL client */
                ssl_finish_client( gupnp_device_proxy_get_ssl_client(proxy) );

                g_object_unref (proxy);

                g_object_unref (control_point->priv->devices->data);
                control_point->priv->devices =
                        g_list_delete_link (control_point->priv->devices,
                                            control_point->priv->devices);
        }

        while (control_point->priv->services) {
                g_object_unref (control_point->priv->services->data);
                control_point->priv->services =
                        g_list_delete_link (control_point->priv->services,
                                            control_point->priv->services);
        }

        /* Cancel any pending description file GETs */
        while (control_point->priv->pending_gets) {
                GetDescriptionURLData *data;
                GUPnPContext *context;
                SoupSession *session;

                data = control_point->priv->pending_gets->data;

                context = gupnp_control_point_get_context (control_point);
                session = gupnp_context_get_session (context);

                soup_session_cancel_message (session,
                                             data->message,
                                             SOUP_STATUS_CANCELLED);

                get_description_url_data_free (data);
        }

        /* Release weak references on remaining cached documents */
        g_hash_table_foreach (control_point->priv->doc_cache,
                              weak_unref_doc,
                              control_point);

        /* Call super */
        object_class = G_OBJECT_CLASS (gupnp_control_point_parent_class);
        object_class->dispose (object);
}

static void
gupnp_control_point_finalize (GObject *object)
{
        GUPnPControlPoint *control_point;
        GObjectClass *object_class;

        control_point = GUPNP_CONTROL_POINT (object);

        g_hash_table_destroy (control_point->priv->doc_cache);

        /* Call super */
        object_class = G_OBJECT_CLASS (gupnp_control_point_parent_class);
        object_class->finalize (object);
}


/* Search @element for matching services */
static void
process_service_list (xmlNode           *element,
                      GUPnPControlPoint *control_point,
                      XmlDocWrapper     *doc,
                      const char        *udn,
                      const char        *service_type,
                      const char        *description_url,
                      const char        *secure_description_url,
                      SoupURI           *url_base,
                      SoupURI           *secure_url_base)
{
        for (element = element->children; element; element = element->next) {
                xmlChar *prop;
                gboolean match;
                GUPnPContext *context;
                GUPnPServiceProxy *proxy;

                if (strcmp ((char *) element->name, "service") != 0)
                        continue;

                /* See if this is a matching service */
                prop = xml_util_get_child_element_content (element,
                                                           "serviceType");
                if (!prop)
                        continue;

                match = (strcmp ((char *) prop, service_type) == 0);

                xmlFree (prop);

                if (!match)
                        continue;

                /* Match */

                /* Get context */
                context = gupnp_control_point_get_context (control_point);

                /* Create proxy */
                proxy = gupnp_resource_factory_create_service_proxy
                                                 (control_point->priv->factory,
                                                  context,
                                                  doc,
                                                  element,
                                                  udn,
                                                  service_type,
                                                  description_url,
                                                  secure_description_url,
                                                  url_base,
                                                  secure_url_base);

                control_point->priv->services =
                        g_list_prepend (control_point->priv->services,
                                        proxy);

                g_signal_emit (control_point,
                               signals[SERVICE_PROXY_AVAILABLE],
                               0,
                               proxy);
        }
}

/* Recursively search @element for matching devices */
static void
process_device_list (xmlNode           *element,
                     GUPnPControlPoint *control_point,
                     GUPnPSSLClient    **client,
                     GUPnPDeviceProxy  *root_proxy,
                     XmlDocWrapper     *doc,
                     const char        *udn,
                     const char        *service_type,
                     const char        *description_url,
                     const char        *secure_description_url,
                     SoupURI           *url_base,
                     SoupURI           *secure_url_base)
{ 
        for (element = element->children; element; element = element->next) {
                xmlNode *children;
                xmlChar *prop;
                gboolean match;
                GUPnPContext *context;

                if (strcmp ((char *) element->name, "device") != 0)
                        continue;

                /* Recurse into children */
                children = xml_util_get_element (element,
                                                 "deviceList",
                                                 NULL);

                if (children) {
                        process_device_list (children,
                                             control_point,
                                             client,
                                             root_proxy,
                                             doc,
                                             udn,
                                             service_type,
                                             description_url,
                                             secure_description_url,
                                             url_base,
                                             secure_url_base);
                }

                /* See if this is a matching device */
                prop = xml_util_get_child_element_content (element, "UDN");
                if (!prop)
                        continue;

                match = (strcmp ((char *) prop, udn) == 0);

                xmlFree (prop);

                if (!match)
                        continue;

                /* Match */

                /* Get context */
                context = gupnp_control_point_get_context (control_point);

                if (service_type) {
                        /* Dive into serviceList */
                        children = xml_util_get_element (element,
                                                         "serviceList",
                                                         NULL);

                        if (children) {
                                process_service_list (children,
                                                      control_point,
                                                      doc,
                                                      udn,
                                                      service_type,
                                                      description_url,
                                                      secure_description_url,
                                                      url_base,
                                                      secure_url_base);
                        }
                } else {
                        /* Create device proxy */
                        GUPnPDeviceProxy *proxy;

                        proxy = gupnp_resource_factory_create_device_proxy
                                        (control_point->priv->factory,
                                         context,
                                         doc,
                                         element,
                                         udn,
                                         description_url,
                                         secure_description_url,
                                         url_base,
                                         secure_url_base);

                        control_point->priv->devices =
                                g_list_prepend
                                        (control_point->priv->devices,
                                         proxy);

                        g_signal_emit (control_point,
                                       signals[DEVICE_PROXY_AVAILABLE],
                                       0,
                                       proxy);

                        // set SSL client for proxy
                        if (client != NULL && *client != NULL)
                            gupnp_device_proxy_set_ssl_client(proxy, *client);

                        if (root_proxy == NULL)
                            root_proxy = proxy;

                        // set root_proxy to proxy
                        gupnp_device_proxy_set_root_proxy(proxy, root_proxy);
                }
        }
}

/*
 * Called when the description document is loaded.
 */
static void
description_loaded (GUPnPControlPoint *control_point,
                    XmlDocWrapper     *doc,
                    const char        *udn,
                    const char        *service_type,
                    const char        *description_url,
                    const char        *secure_description_url,
                    GUPnPSSLClient    **client)
{
        xmlNode *element;
        SoupURI *url_base;
        SoupURI *secure_url_base;

        /* Save the URL base, if any */
        element = xml_util_get_element ((xmlNode *) doc->doc,
                                        "root",
                                        NULL);

        url_base = xml_util_get_child_element_content_uri (element,
                                                           "URLBase",
                                                           NULL);
        if (!url_base)
                url_base = soup_uri_new (description_url);

        secure_url_base = soup_uri_new (secure_description_url);

        /* Iterate matching devices */
        process_device_list (element,
                             control_point,
                             client,
                             NULL,
                             doc,
                             udn,
                             service_type,
                             description_url,
                             secure_description_url,
                             url_base,
                             secure_url_base);

        /* Cleanup */
        soup_uri_free (url_base);
        soup_uri_free (secure_url_base);
}

/*
 * Description URL downloaded.
 */
static void
got_description_url (SoupSession           *session,
                     SoupMessage           *msg,
                     GetDescriptionURLData *data)
{
        XmlDocWrapper *doc;

        if (msg->status_code == SOUP_STATUS_CANCELLED)
                return;

        /* Now, make sure again this document is not already cached. If it is,
         * we re-use the cached one. */
        doc = g_hash_table_lookup (data->control_point->priv->doc_cache,
                                   data->description_url);
        if (doc) {
                /* Doc was cached */
                description_loaded (data->control_point,
                                    doc,
                                    data->udn,
                                    data->service_type,
                                    data->description_url,
                                    data->secure_description_url,
                                    NULL);

                get_description_url_data_free (data);

                return;
        }

        /* Not cached */
        if (SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
                xmlDoc *xml_doc;

                /* Parse response */
                xml_doc = xmlRecoverMemory (msg->response_body->data,
                                            msg->response_body->length);
                if (xml_doc) {
                        doc = xml_doc_wrapper_new (xml_doc);

                        description_loaded (data->control_point,
                                            doc,
                                            data->udn,
                                            data->service_type,
                                            data->description_url,
                                            data->secure_description_url,
                                            NULL);

                        /* Insert into document cache */
                        g_hash_table_insert
                                          (data->control_point->priv->doc_cache,
                                           g_strdup (data->description_url),
                                           doc);

                        /* Make sure the document is removed from the cache
                         * once finalized. */
                        g_object_weak_ref (G_OBJECT (doc),
                                           doc_finalized,
                                           data->control_point);

                        /* If no proxy was created, make sure doc is freed. */
                        g_object_ref_sink (doc);
                        g_object_unref (doc);
                } else
                        g_warning ("Failed to parse %s", data->description_url);
        } else
                g_warning ("Failed to GET %s", data->description_url);

        get_description_url_data_free (data);
}

/*
 * Downloads and parses (or takes from cache) @description_url,
 * creating:
 *  - A #GUPnPDeviceProxy for the device specified by @udn if @service_type
 *    is %NULL.
 *  - A #GUPnPServiceProxy for the service of type @service_type from the device
 *    specified by @udn if @service_type is not %NULL.
 */
static void
load_description (GUPnPControlPoint *control_point,
                  const char        *description_url,
                  const char        *secure_description_url,
                  const char        *udn,
                  const char        *service_type)
{
        XmlDocWrapper *doc;

        doc = g_hash_table_lookup (control_point->priv->doc_cache,
                                   description_url);
        if (doc) {
                /* Doc was cached */
                description_loaded (control_point,
                                    doc,
                                    udn,
                                    service_type,
                                    description_url,
                                    secure_description_url,
                                    NULL);
        } else {
                /* Asynchronously download doc */
                GUPnPContext *context;
                SoupSession *session;
                GetDescriptionURLData *data;

                context = gupnp_control_point_get_context (control_point);

                session = gupnp_context_get_session (context);

                data = g_slice_new (GetDescriptionURLData);

                data->message = soup_message_new (SOUP_METHOD_GET,
                                                  description_url);
                if (data->message == NULL) {
                        g_warning ("Invalid description URL: %s",
                                   description_url);

                        g_slice_free (GetDescriptionURLData, data);

                        return;
                }

                http_request_set_user_agent (data->message);
                http_request_set_accept_language (data->message);

                data->control_point   = control_point;

                data->udn             = g_strdup (udn);
                data->service_type    = g_strdup (service_type);
                data->description_url = g_strdup (description_url);
                data->secure_description_url = g_strdup (secure_description_url);

                control_point->priv->pending_gets =
                        g_list_prepend (control_point->priv->pending_gets,
                                        data);

	        soup_session_queue_message (session,
                                            data->message,
                                            (SoupSessionCallback)
                                                   got_description_url,
                                            data);
        }
}


static void
secure_got_description_url (GUPnPSSLClient          **client,
                            SoupMessage             *msg,
                            gpointer                userdata)
{
        GetDescriptionURLData *data = userdata;        
        XmlDocWrapper *doc;

        if (msg->status_code == SOUP_STATUS_CANCELLED)
                return;
 
        /* Now, make sure again this document is not already cached. If it is,
         * we re-use the cached one. */
        doc = g_hash_table_lookup (data->control_point->priv->doc_cache,
                                   data->secure_description_url);
        if (doc) {
                /* Doc was cached */
                description_loaded (data->control_point,
                                    doc,
                                    data->udn,
                                    data->service_type,
                                    data->description_url,
                                    data->secure_description_url,
                                    client);

                get_description_url_data_free (data);

                return;
        }

        /* Not cached */
        if (SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
                xmlDoc *xml_doc;

                /* Parse response */
                xml_doc = xmlRecoverMemory (msg->response_body->data,
                                            msg->response_body->length);
                if (xml_doc) {
                        doc = xml_doc_wrapper_new (xml_doc);

                        description_loaded (data->control_point,
                                            doc,
                                            data->udn,
                                            data->service_type,
                                            data->description_url,
                                            data->secure_description_url,
                                            client);

                        /* Insert into document cache */
                        g_hash_table_insert
                                          (data->control_point->priv->doc_cache,
                                           g_strdup (data->secure_description_url),
                                           doc);

                        /* Make sure the document is removed from the cache
                         * once finalized. */
                        g_object_weak_ref (G_OBJECT (doc),
                                           doc_finalized,
                                           data->control_point);

                        /* If no proxy was created, make sure doc is freed. */
                        g_object_ref_sink (doc);
                        g_object_unref (doc);
                } else
                        g_warning ("Failed to parse %s", data->secure_description_url);
        } else
                g_warning ("Failed to GET %s", data->secure_description_url);

        get_description_url_data_free (data);
} 


/* Callback function set in soup_message_headers_foreach. Used for creating string form headers */ 
static void header_callback(const char *name,
                        const char *value,
                        gpointer user_data)
{
    if (user_data)
    {
        strcat((char *)user_data,name);
        strcat((char *)user_data,": ");
        strcat((char *)user_data,value); 
        strcat((char *)user_data,"\r\n");
    }
    //g_debug ("HEADER: %s: %s\nMESSAGE SO FAR: %s",name,value,(char *)user_data);
}

/* Create a string from SoupMessage. String contains headers and the body */
static int create_msg_string( SoupMessage *soupmsg, char *path, char *host, int port, char **full_message)
{
    char headers[1000] = "\0";
    char *http_version;

    if (soup_message_get_http_version(soupmsg) == SOUP_HTTP_1_1)
        http_version = "HTTP/1.1";
    else 
        http_version = "HTTP/1.0";
    // add GET and Host headers
    snprintf(headers,1000,"GET %s %s\r\nHost: %s:%d\r\n",path,http_version,host,port);

    soup_message_headers_foreach (soupmsg->request_headers, (SoupMessageHeadersForeachFunc)header_callback, headers);
    strcat(headers,"\r\n");

    *full_message = (char *)malloc(strlen(headers)+2);
    strcpy(*full_message, headers);

    //g_debug ("FULL MESSAGE:\n%s",*full_message);

    return 0;
}

/*
 * Downloads and parses (or takes from cache) @secure_description_url (https-address),
 * creating:
 *  - A #GUPnPSSLClient for the deviceproxy
 *  - A #GUPnPDeviceProxy for the device specified by @udn if @service_type
 *    is %NULL.
 *  - A #GUPnPServiceProxy for the service of type @service_type from the device
 *    specified by @udn if @service_type is not %NULL.
 * 
 * Downloading is done through SSL connection.
 */
static void
secure_load_description (GUPnPControlPoint *control_point,
                  const char        *description_url,
                  const char        *secure_description_url,
                  const char        *udn,
                  const char        *service_type)
{
        // create the SSL client
        int ret;
        GUPnPSSLClient *ssl_client = NULL;

        // get home dir
        const char *homedir = g_getenv ("HOME");
        if (!homedir)
            homedir = g_get_home_dir ();

        char *fullCertStore = g_build_path(G_DIR_SEPARATOR_S, homedir, GUPNP_CERT_STORE, NULL);

        ret = ssl_init_client(&ssl_client, fullCertStore ,NULL,NULL,NULL,NULL, GUPNP_CERT_CN);
        g_free(fullCertStore);
        if (ret != 0)
        {
            g_warning("Failed init SSL client");
            return;
        }

        // create SSL session (connection to server)
        ret = ssl_create_client_session(&ssl_client, secure_description_url, NULL, NULL);
        if (ret != 0)
        {
            g_warning("Failed create SSL session to '%s'",secure_description_url);
            return;
        }

        XmlDocWrapper *doc;

        doc = g_hash_table_lookup (control_point->priv->doc_cache,
                                   secure_description_url);
        if (doc) {
        	    /* Doc was cached */
                description_loaded (control_point,
                                    doc,
                                    udn,
                                    service_type,
                                    description_url,
                                    secure_description_url,
                                    &ssl_client);
       } else {
                /* Asynchronously download doc */
                GUPnPContext *context;
                SoupSession *session;
                GetDescriptionURLData *data;

                context = gupnp_control_point_get_context (control_point);

                session = gupnp_context_get_session (context);

                data = g_slice_new (GetDescriptionURLData);

                data->message = soup_message_new (SOUP_METHOD_GET,
                                                  secure_description_url);
                if (data->message == NULL) {
                        g_warning ("Invalid description URL: %s",
                                   secure_description_url);

                        g_slice_free (GetDescriptionURLData, data);

                        return;
                }

                http_request_set_user_agent (data->message);
                http_request_set_accept_language (data->message);

                data->control_point   = control_point;

                data->udn             = g_strdup (udn);
                data->service_type    = g_strdup (service_type);
                data->description_url = g_strdup (description_url);
                data->secure_description_url = g_strdup (secure_description_url);

                control_point->priv->pending_gets =
                        g_list_prepend (control_point->priv->pending_gets,
                                        data);

                // Create SoupURI from description url. It is easy to get host, port and path values 
                // to message from SoupURI
                SoupURI *uri;
                uri = soup_uri_new (secure_description_url);

                // create message string which is send to server (GET-message)  char *path, char *host, int port,
                char *message;
                create_msg_string( data->message, uri->path, uri->host, uri->port, &message);
                soup_uri_free (uri);

                // send the message
                ssl_client_send_and_receive(&ssl_client, message, data->message, 
                                            (GUPnPSSLClientCallback)secure_got_description_url, data);
        }
}

static gboolean
parse_usn (const char *usn,
           char      **udn,
           char      **service_type)
{
        gboolean ret;
        char **bits;
        guint count, i;

        ret = FALSE;

        *udn = *service_type = NULL;

        /* Verify we have a valid USN */
        if (strncmp (usn, "uuid:", strlen ("uuid:"))) {
                g_warning ("Invalid USN: %s", usn);

                return FALSE;
        }

        /* Parse USN */
        bits = g_strsplit (usn, "::", -1);

        /* Count elements */
        for (count = 0; bits[count]; count++);

        if (count == 1) {
                /* uuid:device-UUID */

                *udn = bits[0];

                ret = TRUE;

        } else if (count == 2) {
                char **second_bits;

                second_bits = g_strsplit (bits[1], ":", -1);

                if (!strcmp (second_bits[0], "upnp") &&
                    !strcmp (second_bits[1], "rootdevice")) {
                        /* uuid:device-UUID::upnp:rootdevice */

                        *udn = bits[0];

                        ret = TRUE;
                } else if (!strcmp (second_bits[0], "urn")) {
                        /* uuid:device-UIID::urn:domain-name:service/device:
                         * type:v */

                        if (!strcmp (second_bits[2], "device")) {
                                *udn = bits[0];

                                ret = TRUE;
                        } else if (!strcmp (second_bits[2], "service")) {
                                *udn = bits[0];
                                *service_type = bits[1];

                                ret = TRUE;
                        }
                }

                g_strfreev (second_bits);
        }

        if (*udn == NULL)
                g_warning ("Invalid USN: %s", usn);

        for (i = 0; i < count; i++) {
                if ((bits[i] != *udn) &&
                    (bits[i] != *service_type))
                        g_free (bits[i]);
        }

        g_free (bits);

        return ret;
}

/* This is not used anymore. Replaced by gupnp_control_point_secure_resource_available 
static void
gupnp_control_point_resource_available (GSSDPResourceBrowser *resource_browser,
                                        const char           *usn,
                                        const GList          *locations)
{
        GUPnPControlPoint *control_point;
        char *udn, *service_type;

        control_point = GUPNP_CONTROL_POINT (resource_browser);

        // Verify we have a location
        if (!locations) {
                g_warning ("No Location header for device with USN %s", usn);
                return;
        }

        // Parse USN 
        if (!parse_usn (usn, &udn, &service_type))
                return;

        load_description (control_point,
                          locations->data,
                          udn,
                          service_type);

        g_free (udn);
        g_free (service_type);
}*/

static void
gupnp_control_point_secure_resource_available (GSSDPResourceBrowser *resource_browser,
                                        const char           *usn,
                                        const GList          *locations,
                                        const GList          *secure_locations)
{
        GUPnPControlPoint *control_point;
        char *udn, *service_type, *url = NULL, *securl = NULL;

        control_point = GUPNP_CONTROL_POINT (resource_browser);

        /* Parse USN */
        if (!parse_usn (usn, &udn, &service_type))
                return;

        /* Verify we have a secure location (https address) 
         * Try to use locations if secure_locations is not found.
         */
        if (!secure_locations && !locations) {
                g_warning ("No SECURELOCATION.UPNP.ORG or LOCATION header for device with USN %s", usn);
                return;
        }

        if (secure_locations) securl = secure_locations->data;
        if (locations) url = locations->data;

        if (secure_locations) {
                secure_load_description (control_point,
                                         url,
                                         securl,
                                         udn,
                                         service_type);
        } else if (locations) {
                load_description (control_point,
                                  url,
                                  securl,
                                  udn,
                                  service_type);
        }

        g_free (udn);
        g_free (service_type);
}

static void
gupnp_control_point_resource_unavailable
                                (GSSDPResourceBrowser *resource_browser,
                                 const char           *usn)
{
        GUPnPControlPoint *control_point;
        char *udn, *service_type;
        GList *l, *cur_l;

        control_point = GUPNP_CONTROL_POINT (resource_browser);

        /* Parse USN */
        if (!parse_usn (usn, &udn, &service_type))
                return;

        /* Find proxy */
        if (service_type) {
                l = control_point->priv->services;

                while (l) {
                        GUPnPServiceInfo *info;
                        GUPnPServiceProxy *proxy;

                        info = GUPNP_SERVICE_INFO (l->data);

                        if ((strcmp (udn,
                                     gupnp_service_info_get_udn (info)) != 0) ||
                            (strcmp (service_type,
                                     gupnp_service_info_get_service_type (info))
                                     != 0)) {
                                l = l->next;

                                continue;
                        }

                        /* Remove proxy */
                        proxy = GUPNP_SERVICE_PROXY (info);

                        cur_l = l;
                        l = l->next;

                        control_point->priv->services =
                                g_list_delete_link
                                        (control_point->priv->services, cur_l);

                        g_signal_emit (control_point,
                                       signals[SERVICE_PROXY_UNAVAILABLE],
                                       0,
                                       proxy);

                        g_object_unref (proxy);
                }
        } else {
                l = control_point->priv->devices;

                while (l) {
                        GUPnPDeviceInfo *info;
                        GUPnPDeviceProxy *proxy;

                        info = GUPNP_DEVICE_INFO (l->data);

                        if (strcmp (udn,
                                    gupnp_device_info_get_udn (info)) != 0) {
                                l = l->next;

                                continue;
                        }

                        /* Remove proxy */
                        proxy = GUPNP_DEVICE_PROXY (info);

                        /* delete SSL client */
                        ssl_finish_client( gupnp_device_proxy_get_ssl_client(proxy) );

                        cur_l = l;
                        l = l->next;

                        control_point->priv->devices =
                                 g_list_delete_link
                                        (control_point->priv->devices, cur_l);

                        g_signal_emit (control_point,
                                       signals[DEVICE_PROXY_UNAVAILABLE],
                                       0,
                                       proxy);

                        g_object_unref (proxy);
                }
        }

        g_free (udn);
        g_free (service_type);
}

static void
gupnp_control_point_set_property (GObject      *object,
                                  guint         property_id,
                                  const GValue *value,
                                  GParamSpec   *pspec)
{
        GUPnPControlPoint *control_point;

        control_point = GUPNP_CONTROL_POINT (object);

        switch (property_id) {
        case PROP_RESOURCE_FACTORY:
                control_point->priv->factory = GUPNP_RESOURCE_FACTORY (g_value_dup_object (value));
                break;
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
                break;
        }
}

static void
gupnp_control_point_get_property (GObject    *object,
                                  guint       property_id,
                                  GValue     *value,
                                  GParamSpec *pspec)
{
        GUPnPControlPoint *control_point;

        control_point = GUPNP_CONTROL_POINT (object);

        switch (property_id) {
        case PROP_RESOURCE_FACTORY:
                g_value_set_object (value, control_point->priv->factory);
                break;
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
                break;
        }
}

static void
gupnp_control_point_class_init (GUPnPControlPointClass *klass)
{
        GObjectClass *object_class;
        GSSDPResourceBrowserClass *browser_class;

        object_class = G_OBJECT_CLASS (klass);

        object_class->set_property = gupnp_control_point_set_property;
        object_class->get_property = gupnp_control_point_get_property;
        object_class->dispose      = gupnp_control_point_dispose;
        object_class->finalize     = gupnp_control_point_finalize;

        browser_class = GSSDP_RESOURCE_BROWSER_CLASS (klass);

        // We are no longer interested in this event, because secure_resource_available gives the non-secure url also
        //browser_class->resource_available =
        //        gupnp_control_point_resource_available;
        browser_class->secure_resource_available =
                        gupnp_control_point_secure_resource_available;
        browser_class->resource_unavailable =
                gupnp_control_point_resource_unavailable;

        g_type_class_add_private (klass, sizeof (GUPnPControlPointPrivate));

        /**
         * GUPnPControlPoint:resource-factory
         *
         * The resource factory to use. Set to NULL for default factory.
         **/
        g_object_class_install_property
                (object_class,
                 PROP_RESOURCE_FACTORY,
                 g_param_spec_object ("resource-factory",
                                      "Resource Factory",
                                      "The resource factory to use",
                                      GUPNP_TYPE_RESOURCE_FACTORY,
                                      G_PARAM_CONSTRUCT_ONLY |
                                      G_PARAM_READWRITE |
                                      G_PARAM_STATIC_NAME |
                                      G_PARAM_STATIC_NICK |
                                      G_PARAM_STATIC_BLURB));

        /**
         * GUPnPControlPoint::device-proxy-available
         * @control_point: The #GUPnPControlPoint that received the signal
         * @proxy: The now available #GUPnPDeviceProxy
         *
         * The ::device-proxy-available signal is emitted whenever a new
         * device has become available.
         **/
        signals[DEVICE_PROXY_AVAILABLE] =
                g_signal_new ("device-proxy-available",
                              GUPNP_TYPE_CONTROL_POINT,
                              G_SIGNAL_RUN_LAST,
                              G_STRUCT_OFFSET (GUPnPControlPointClass,
                                               device_proxy_available),
                              NULL,
                              NULL,
                              g_cclosure_marshal_VOID__OBJECT,
                              G_TYPE_NONE,
                              1,
                              GUPNP_TYPE_DEVICE_PROXY);

        /**
         * GUPnPControlPoint::device-proxy-unavailable
         * @control_point: The #GUPnPControlPoint that received the signal
         * @proxy: The now unavailable #GUPnPDeviceProxy
         *
         * The ::device-proxy-unavailable signal is emitted whenever a
         * device is not available any more.
         **/
        signals[DEVICE_PROXY_UNAVAILABLE] =
                g_signal_new ("device-proxy-unavailable",
                              GUPNP_TYPE_CONTROL_POINT,
                              G_SIGNAL_RUN_LAST,
                              G_STRUCT_OFFSET (GUPnPControlPointClass,
                                               device_proxy_unavailable),
                              NULL,
                              NULL,
                              g_cclosure_marshal_VOID__OBJECT,
                              G_TYPE_NONE,
                              1,
                              GUPNP_TYPE_DEVICE_PROXY);

        /**
         * GUPnPControlPoint::service-proxy-available
         * @control_point: The #GUPnPControlPoint that received the signal
         * @proxy: The now available #GUPnPServiceProxy
         *
         * The ::service-proxy-available signal is emitted whenever a new
         * service has become available.
         **/
        signals[SERVICE_PROXY_AVAILABLE] =
                g_signal_new ("service-proxy-available",
                              GUPNP_TYPE_CONTROL_POINT,
                              G_SIGNAL_RUN_LAST,
                              G_STRUCT_OFFSET (GUPnPControlPointClass,
                                               service_proxy_available),
                              NULL,
                              NULL,
                              g_cclosure_marshal_VOID__OBJECT,
                              G_TYPE_NONE,
                              1,
                              GUPNP_TYPE_SERVICE_PROXY);

        /**
         * GUPnPControlPoint::service-proxy-unavailable
         * @control_point: The #GUPnPControlPoint that received the signal
         * @proxy: The now unavailable #GUPnPServiceProxy
         *
         * The ::service-proxy-unavailable signal is emitted whenever a
         * service is not available any more.
         **/
        signals[SERVICE_PROXY_UNAVAILABLE] =
                g_signal_new ("service-proxy-unavailable",
                              GUPNP_TYPE_CONTROL_POINT,
                              G_SIGNAL_RUN_LAST,
                              G_STRUCT_OFFSET (GUPnPControlPointClass,
                                               service_proxy_unavailable),
                              NULL,
                              NULL,
                              g_cclosure_marshal_VOID__OBJECT,
                              G_TYPE_NONE,
                              1,
                              GUPNP_TYPE_SERVICE_PROXY);
}

/**
 * gupnp_control_point_new
 * @context: A #GUPnPContext
 * @target: The search target
 *
 * Create a new #GUPnPControlPoint with the specified @context and @target.
 *
 * @target should be a service or device name, such as
 * <literal>urn:schemas-upnp-org:service:WANIPConnection:1</literal> or
 * <literal>urn:schemas-upnp-org:device:MediaRenderer:1</literal>.
 *
 * Return value: A new #GUPnPControlPoint object.
 **/
GUPnPControlPoint *
gupnp_control_point_new (GUPnPContext *context,
                         const char   *target)
{
        GUPnPResourceFactory *factory;

        factory = gupnp_resource_factory_get_default ();

        return gupnp_control_point_new_full (context,
                                             factory,
                                             target);
}

/**
 * gupnp_control_point_new_full
 * @context: A #GUPnPContext
 * @factory: A #GUPnPResourceFactory
 * @target: The search target
 *
 * Create a new #GUPnPControlPoint with the specified @context, @factory and
 * @target.
 *
 * @target should be a service or device name, such as
 * <literal>urn:schemas-upnp-org:service:WANIPConnection:1</literal> or
 * <literal>urn:schemas-upnp-org:device:MediaRenderer:1</literal>.
 *
 * Return value: A new #GUPnPControlPoint object.
 **/
GUPnPControlPoint *
gupnp_control_point_new_full (GUPnPContext         *context,
                              GUPnPResourceFactory *factory,
                              const char           *target)
{
        g_return_val_if_fail (GUPNP_IS_CONTEXT (context), NULL);
        g_return_val_if_fail (GUPNP_IS_RESOURCE_FACTORY (factory), NULL);
        g_return_val_if_fail (target, NULL);

        return g_object_new (GUPNP_TYPE_CONTROL_POINT,
                             "client", context,
                             "target", target,
                             "resource-factory", factory,
                             NULL);
}

/**
 * gupnp_control_point_get_context
 * @control_point: A #GUPnPControlPoint
 *
 * Get the #GUPnPControlPoint associated with @control_point.
 *
 * Return value: The #GUPnPContext.
 **/
GUPnPContext *
gupnp_control_point_get_context (GUPnPControlPoint *control_point)
{
        GSSDPClient *client;

        g_return_val_if_fail (GUPNP_IS_CONTROL_POINT (control_point), NULL);

        client = gssdp_resource_browser_get_client
                                (GSSDP_RESOURCE_BROWSER (control_point));

        return GUPNP_CONTEXT (client);
}

/**
 * gupnp_control_point_list_device_proxies
 * @control_point: A #GUPnPControlPoint
 *
 * Get the #GList of discovered #GUPnPDeviceProxy objects. Do not free the list
 * nor its elements.
 *
 * Return value: a #GList of #GUPnPDeviceProxy objects.
 **/
const GList *
gupnp_control_point_list_device_proxies (GUPnPControlPoint *control_point)
{
        g_return_val_if_fail (GUPNP_IS_CONTROL_POINT (control_point), NULL);

        return (const GList *) control_point->priv->devices;
}

/**
 * gupnp_control_point_list_service_proxies
 * @control_point: A #GUPnPControlPoint
 *
 * Get the #GList of discovered #GUPnPServiceProxy objects. Do not free the list
 * nor its elements.
 *
 * Return value: a #GList of #GUPnPServiceProxy objects.
 **/
const GList *
gupnp_control_point_list_service_proxies (GUPnPControlPoint *control_point)
{
        g_return_val_if_fail (GUPNP_IS_CONTROL_POINT (control_point), NULL);

        return (const GList *) control_point->priv->services;
}

/**
 * gupnp_control_point_get_resource_factory
 * @control_point: A #GUPnPControlPoint
 *
 * Get the #GUPnPResourceFactory used by the @control_point.
 *
 * Return value: A #GUPnPResourceFactory.
 **/
GUPnPResourceFactory *
gupnp_control_point_get_resource_factory (GUPnPControlPoint *control_point)
{
        g_return_val_if_fail (GUPNP_IS_CONTROL_POINT (control_point), NULL);

        return control_point->priv->factory;
}
