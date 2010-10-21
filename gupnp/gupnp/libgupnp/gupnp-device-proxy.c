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

/* This file is part of Nokia Device Protection service
 *
 * Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
 *
 * Contact:  Nokia Corporation: Mika.saaranen@nokia.com
 *
 * This file may be used under the terms of the GNU Lesser General Public License version 2.1,
 * a copy of which is found in COPYING included in the packaging of this file.
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

#include "gupnp-device-proxy.h"
#include "gupnp-device-info-private.h"
#include "gupnp-resource-factory-private.h"
#include "xml-util.h"
#include "pki.h"

#define	DEBUG(args) (printf("DEBUG: "), printf args)

/* hostapd & WPA specifics */
#include	<hostap/hostapd_iface.h>
#include	"./libgupnp/crypt.h"

extern const char * wps_message_type_name( int type );

typedef enum {  WPA_SM_R_PROCESS,         WPA_SM_R_SUCCESS,        WPA_SM_R_SUCCESSINFO,
                WPA_SM_R_FAILURE,         WPA_SM_R_FAILUREEXIT,	   WPA_SM_R_PASS_HANDLING
} wpa_registrar_sm_status; /* if WPA_SM_R_SUCCESS, SM can exit after sending any pending messages */

G_DEFINE_TYPE (GUPnPDeviceProxy,
               gupnp_device_proxy,
               GUPNP_TYPE_DEVICE_INFO);

struct _GUPnPDeviceProxyPrivate {
        GUPnPDeviceProxy *root_proxy;

        GUPnPSSLClient *ssl_client; // this is used for SSL connections
        GString *username;          // stores username which is logged in for this deviceproxy

        unsigned char *cp_uuid;
        unsigned char *device_uuid;
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

        unsigned char     *wpa_registrar_send_msg;
        int                wpa_registrar_send_msg_len;
        unsigned char      *uuid;
        size_t             uuid_len;
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

struct _GUPnPDeviceProxyChangePassword {
        GUPnPDeviceProxy  *proxy;
        GUPnPServiceProxy *device_prot_service;

        GUPnPDeviceProxyChangePasswordCallback callback;

        gpointer user_data;

        GError *error;

        GString *username;
        GString *password;

        GString *salt;
        GString *stored;

        gboolean done;
};

struct _GUPnPDeviceProxyAddUser {
        GUPnPDeviceProxy  *proxy;
        GUPnPServiceProxy *device_prot_service;

        GUPnPDeviceProxyAddUserCallback callback;

        gpointer user_data;

        GError *error;

        GString *username;
        GString *password;
        GString *identitylist;

        gboolean done;
};

struct _GUPnPDeviceProxyRemoveUser {
        GUPnPDeviceProxy  *proxy;
        GUPnPServiceProxy *device_prot_service;

        GUPnPDeviceProxyRemoveUserCallback callback;

        gpointer user_data;

        GError *error;

        GString *username;
        GString *identity;

        gboolean done;
};


struct _GUPnPDeviceProxySetRoles {
        GUPnPDeviceProxy  *proxy;
        GUPnPServiceProxy *device_prot_service;

        GUPnPDeviceProxySetRolesCallback callback;

        gpointer user_data;

        GError *error;

        GString *username;
        GString *identity;
        GString *rolelist;

        gboolean done;
};

struct _GUPnPDeviceProxyGetACLData {
        GUPnPDeviceProxy  *proxy;
        GUPnPServiceProxy *device_prot_service;

        GUPnPDeviceProxyGetACLDataCallback callback;

        gpointer user_data;

        GError *error;

        XmlDocWrapper *ACL;
        //GHashTable *users; // username as key, roles as value

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
        const char           *location, *secure_location;
        const SoupURI        *url_base;
        const SoupURI        *secure_url_base;

        proxy = GUPNP_DEVICE_PROXY (info);

        factory = gupnp_device_info_get_resource_factory (info);
        context = gupnp_device_info_get_context (info);
        doc = _gupnp_device_info_get_document (info);
        location = gupnp_device_info_get_location (info);
        secure_location = gupnp_device_info_get_secure_location (info);
        url_base = gupnp_device_info_get_url_base (info);
        secure_url_base = gupnp_device_info_get_secure_url_base (info);

        device = gupnp_resource_factory_create_device_proxy (factory,
                                                             context,
                                                             doc,
                                                             element,
                                                             NULL,
                                                             location,
                                                             secure_location,
                                                             url_base,
                                                             secure_url_base);

        if (device) {
            // Add root deviceproxy information for new proxy
            // if older proxy here ('proxy'), doesn't already have root_proxy defined,
            // then it is the root_proxy for 'device'
            // (actually I'm not 100% sure if this root_proxy is even the root, or is it the
            // last leaf proxy. But it works at least if there are most of 3 levels of devices.
            if (proxy->priv->root_proxy)
                gupnp_device_proxy_set_root_proxy(device,proxy->priv->root_proxy);
            else
                gupnp_device_proxy_set_root_proxy(device,proxy);
        }


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
        const char           *location, *secure_location, *udn;
        const SoupURI        *url_base;
        const SoupURI        *secure_url_base;

        proxy = GUPNP_DEVICE_PROXY (info);

        factory = gupnp_device_info_get_resource_factory (info);
        context = gupnp_device_info_get_context (info);
        doc = _gupnp_device_info_get_document (info);
        udn = gupnp_device_info_get_udn (info);
        location = gupnp_device_info_get_location (info);
        secure_location = gupnp_device_info_get_secure_location (info);
        url_base = gupnp_device_info_get_url_base (info);
        secure_url_base = gupnp_device_info_get_secure_url_base (info);

        service = gupnp_resource_factory_create_service_proxy (factory,
                                                               context,
                                                               doc,
                                                               element,
                                                               udn,
                                                               NULL,
                                                               location,
                                                               secure_location,
                                                               url_base,
                                                               secure_url_base);

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
        proxy->priv->username = g_string_new("");
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

#if 0
int setup_ready_value;

static void
setup_ready_cb (GUPnPServiceProxy *proxy,
				const char        *variable,
				GValue            *value,
				gpointer           user_data )
{
        GValue	bool_value;

		memset (&bool_value, 0, sizeof (GValue));		// transfer event value to local var.
        g_value_init (&bool_value, G_TYPE_BOOLEAN);
        g_value_transform (value, &bool_value);

		setup_ready_value = (int)g_value_get_boolean( &bool_value);
		hostapd_printf("%s: %s event with value = %s received", __func__, variable, ( setup_ready_value ) ? "TRUE" : "FALSE" );
}
#endif

#if 0
#define PBC_WALK_TIME	10	// in seconds

int pbc_button_wait_handling( GUPnPServiceProxy		*proxy,
                              GUPnPDeviceProxyWps	*wps )
{
	int i, return_value = -1;
	
	if ( wps->method == GUPNP_DEVICE_WPS_METHOD_PUSHBUTTON )
	{
	  hostapd_printf("%s: received WPS_NACK & method == PUSH-BUTTON", __func__ );
	  // TODO : Here we need to wait max. 120 seconds for SetupReady == TRUE
	  //        and after that continue WPS-handshaking with M2 -message

		//gupnp_service_proxy_add_notify(	proxy,		/* add notification-callback for SetupReady occurance in receive */
		//								  "SetupReady",
		//								  G_TYPE_BOOLEAN,
		//								  setup_ready_cb,
		//								  NULL);

	  setup_ready_value = -1;	// say this is an initialization

      GUPnPContext *context;
      GMainContext *main_context;
      GMainLoop *main_loop;

	  context = gupnp_service_info_get_context (GUPNP_SERVICE_INFO (proxy));
      main_context = gssdp_client_get_main_context (GSSDP_CLIENT (context));
      main_loop = g_main_loop_new (main_context, TRUE);
	  hostapd_printf("%s: main_loop context = 0x%p", __func__, main_loop );	// TEST
	  for ( i = 0; i < PBC_WALK_TIME; i++ )
	  {
        /* Loop till we get a reply (or time out) */
        if (g_main_loop_is_running (main_loop))	// run the main-loop cause the event-receive expects that
          g_main_loop_run (main_loop);
		if ( setup_ready_value != -1 )
		{
		  hostapd_printf("%s: SetupReady event detected", __func__ );
		  return_value = setup_ready_value;
		  break;
		}
		hostapd_sleep( 10 );	// 1 second sleep
	  }
	  hostapd_printf("%s: end-of-waiting SetupReady -event", __func__ );
	  setup_ready_value = TRUE; // TEST
      g_main_loop_unref (main_loop);
      g_main_loop_quit (main_loop);

	}
	else	// NACK, but method is not PBC .... assuming PIN
	{
	  hostapd_printf("%s: NACK, but method is not PBC .... assuming PIN");
	}
	return( return_value );
}
#endif

#define	MAX_PIN_LENGTH	10

//      ----------- prototypes ---------
//void
//wps_pin_invocation( GUPnPDeviceProxyWps *deviceProxyWps,
//					char *pin_code );
void
gupnp_device_proxy_continue_wps (GUPnPDeviceProxyWps        *wps,
                                 GString                    *pin,
								 GUPnPDeviceProxyWpsCallback callback,
                                 gpointer                    user_data);
#if 0
void (*wps_pin_dialog_cb)(void *, void *);

void gupnp_device_proxy_set_pin_dialog_cb( void (*wps_pin_dialog) )
{
	wps_pin_dialog_cb = wps_pin_dialog;	// save callback for later use
}

int pin_wait_handling( GUPnPServiceProxy		*proxy,
                       GUPnPDeviceProxyWps		*wps )
{
	int return_value = -1;
	char	device_pin[ MAX_PIN_LENGTH ];
	GString *dev_pin;

	if ( wps->method == GUPNP_DEVICE_WPS_METHOD_PIN )
	{
		hostapd_printf("%s: received WPS_ACK & method == PIN", __func__ );
		// TODO : Here we need to wait max. 120 seconds ( timeout needed ?? ) for User to input the PIN-code
		//        transferred out-of-band from Device and after that continue WPS-handshaking with M2 -message
		//        We need a call-back dialog to ask user for PIN code... what else ??

	  wps_pin_dialog_cb();	// ask PIN from User and continue
	  dev_pin = g_string_new( device_pin );
	  gupnp_device_proxy_continue_wps (			// continue WPS: messages M2...M8
						wps,
						dev_pin,
						NULL,
						NULL );
	}
	return( return_value );
}
#endif
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

/* this is in 'wps_dialog.c' */
//extern void on_state_variable_changed_setup_ready( GUPnPServiceProxy *proxy, char * str_value);

static void
wps_got_response (GUPnPServiceProxy       *proxy,
                  GUPnPServiceProxyAction *action,
                  gpointer                 user_data)
{
        GUPnPDeviceProxyWps *wps = user_data;
        char *out_message;
        GError *error = NULL;
        int err;
        int status;

		hostapd_printf("%s:start: something received from SSL -tunnel", __func__ );
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
				hostapd_printf("Error: %s", wps->error->message);
                wps->callback(wps->proxy, wps, wps->device_name, &wps->error, wps->user_data);
                return;
        }

        if (wps->error != NULL || out_message == NULL)
        {
                g_warning("Error: %s", wps->error->message);
				hostapd_printf("Error: %s", wps->error->message);
                wps->callback(wps->proxy, wps, wps->device_name, &wps->error, wps->user_data);
                return;
        }
/** Decode message received from SLL -path to binary ****/
		// Base64-->Binary decoding variables
        int b64_msg_len = strlen(out_message);
        unsigned char *binary_message=(unsigned char *)g_malloc(b64_msg_len);
		int outlen;
		
		hostapd_base64_decode (b64_msg_len, (const unsigned char *)out_message, &outlen, binary_message, b64_msg_len);

		char cstr[ 30 ];
		sprintf( cstr,"SSL-input:%s", wps_message_type_name( binary_message[9] ));
		hostapd_hexdump(cstr, binary_message, outlen);
		
/** Now we check the existence of ACK/NACK messages. With method checking (PIN/Push-Button) next steps after M2D are branched here. **/
		char terminate_after_m2d_or_m8 = FALSE;

		status = WPA_SM_R_PROCESS;	// this is a default meaning: continue
		switch( wps->method )
		{
		  case GUPNP_DEVICE_WPS_METHOD_PUSHBUTTON :	// deal : PBC configuration ?
			if ( hostapd_is_this_wps_nack_message( binary_message, outlen ))	// NACK --> Button not yet pushed
			{
			  hostapd_printf("%s: PBC: received WPS_NACK. Start to waiting SetupReady=TRUE", __func__ );
			  status = WPA_SM_R_SUCCESSINFO;	/** terminate after M2D, and let UI to deal with "gupnp_device_proxy_continue_wps" **/
			  terminate_after_m2d_or_m8 = TRUE;
			}
			else if ( hostapd_is_this_wps_ack_message( binary_message, outlen ))	// ACK --> Button has already pushed
			{
			  hostapd_printf("%s: PBC: received WPS_ACK --> Don't wait SetupReady=TRUE. Continue immediately", __func__ );
//			  gupnp_device_proxy_continue_wps ( wps, NULL, NULL, user_data ); // we just continue in this level !!!!!!!!
//			  on_state_variable_changed_setup_ready( proxy, "TRUE");

			  status = WPA_SM_R_PASS_HANDLING;	/** terminate after M8, and let UI to deal with "gupnp_device_proxy_continue_wps" **/
			  terminate_after_m2d_or_m8 = TRUE;
			}
			break;
		  case GUPNP_DEVICE_WPS_METHOD_PIN :	// deal : PIN  configuration ?
			hostapd_printf("%s: PIN method in progress", __func__ );
			// if ACK --> Enrollee have PIN available for Registrar. Feed it in using GUI !!
			if ( hostapd_is_this_wps_ack_message( binary_message, outlen ))	
			{
				status = WPA_SM_R_SUCCESSINFO;	/** terminate after M2D, and let UI to deal with "gupnp_device_proxy_continue_wps" **/
				terminate_after_m2d_or_m8 = TRUE;
			}
			break;
		  default :
			hostapd_printf("%s: undefined method %d", __func__, wps->method );
			break;
		}
		// Base64 encoding variables
		int maxb64len;
		int b64len;
		unsigned char *base64msg = NULL;

		if ( terminate_after_m2d_or_m8 == FALSE )
		{
	//		hostapd_wsc_nack_received();	// update current value by making call
	//		hostapd_wsc_ack_received();	// update current value by making call
			int update_status = hostapd_update_registrar_state_machine(	binary_message,
																		outlen,
																		&wps->wpa_registrar_send_msg,
																		&wps->wpa_registrar_send_msg_len,
																		&err);
			if (err != 0 || wps->wpa_registrar_send_msg_len <= 0 || update_status == 0 )
			{
					wps->error = g_error_new(GUPNP_SERVER_ERROR,
											GUPNP_SERVER_ERROR_OTHER,
											"DeviceProtection introduction failed to update state machine (%d). Terminating...",err);
					g_warning("Error: %s", wps->error->message);

					wps->callback(wps->proxy, wps, wps->device_name, &wps->error, wps->user_data);
					return;
			}

			maxb64len = 2 * wps->wpa_registrar_send_msg_len;
			base64msg = (unsigned char *)g_malloc(maxb64len);
			hostapd_base64_encode(wps->wpa_registrar_send_msg_len, wps->wpa_registrar_send_msg, &b64len, base64msg, maxb64len);

			if ( hostapd_is_authentication_finished() ) 	/* M8 processed --> all done */
			{
			  status = WPA_SM_R_SUCCESS;
			  hostapd_printf("%s: TEST: authentication finished cause WSC_Done received", __func__ );
			}
			else	/* continue .. */
			  status = WPA_SM_R_PROCESS;	// TODO: something else is needed to set "status" --> continue forever
		} /* terminate_after_m2d_or_m8 == TRUE */
		switch (status)
        {
        case WPA_SM_R_SUCCESS:
                g_warning("DeviceProtection introduction last message received!");

				/* TODO: UUID should be digged from somewhere ?? */
                wps->proxy->priv->root_proxy->priv->device_uuid = hostapd_get_uuid_e_ptr();
				print_uuid( "UUID-R: ", wps->proxy->priv->root_proxy->priv->cp_uuid, GUPNP_DP_UUID_LEN );
				print_uuid( "UUID-E: ", wps->proxy->priv->root_proxy->priv->device_uuid, GUPNP_DP_UUID_LEN );

                wps->done = TRUE;
                wps->callback(wps->proxy, wps, wps->device_name, &wps->error, wps->user_data);
                break;

        case WPA_SM_R_SUCCESSINFO:
#ifdef WPA_ADDITIONAL_DEBUG
				hostapd_printf("%s: status=WPA_SM_R_SUCCESSINFO", __func__ );
#endif
				g_warning("DeviceProtection introduction last message received M2D!");
#if 0
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
#endif
                wps->device_name = g_string_new("Device-Name");	/* TODO: Where to get "DeviceName" ?? */

                wps->callback(wps->proxy, wps, wps->device_name, &wps->error, wps->user_data);

                break;

        case WPA_SM_R_FAILURE:
#ifdef WPA_ADDITIONAL_DEBUG
				hostapd_printf("%s: status=WPA_SM_R_FAILURE", __func__ );
#endif
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

        case WPA_SM_R_FAILUREEXIT:
#ifdef WPA_ADDITIONAL_DEBUG
				hostapd_printf("%s: status=WPA_SM_R_FAILUREEXIT", __func__ );
#endif
				wps->error = g_error_new(GUPNP_SERVER_ERROR,
                                         GUPNP_SERVER_ERROR_OTHER,
                                         "DeviceProtection introduction error in state machine. Terminating...");
                g_warning("Error: %s", wps->error->message);

                wps->callback(wps->proxy, wps, wps->device_name, &wps->error, wps->user_data);
                break;
		case WPA_SM_R_PASS_HANDLING :
				// Don't do nothing, because everything handled in recursion
				hostapd_printf("%s: status=WPA_SM_R_PASS_HANDLING", __func__ );
				g_warning("DeviceProtection introduction last message received M2D!");
                wps->callback(wps->proxy, wps, wps->device_name, &wps->error, (gpointer)1);
		  break;
        default:
#ifdef WPA_ADDITIONAL_DEBUG
				hostapd_printf("%s: status=%d, -->continue", __func__, status );
#endif
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

static int createUUIDR(unsigned char **uuid, size_t *uuid_len)
{
    int ret, cert_size = 10000;
    *uuid = NULL;
    unsigned char cert[cert_size];
    unsigned char hash[cert_size];

    // get certificate
    ret = ssl_client_export_cert(cert, &cert_size);
    if (ret != 0)
    {
        g_warning("Failed to export client certificate");
        return ret;
    }

    // create hash from certificate
    ret = calculate_sha256(cert, cert_size, hash);
    if (ret < 0)
    {
        g_warning("Failed to create hash from client certificate");
        return ret;
    }

    // create uuid from certificate
    createUuidFromData(NULL, uuid, uuid_len, hash, 16);
    if (*uuid == NULL)
    {
        g_warning("Failed to create uuid from the hash of client certificate");
        return -2;
    }

    return 0;
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

	// we need to have SSL
	// so let's create it (if not created already)
	if (!gupnp_device_proxy_init_ssl (proxy, &wps->error))
	{
			g_warning("Error: %s", wps->error->message);
			return wps;
	}

/*        if (wps->method == GUPNP_DEVICE_WPS_METHOD_PUSHBUTTON)
	{
			wps->error = g_error_new(GUPNP_SERVER_ERROR,
									  GUPNP_SERVER_ERROR_OTHER,
									  "Push button method not yet supported.");
			g_warning("Error: %s", wps->error->message);
			return wps;
	}
*/
	if (wps->device_prot_service == NULL)
	{
			wps->error = g_error_new(GUPNP_SERVER_ERROR,
									  GUPNP_SERVER_ERROR_OTHER,
									  "No device protection service found.");
			g_warning("Error: %s", wps->error->message);
			return wps;
	}

	// create UUID-R for WPS
	if (createUUIDR(&wps->uuid, &wps->uuid_len) != 0)
	{
			wps->error = g_error_new(GUPNP_SERVER_ERROR,
									  GUPNP_SERVER_ERROR_OTHER,
									  "Failed to create UUID-R for WPS.");
			g_warning("Error: %s", wps->error->message);
			return wps;
	}

	// save our uuid
	proxy->priv->root_proxy->priv->cp_uuid = (unsigned char *)malloc( GUPNP_DP_UUID_LEN );
	memcpy( proxy->priv->root_proxy->priv->cp_uuid, wps->uuid, GUPNP_DP_UUID_LEN );
	print_uuid(  "UUID-R: ", proxy->priv->root_proxy->priv->cp_uuid, GUPNP_DP_UUID_LEN );

	hostapd_wps_registrar_info info;

	info.devicePIN = wps->pin->str;
	info.manufacturer = NULL;
	info.modelName = NULL;
	info.modelNumber = NULL;
	info.manufacturer = NULL;
	info.deviceName = wps->client_name->str;
	info.primaryDeviceType = NULL;
	info.primaryDeviceType_len = 0;
	info.macAddress = NULL;
	info.macAddress_len = 0;
	info.uuid = wps->uuid;
	info.uuid_len = wps->uuid_len;
	info.OSVersion = NULL;
	info.OSVersion_len = 0;
	info.pubKey = NULL;
	info.pubKey_len = 0;
	info.configMethods = 0;
	info.RFBands = 0;
	
	error = hostapd_iface_init( & info );
   if (error != WPA_E_SUCCESS)
   {
		wps->error = g_error_new(GUPNP_SERVER_ERROR,
      						GUPNP_SERVER_ERROR_OTHER,
							"hostapd_iface_init()failed");
		g_warning("%s, %d", wps->error->message, error);
        return wps;
	}
	
	hostapd_create_registrar_state_machine(&error);
	if (error != WPA_E_SUCCESS)
	{
		wps->error = g_error_new(GUPNP_SERVER_ERROR,
								GUPNP_SERVER_ERROR_OTHER,
								"hostapd_create_registrar_sm() failed");
		g_warning("%s", wps->error->message);
        return wps;
	}

	// If push-button config requested from GUI
	if (wps->method == GUPNP_DEVICE_WPS_METHOD_PUSHBUTTON)
    {
		hostapd_push_button_configuration();
	}

	
	hostapd_start_registrar_state_machine((const char *)wps->pin->str);

    if (error != WPA_E_SUCCESS)
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
	hostapd_printf("%s:all done\n", __func__ );

    return wps;
}

/*********
 At now, situation is this :
  - M2 message has constructed in together with M2D message and HOSTAPD State Machine has turned into position,
	which starts with M2 after this ACK has injected into it.
*********/
#define	M2_MESSAGE_MAX_LEN	1024
void
gupnp_device_proxy_continue_wps (GUPnPDeviceProxyWps        *wps,
                                 GString                    *pin_code,
								 GUPnPDeviceProxyWpsCallback callback,
                                 gpointer                    user_data)
{
	// TODO: wps messages m2..m8

	hostapd_printf("%s:", __func__ );

	if ( wps->method == GUPNP_DEVICE_WPS_METHOD_PIN && pin_code )
	{
		// Change the PIN, cause we have just received it from the UI dialog
  		hostapd_input_pin_to_wps( pin_code->str );
		g_string_free( pin_code, TRUE );
	}
	if ( callback )	// if callback wanted to be changed
	  wps->callback = callback;
	unsigned char 	*ack_binary_message =(unsigned char *)g_malloc(200);	// 200 bytes is enough for WPS-ACK
	int				ack_bin_msg_len;
	hostapd_construct_ack_mesage( ack_binary_message, &ack_bin_msg_len );	// continue immediately with M2
	
	unsigned char *	wps_next_message = (unsigned char *)g_malloc( M2_MESSAGE_MAX_LEN );
	int				wps_next_message_len;
	int				err;

	int update_status = hostapd_update_registrar_state_machine(	ack_binary_message,
																ack_bin_msg_len,
																&wps_next_message,
																&wps_next_message_len,
																&err);

	g_free( ack_binary_message );
    if (err != 0 || wps_next_message_len <= 0 || update_status == 0 )
    {
		wps->error = g_error_new(GUPNP_SERVER_ERROR,
								GUPNP_SERVER_ERROR_OTHER,
								"DeviceProtection introduction failed to update state machine (%d). Terminating...",err);
		g_warning("Error: %s", wps->error->message);

		wps->callback(wps->proxy, wps, wps->device_name, &wps->error, wps->user_data);
		g_free( wps_next_message );
		return;
	}
    int maxbase64len = 2 * wps_next_message_len;	// ASCII conversion doubles bytecnt.
    int base64len;
    unsigned char *base64msg = (unsigned char *)g_malloc(maxbase64len);

	hostapd_base64_encode(wps_next_message_len, (const unsigned char *)wps_next_message, &base64len, base64msg, maxbase64len);
	g_free( wps_next_message );

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
        gboolean done = wps->done;
        g_object_unref(wps->proxy);
        g_string_free(wps->client_name, TRUE);
		if ( wps->pin )
		  g_string_free(wps->pin, TRUE);
        //g_string_free(wps->device_name, TRUE);

		//		g_free(wps);

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
            const char *URL = gupnp_service_info_get_secure_control_url (GUPNP_SERVICE_INFO(found_device));
            g_object_unref (found_device);

            // create ssl
            int ret = gupnp_device_proxy_create_and_init_ssl_client (proxy, URL);
            if (URL) free((char *)URL);
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
 * @url: HTTPS Address of server.
 *
 * Create and initialize ssl client of proxy. Connects to server.
 **/
int
gupnp_device_proxy_create_and_init_ssl_client (GUPnPDeviceProxy *proxy,
                                                const char *https_url)
{
        g_assert (proxy != NULL);

        int ret = 0;

        if (https_url == NULL)
            return -2;

        // get home dir
        const char *homedir = g_getenv ("HOME");
        if (!homedir)
            homedir = g_get_home_dir ();

        char *fullCertStore = g_build_path(G_DIR_SEPARATOR_S, homedir, GUPNP_CERT_STORE, NULL);

        ret = ssl_init_client(&(proxy->priv->ssl_client), fullCertStore ,NULL,NULL,NULL,NULL, GUPNP_CERT_CN);
        g_free(fullCertStore);
        if (ret != 0)
        {
            g_warning("Failed init SSL client");
            return ret;
        }

        // create SSL session (connection to server)
        ret = ssl_create_client_session(&(proxy->priv->ssl_client), https_url, NULL, NULL);
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
        proxy->priv->ssl_client = g_slice_dup(GUPnPSSLClient, client);
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
GUPnPSSLClient **
gupnp_device_proxy_get_ssl_client (GUPnPDeviceProxy *proxy)
{
        g_assert (proxy != NULL);

        if (proxy->priv->root_proxy)
            return &(proxy->priv->root_proxy->priv->ssl_client);

        return NULL;
}

/**
 * gupnp_device_proxy_set_username
 * @proxy: A #GUPnPDeviceProxy
 * @username: Username which is added for root proxy
 *
 * Set the username which is logged in to root device of given deviceproxy.
 *
 * Return value: void
 **/
void
gupnp_device_proxy_set_username (GUPnPDeviceProxy *proxy, const gchar *username)
{
        g_assert (proxy != NULL);
        g_assert (username != NULL);
        // make sure that username is inserted into root device in deviceproxy
        if (proxy->priv->root_proxy)
            g_string_assign(proxy->priv->root_proxy->priv->username, username);
}

/**
 * gupnp_device_proxy_get_username
 * @proxy: A #GUPnPDeviceProxy
 *
 * Get the username which deviceproxy is logged in. If not logged in empty string.
 *
 * Return value: Copy of username which is logged in for given GUPnPDeviceProxy. 
 * Caller should call g_string_free for received stirng. 
 **/
GString *
gupnp_device_proxy_get_username (GUPnPDeviceProxy *proxy)
{
        g_assert (proxy != NULL);

        if (proxy->priv->root_proxy)
            return g_string_new(proxy->priv->root_proxy->priv->username->str);

        return NULL;
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
static int createAuthenticator( const unsigned char *bin_stored,
                                int                  bin_stored_len,
                                const char          *b64_challenge,
                                const unsigned char *cp_uuid,
                                const unsigned char *device_uuid,
                                char               **b64_authenticator,
                                int                 *auth_len )
{
    if ( bin_stored == NULL )
    {
        return -1;
    }

    // challenge from base64 to binary
    int b64msglen = strlen( b64_challenge );

    unsigned char *bin_challenge = ( unsigned char * ) malloc( b64msglen );

    if ( bin_challenge == NULL )
    {
        return -1;
    }

    int bin_challenge_len;

    hostapd_base64_decode( b64msglen, (const unsigned char *) b64_challenge, &bin_challenge_len, bin_challenge, b64msglen );
    // create ( Challenge || DeviceID || ControlPointID )
    int cdc_len = bin_challenge_len + 2*(GUPNP_DP_UUID_LEN);
    unsigned char *cdc = (unsigned char *) malloc ( cdc_len );
    memcpy( cdc, bin_challenge, bin_challenge_len );
    memcpy( cdc + bin_challenge_len, device_uuid, GUPNP_DP_UUID_LEN );
    memcpy( cdc + bin_challenge_len + GUPNP_DP_UUID_LEN, cp_uuid, GUPNP_DP_UUID_LEN );

    unsigned char hmac_result[WPA_HASH_LEN];
    hostapd_hmac_sha256( bin_stored, bin_stored_len, cdc, cdc_len, hmac_result );
    // release useless stuff
    free( bin_challenge );
    free( cdc );

    // encode required amount of first bytes of created hash as base64 authenticator
    int maxb64len = 2 * GUPNP_DP_AUTH_BYTES;

    *auth_len = 0;

    *b64_authenticator = ( char * ) malloc( maxb64len );

	hostapd_base64_encode( GUPNP_DP_AUTH_BYTES, hmac_result, auth_len, ( unsigned char * ) *b64_authenticator, maxb64len);

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

		hostapd_printf("%s", __func__ );	/* NNN */
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

#define NO_UPPERCASE_USERNAME	1
#define	WPSUTIL_BASE64			1

// this is called when library receives response for GetUserLoginChallenge-action
static void
login_challenge_response( GUPnPServiceProxy       *proxy,
                          GUPnPServiceProxyAction *action,
                          gpointer                 user_data )
{
    GUPnPDeviceProxyLogin *logindata = user_data;
    char *salt;
    char *challenge;
    gchar* nameUPPER;
    GError *error = NULL;
    int err;

	hostapd_printf("%s", __func__ );	/* NNN */
    if ( logindata->proxy->priv->device_uuid == NULL ||
         logindata->proxy->priv->cp_uuid == NULL )
    {
        logindata->error = g_error_new( GUPNP_SERVER_ERROR,
                                        GUPNP_SERVER_ERROR_OTHER,
                                        "UUID unknown, run WPS setup before user login." );
        g_warning( "Error: %s", logindata->error->message );
        logindata->callback( logindata->proxy, logindata, &logindata->error, logindata->user_data );
        return;
    }

    if ( !gupnp_service_proxy_end_action( proxy,
                                          action,
                                          &error,
                                          "Salt",
                                          G_TYPE_STRING,
                                          &salt,
                                          "Challenge",
                                          G_TYPE_STRING,
                                          &challenge,
                                          NULL ) )
    {
        logindata->error = error;
        g_warning( "Error: %s", logindata->error->message );
        logindata->callback( logindata->proxy, logindata, &logindata->error, logindata->user_data );
        return;
    }

    if ( logindata->error != NULL || salt == NULL || challenge == NULL )
    {
        g_warning( "Error: %s", logindata->error->message );
        logindata->callback( logindata->proxy, logindata, &logindata->error, logindata->user_data );
        return;
    }
    else
    {
        // create STORED. Needed values are salt, username (in uppercase) and password
        // salt from base64 to binary
        int b64_msg_len = strlen( salt );
        unsigned char *bin_salt = ( unsigned char * ) g_malloc( b64_msg_len );
        int bin_salt_len;
		hostapd_base64_decode( b64_msg_len, ( const unsigned char * ) salt, &bin_salt_len, bin_salt, b64_msg_len );

        // username to utf8 uppercase
#ifdef NO_UPPERCASE_USERNAME
		nameUPPER = logindata->username->str;
#else
        nameUPPER = g_utf8_strup( logindata->username->str, logindata->username->len );
#endif

        if ( !nameUPPER )
        {
            logindata->error = g_error_new( GUPNP_SERVER_ERROR,
                                            GUPNP_SERVER_ERROR_OTHER,
                                            "Failed to convert username to uppercase" );
            g_warning( "%s", logindata->error->message );
            logindata->callback( logindata->proxy, logindata, &logindata->error, logindata->user_data );
            return;
        }

        // concatenate NAME and binary salt
        glong name_len = g_utf8_strlen( nameUPPER, -1 );

        glong namesalt_len = name_len + bin_salt_len;  // should it matter if salt_len is greater than 16. It shouldn't happen, but...

        unsigned char namesalt[namesalt_len];

        memcpy( namesalt, nameUPPER, name_len );

        memcpy( namesalt + name_len, bin_salt, bin_salt_len );


        // create STORED
        unsigned char bin_stored[GUPNP_DP_STORED_BYTES];

        err = crypt_pbkdf2( logindata->password->str, logindata->password->len, namesalt,
                           namesalt_len, GUPNP_DP_PRF_ROUNDS, GUPNP_DP_STORED_BYTES, bin_stored );

        if ( err != 0 )
        {
            logindata->error = g_error_new( GUPNP_SERVER_ERROR,
                                            GUPNP_SERVER_ERROR_OTHER,
                                            "Failed to create STORED" );
            g_warning( "%s", logindata->error->message );
            logindata->callback( logindata->proxy, logindata, &logindata->error, logindata->user_data );
            return;
        }


        // create Authenticator
        char *b64_authenticator = NULL;

        int auth_len = 0;
        err = createAuthenticator( bin_stored, GUPNP_DP_STORED_BYTES, challenge,
                                   logindata->proxy->priv->cp_uuid,
                                   logindata->proxy->priv->device_uuid,
                                   &b64_authenticator, &auth_len );

        if ( err != 0 )
        {
            logindata->error = g_error_new( GUPNP_SERVER_ERROR,
                                            GUPNP_SERVER_ERROR_OTHER,
                                            "Failed to create Authenticator" );
            g_warning( "%s", logindata->error->message );
            logindata->callback( logindata->proxy, logindata, &logindata->error, logindata->user_data );
            return;
        }

        // send UserLogin
        gupnp_service_proxy_begin_action( logindata->device_prot_service,
                                          "UserLogin",
                                          login_response,
                                          logindata,
                                          "ProtocolType",
                                          G_TYPE_STRING,
                                          "PKCS5",
                                          "Challenge",
                                          G_TYPE_STRING,
                                          challenge,
                                          "Authenticator",
                                          G_TYPE_STRING,
                                          b64_authenticator,
                                          NULL );

//		g_free( b64_authenticator );
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
        GError *gerror;

        g_return_val_if_fail (GUPNP_IS_DEVICE_PROXY (proxy), NULL);
        g_return_val_if_fail (callback, NULL);
        g_return_val_if_fail (username, NULL);
        g_return_val_if_fail (password, NULL);

        // we need to have SSL
        // so let's create it
        gupnp_device_proxy_init_ssl (proxy, &gerror);

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

        if (gupnp_device_proxy_get_ssl_client(proxy) == NULL)
        {
                logindata->error = g_error_new(GUPNP_SERVER_ERROR,
                             GUPNP_SERVER_ERROR_OTHER,
                             "For logging in SSL connection is needed.");
                g_warning("Error: %s", logindata->error->message);
                return logindata;
        }

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
                                         "ProtocolType",
                                         G_TYPE_STRING,
                                         "PKCS5",
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
        
        // copy username to deviceproxy
        if (logindata->done)
            gupnp_device_proxy_set_username(logindata->proxy, logindata->username->str);
        
        gboolean done = logindata->done;

        g_object_unref(logindata->proxy);

        g_string_free(logindata->username, TRUE);
        g_string_free(logindata->password, TRUE);

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
        GError *gerror;

        g_return_val_if_fail (GUPNP_IS_DEVICE_PROXY (proxy), NULL);
        g_return_val_if_fail (callback, NULL);

        // we need to have SSL
        // so let's create it (if not created already
        gupnp_device_proxy_init_ssl (proxy, &gerror);

        logoutdata = g_slice_new (GUPnPDeviceProxyLogout);
        logoutdata->proxy = proxy;
        logoutdata->callback = callback;
        logoutdata->user_data = user_data;
        logoutdata->error = NULL;
        logoutdata->device_prot_service = find_device_protection_service (proxy);
        logoutdata->done = FALSE;

        if (gupnp_device_proxy_get_ssl_client(proxy) == NULL)
        {
                logoutdata->error = g_error_new(GUPNP_SERVER_ERROR,
                             GUPNP_SERVER_ERROR_OTHER,
                             "For logging out SSL connection is needed.");
                g_warning("Error: %s", logoutdata->error->message);
                return logoutdata;
        }

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
        // erase logged in username from proxy
        if (logoutdata->done)
            gupnp_device_proxy_set_username(logoutdata->proxy, "");
        
        gboolean done = logoutdata->done;

        g_object_unref(logoutdata->proxy);

        return done;
}

/* SetUserLoginPassword action stuff */

// this is called when library receives response for SetUserLoginPassword-action
static void
set_user_login_password_response (GUPnPServiceProxy       *proxy,
                                  GUPnPServiceProxyAction *action,
                                  gpointer                 user_data)
{
        GUPnPDeviceProxyChangePassword *passworddata = user_data;
        GError *error = NULL;

        if (!gupnp_service_proxy_end_action (proxy,
                                             action,
                                            &error,
                                             NULL))
        {
                passworddata->error = error;
                g_warning("Error: %s", passworddata->error->message);
        }
        else
        {
            passworddata->done = TRUE;
        }
        passworddata->callback(passworddata->proxy, passworddata, &passworddata->error, passworddata->user_data);
}

// Change user login password input from GUI
GUPnPDeviceProxyChangePassword *
gupnp_device_proxy_change_password (GUPnPDeviceProxy                       *proxy,
                                    const gchar                            *username,
                                    const gchar                            *password,
                                    GUPnPDeviceProxyChangePasswordCallback  callback,
                                    gpointer                                user_data)
{
        GUPnPDeviceProxyChangePassword *passworddata;
        GError *gerror;

        g_return_val_if_fail (GUPNP_IS_DEVICE_PROXY (proxy), NULL);
        g_return_val_if_fail (callback, NULL);
        g_return_val_if_fail (username, NULL);
        g_return_val_if_fail (password, NULL);

        // we need to have SSL
        // so let's create it
        gupnp_device_proxy_init_ssl (proxy, &gerror);

        passworddata = g_slice_new (GUPnPDeviceProxyChangePassword);
        passworddata->proxy = proxy;
        passworddata->callback = callback;
        passworddata->user_data = user_data;
        passworddata->error = NULL;
        passworddata->device_prot_service = find_device_protection_service (proxy);
        passworddata->username = g_string_new(username);
        passworddata->password = g_string_new(password);
        passworddata->salt = NULL;
        passworddata->stored = NULL;
        passworddata->done = FALSE;

        if (gupnp_device_proxy_get_ssl_client(proxy) == NULL)
        {
                passworddata->error = g_error_new(GUPNP_SERVER_ERROR,
                             GUPNP_SERVER_ERROR_OTHER,
                             "For changing user password SSL connection is needed.");
                g_warning("Error: %s", passworddata->error->message);
                return passworddata;
        }

        if (passworddata->device_prot_service == NULL)
        {
                passworddata->error = g_error_new(GUPNP_SERVER_ERROR,
                                         GUPNP_SERVER_ERROR_OTHER,
                                         "No device protection service found.");
                g_warning("Error: %s", passworddata->error->message);
                return passworddata;
        }

        // create new salt and stored
        // username to utf8 uppercase
        int ret, salt_len, stored_len;
#ifdef NO_UPPERCASE_USERNAME
		gchar *nameUPPER = passworddata->username->str;
#else
        gchar *nameUPPER = g_utf8_strup(passworddata->username->str, passworddata->username->len);
#endif
        
        int maxb64len = 2*GUPNP_DP_STORED_BYTES;     
        unsigned char *b64_salt = (unsigned char *)malloc(maxb64len); 
        unsigned char *b64_stored = (unsigned char *)malloc(maxb64len);        
        
        int name_len = strlen(nameUPPER);
        int namesalt_len = name_len + GUPNP_DP_SALT_BYTES;
        unsigned char namesalt[namesalt_len];
    
        // create SALT   
        unsigned char *salt = crypt_create_random_value(GUPNP_DP_SALT_BYTES);
        
        memcpy(namesalt, nameUPPER, name_len);
        memcpy(namesalt+name_len, salt, GUPNP_DP_SALT_BYTES);
        
        /* Create STORED = first 160 bits of the key T1, with T1 computed according to [PKCS#5] algorithm PBKDF2
            
            T1 is defined as the exclusive-or sum of the first c iterates of PRF applied to the concatenation 
            of the Password, Name, Salt, and four-octet block index (0x00000001) in big-endian format.  
            For DeviceProtection, the value for c is 5,000.  Name MUST be converted to upper-case, and 
            Password and Name MUST be encoded in UTF-8 format prior to invoking the PRF operation.  
            T1 = U1 \xor U2 \xor … \xor Uc
            where
            U1 = PRF(Password, Name || Salt || 0x0 || 0x0 || 0x0 || 0x1)
            U2 = PRF(Password, U1),
            …
            Uc = PRF(Password, Uc-1).
            
            NOTE2: crypt_pbkdf2 goes through whole PBKDF2 algorithm, even if in this case only first block
                   is needed for result. First 160 bits are the same if all the data is processed or just 
                   the first block. (block size should be defined to 160bits => DP_STORED_BYTES = 8)
         */
        unsigned char bin_stored[GUPNP_DP_STORED_BYTES];
        ret = crypt_pbkdf2(passworddata->password->str, passworddata->password->len, namesalt,
                        namesalt_len, GUPNP_DP_PRF_ROUNDS, GUPNP_DP_STORED_BYTES, bin_stored);
                        
        if (ret != 0) 
        {
                passworddata->error = g_error_new(GUPNP_SERVER_ERROR,
                             GUPNP_SERVER_ERROR_OTHER,
                             "Failed to create stored value for password changing");
                g_warning("Error: %s", passworddata->error->message);
                return passworddata;  
        }
        
        // SALT and STORED to base 64
        hostapd_base64_encode(GUPNP_DP_SALT_BYTES, salt, &salt_len, b64_salt, maxb64len);
        hostapd_base64_encode(GUPNP_DP_STORED_BYTES, bin_stored, &stored_len, b64_stored, maxb64len);

        // create GStrings from salt and stored
        passworddata->salt = g_string_new_len((char *)b64_salt, salt_len);
        passworddata->stored = g_string_new_len((char *)b64_stored, stored_len);

        g_free(b64_salt);
        g_free(b64_stored);
        gupnp_service_proxy_begin_action(passworddata->device_prot_service,
                                         "SetUserLoginPassword",
                                         set_user_login_password_response,
                                         passworddata,
                                         "ProtocolType",
                                         G_TYPE_STRING,
                                         "PKCS5",
                                         "Name",
                                         G_TYPE_STRING,
                                         username,
                                         "Stored",
                                         G_TYPE_STRING,
                                         passworddata->stored->str,
                                         "Salt",
                                         G_TYPE_STRING,
                                         passworddata->salt->str,
                                         NULL);

        return passworddata;
}

// End password-change-process by calling this. Returns if operation is succeeded. Username which password is changed,
// is returned in loginname
gboolean
gupnp_device_proxy_end_change_password (GUPnPDeviceProxyChangePassword *passworddata, GString *loginname)
{
        // copy username logged in to loginname
        if (loginname)
            g_string_assign(loginname, passworddata->username->str);

        gboolean done = passworddata->done;

        g_object_unref(passworddata->proxy);

        g_string_free(passworddata->username, TRUE);
        g_string_free(passworddata->password, TRUE);
        g_string_free(passworddata->salt, TRUE);
        g_string_free(passworddata->stored, TRUE);        

        return done;
}


/*   Add new User  */

// this is called when library receives response for AddIdentityList-action
static void
add_identitylist_response (GUPnPServiceProxy       *proxy,
                           GUPnPServiceProxyAction *action,
                           gpointer                 user_data)
{
        GUPnPDeviceProxyAddUser *adduserdata = user_data;
        
        GError *error = NULL;

		hostapd_printf("%s:", __func__ );
        if (!gupnp_service_proxy_end_action (proxy,
                                             action,
                                            &error,
                                             NULL))
        {
                adduserdata->error = error;
                g_warning("Error: %s", adduserdata->error->message);
        }
        else
        {
            adduserdata->done = TRUE;
        }
        adduserdata->callback(adduserdata->proxy, adduserdata, &adduserdata->error, adduserdata->user_data);
}

// Begin logout-process by calling this
GUPnPDeviceProxyAddUser *
gupnp_device_proxy_add_user (GUPnPDeviceProxy           *proxy,
                             const gchar                *username,
                             const gchar                *password,   
                             GUPnPDeviceProxyAddUserCallback callback,
                             gpointer                    user_data)
{
        GUPnPDeviceProxyAddUser *adduserdata;
        GError *gerror;

        g_return_val_if_fail (GUPNP_IS_DEVICE_PROXY (proxy), NULL);
        g_return_val_if_fail (username, NULL);
        g_return_val_if_fail (password, NULL);
        g_return_val_if_fail (callback, NULL);

        // we need to have SSL
        // so let's create it (if not created already
        gupnp_device_proxy_init_ssl (proxy, &gerror);

        adduserdata = g_slice_new (GUPnPDeviceProxyAddUser);
        adduserdata->proxy = proxy;
        adduserdata->callback = callback;
        adduserdata->user_data = user_data;
        adduserdata->error = NULL;
        adduserdata->device_prot_service = find_device_protection_service (proxy);
        adduserdata->done = FALSE;
        adduserdata->username = g_string_new(username);
        adduserdata->password = g_string_new(password); // password is not used here, but let's keep it for change_password, if it is needed there
        adduserdata->identitylist = g_string_new("");

        if (gupnp_device_proxy_get_ssl_client(proxy) == NULL)
        {
                adduserdata->error = g_error_new(GUPNP_SERVER_ERROR,
                             GUPNP_SERVER_ERROR_OTHER,
                             "For adding user SSL connection is needed.");
                g_warning("Error: %s", adduserdata->error->message);
                return adduserdata;
        }

        if (adduserdata->device_prot_service == NULL)
        {
                adduserdata->error = g_error_new(GUPNP_SERVER_ERROR,
                                         GUPNP_SERVER_ERROR_OTHER,
                                         "No device protection service found.");
                g_warning("Error: %s", adduserdata->error->message);
                return adduserdata;
        }

        // create Identities XML fragment
        g_string_printf(adduserdata->identitylist, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                                                   "<Identities xmlns=\"urn:schemas-upnp-org:gw:DeviceProtection\" "
                                                   "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
                                                   "xsi:schemaLocation=\"http://www.upnp.org/schemas/gw/DeviceProtection-v1.xsd\">"
                                                   "<User><Name>%s</Name></User></Identities>", username);

        // escape identitylist xml
        GString *escIdList = g_string_new("");
        xml_util_add_content_wo_escape(escIdList, adduserdata->identitylist->str);
        
		escIdList->str[ escIdList->len ] = '\0';	/* TEST - terminate for printing */
		hostapd_printf("\n\n************* %s: AddIdentityList(%s)\n", __func__, escIdList->str ); /* TEST - printing */
		gupnp_service_proxy_begin_action(adduserdata->device_prot_service,
                                         "AddIdentityList",
                                         add_identitylist_response,
                                         adduserdata,
                                         "IdentityList",
                                         G_TYPE_STRING,
                                         escIdList->str,
                                         NULL);

        return adduserdata;
}


gboolean
gupnp_device_proxy_end_add_user (GUPnPDeviceProxyAddUser *adduserdata)
{
        gboolean done = adduserdata->done;

        g_object_unref(adduserdata->proxy);
        
        g_string_free(adduserdata->username,TRUE);
        g_string_free(adduserdata->password,TRUE);
        g_string_free(adduserdata->identitylist,TRUE);

        return done;
}


/*   Remove User  */

// this is called when library receives response for RemoveIdentity-action
static void
remove_identity_response (GUPnPServiceProxy       *proxy,
                           GUPnPServiceProxyAction *action,
                           gpointer                 user_data)
{
        GUPnPDeviceProxyRemoveUser *removeuserdata = user_data;
        
        GError *error = NULL;

        if (!gupnp_service_proxy_end_action (proxy,
                                             action,
                                            &error,
                                             NULL))
        {
                removeuserdata->error = error;
                g_warning("Error: %s", removeuserdata->error->message);
        }
        else
        {
            removeuserdata->done = TRUE;
        }
        removeuserdata->callback(removeuserdata->proxy, removeuserdata, &removeuserdata->error, removeuserdata->user_data);
}

// Begin logout-process by calling this
GUPnPDeviceProxyRemoveUser *
gupnp_device_proxy_remove_user (GUPnPDeviceProxy           *proxy,
                             const gchar                *username,  
                             GUPnPDeviceProxyRemoveUserCallback callback,
                             gpointer                    user_data)
{
        GUPnPDeviceProxyRemoveUser *removeuserdata;
        GError *gerror;

        g_return_val_if_fail (GUPNP_IS_DEVICE_PROXY (proxy), NULL);
        g_return_val_if_fail (username, NULL);

        // we need to have SSL
        // so let's create it (if not created already
        gupnp_device_proxy_init_ssl (proxy, &gerror);

        removeuserdata = g_slice_new (GUPnPDeviceProxyRemoveUser);
        removeuserdata->proxy = proxy;
        removeuserdata->callback = callback;
        removeuserdata->user_data = user_data;
        removeuserdata->error = NULL;
        removeuserdata->device_prot_service = find_device_protection_service (proxy);
        removeuserdata->done = FALSE;
        removeuserdata->username = g_string_new(username);
        removeuserdata->identity = g_string_new("");

        if (gupnp_device_proxy_get_ssl_client(proxy) == NULL)
        {
                removeuserdata->error = g_error_new(GUPNP_SERVER_ERROR,
                             GUPNP_SERVER_ERROR_OTHER,
                             "For removing user SSL connection is needed.");
                g_warning("Error: %s", removeuserdata->error->message);
                return removeuserdata;
        }

        if (removeuserdata->device_prot_service == NULL)
        {
                removeuserdata->error = g_error_new(GUPNP_SERVER_ERROR,
                                         GUPNP_SERVER_ERROR_OTHER,
                                         "No device protection service found.");
                g_warning("Error: %s", removeuserdata->error->message);
                return removeuserdata;
        }

        // create Identity XML fragment
        g_string_printf(removeuserdata->identity, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<Identity xmlns=\"urn:schemas-upnp-org:gw:DeviceProtection\"\
xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\
xsi:schemaLocation=\"urn:schemas-upnp-org:gw:DeviceProtection\
http://www.upnp.org/schemas/gw/DeviceProtection.xsd\">\
<User>\
<Name>%s</Name>\
</User>\
</Identity>", username);

        // escape identity xml
        GString *escId = g_string_new("");
        xml_util_add_content_wo_escape(escId, removeuserdata->identity->str);

		escId->str[ escId->len ] = '\0';	/* TEST - terminate for printing */
		hostapd_printf("\n\n************* %s: RemoveIdentity (%s)\n", __func__, escId->str ); /* TEST - printing */
        gupnp_service_proxy_begin_action(removeuserdata->device_prot_service,
                                         "RemoveIdentity",
                                         remove_identity_response,
                                         removeuserdata,
                                         "Identity",
                                         G_TYPE_STRING,
                                         escId->str,
                                         NULL);

        return removeuserdata;
}


gboolean
gupnp_device_proxy_end_remove_user (GUPnPDeviceProxyRemoveUser *removeuserdata)
{
        gboolean done = removeuserdata->done;

        g_object_unref(removeuserdata->proxy);
        
        g_string_free(removeuserdata->username,TRUE);
        g_string_free(removeuserdata->identity,TRUE);

        return done;
}

/*   Add Roles For User  */

// this is called when library receives response for AddRolesForIdentity-action
static void
add_roles_response (GUPnPServiceProxy       *proxy,
                    GUPnPServiceProxyAction *action,
                    gpointer                 user_data)
{
        GUPnPDeviceProxySetRoles *addrolesdata = user_data;
        
        GError *error = NULL;

        if (!gupnp_service_proxy_end_action (proxy,
                                             action,
                                            &error,
                                             NULL))
        {
                addrolesdata->error = error;
                g_warning("Error: %s", addrolesdata->error->message);
        }
        else
        {
            addrolesdata->done = TRUE;
        }
        addrolesdata->callback(addrolesdata->proxy, addrolesdata, &addrolesdata->error, addrolesdata->user_data);
}

// Begin adding roles for user
GUPnPDeviceProxySetRoles *
gupnp_device_proxy_add_roles (GUPnPDeviceProxy           *proxy,
                             const gchar                *username,  
                             const gchar                *rolelist,  
                             GUPnPDeviceProxySetRolesCallback callback,
                             gpointer                    user_data)
{
        GUPnPDeviceProxySetRoles *addrolesdata;
        GError *gerror;

        g_return_val_if_fail (GUPNP_IS_DEVICE_PROXY (proxy), NULL);
        g_return_val_if_fail (username, NULL);
        g_return_val_if_fail (rolelist, NULL);

        // we need to have SSL
        // so let's create it (if not created already
        gupnp_device_proxy_init_ssl (proxy, &gerror);

        addrolesdata = g_slice_new (GUPnPDeviceProxySetRoles);
        addrolesdata->proxy = proxy;
        addrolesdata->callback = callback;
        addrolesdata->user_data = user_data;
        addrolesdata->error = NULL;
        addrolesdata->device_prot_service = find_device_protection_service (proxy);
        addrolesdata->done = FALSE;
        addrolesdata->username = g_string_new(username);
        addrolesdata->identity = g_string_new("");
        addrolesdata->rolelist = g_string_new(rolelist);

        if (gupnp_device_proxy_get_ssl_client(proxy) == NULL)
        {
                addrolesdata->error = g_error_new(GUPNP_SERVER_ERROR,
                             GUPNP_SERVER_ERROR_OTHER,
                             "For adding roles for user SSL connection is needed.");
                g_warning("Error: %s", addrolesdata->error->message);
                return addrolesdata;
        }

        if (addrolesdata->device_prot_service == NULL)
        {
                addrolesdata->error = g_error_new(GUPNP_SERVER_ERROR,
                                         GUPNP_SERVER_ERROR_OTHER,
                                         "No device protection service found.");
                g_warning("Error: %s", addrolesdata->error->message);
                return addrolesdata;
        }

        // create Identity XML fragment
        g_string_printf(addrolesdata->identity, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<Identity xmlns=\"urn:schemas-upnp-org:gw:DeviceProtection\"\
xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\
xsi:schemaLocation=\"urn:schemas-upnp-org:gw:DeviceProtection\
http://www.upnp.org/schemas/gw/DeviceProtection.xsd\">\
<User>\
<Name>%s</Name>\
</User>\
</Identity>", username);

        // escape identity xml
        GString *escId = g_string_new("");
        xml_util_add_content_wo_escape(escId, addrolesdata->identity->str);

        gupnp_service_proxy_begin_action(addrolesdata->device_prot_service,
                                         "AddRolesForIdentity",
                                         add_roles_response,
                                         addrolesdata,
                                         "Identity",
                                         G_TYPE_STRING,
                                         escId->str,
                                         "RoleList",
                                         G_TYPE_STRING,
                                         rolelist,
                                         NULL);

        return addrolesdata;
}


gboolean
gupnp_device_proxy_end_add_roles (GUPnPDeviceProxySetRoles *addrolesdata)
{
        gboolean done = addrolesdata->done;

        g_object_unref(addrolesdata->proxy);
        
        g_string_free(addrolesdata->username,TRUE);
        g_string_free(addrolesdata->identity,TRUE);
        g_string_free(addrolesdata->rolelist,TRUE);

        return done;
}

/*   Remove Roles From User  */

// this is called when library receives response for RemoveRolesForIdentity-action
static void
remove_roles_response (GUPnPServiceProxy       *proxy,
                    GUPnPServiceProxyAction *action,
                    gpointer                 user_data)
{
        GUPnPDeviceProxySetRoles *removerolesdata = user_data;
        
        GError *error = NULL;

        if (!gupnp_service_proxy_end_action (proxy,
                                             action,
                                            &error,
                                             NULL))
        {
                removerolesdata->error = error;
                g_warning("Error: %s", removerolesdata->error->message);
        }
        else
        {
            removerolesdata->done = TRUE;
        }
        removerolesdata->callback(removerolesdata->proxy, removerolesdata, &removerolesdata->error, removerolesdata->user_data);
}

// Begin adding roles for user
GUPnPDeviceProxySetRoles *
gupnp_device_proxy_remove_roles (GUPnPDeviceProxy           *proxy,
                             const gchar                *username,  
                             const gchar                *rolelist,  
                             GUPnPDeviceProxySetRolesCallback callback,
                             gpointer                    user_data)
{
        GUPnPDeviceProxySetRoles *removerolesdata;
        GError *gerror;

        g_return_val_if_fail (GUPNP_IS_DEVICE_PROXY (proxy), NULL);
        g_return_val_if_fail (username, NULL);
        g_return_val_if_fail (rolelist, NULL);

        // we need to have SSL
        // so let's create it (if not created already
        gupnp_device_proxy_init_ssl (proxy, &gerror);

        removerolesdata = g_slice_new (GUPnPDeviceProxySetRoles);
        removerolesdata->proxy = proxy;
        removerolesdata->callback = callback;
        removerolesdata->user_data = user_data;
        removerolesdata->error = NULL;
        removerolesdata->device_prot_service = find_device_protection_service (proxy);
        removerolesdata->done = FALSE;
        removerolesdata->username = g_string_new(username);
        removerolesdata->identity = g_string_new("");
        removerolesdata->rolelist = g_string_new(rolelist);

        if (gupnp_device_proxy_get_ssl_client(proxy) == NULL)
        {
                removerolesdata->error = g_error_new(GUPNP_SERVER_ERROR,
                             GUPNP_SERVER_ERROR_OTHER,
                             "For removing roles for user SSL connection is needed.");
                g_warning("Error: %s", removerolesdata->error->message);
                return removerolesdata;
        }

        if (removerolesdata->device_prot_service == NULL)
        {
                removerolesdata->error = g_error_new(GUPNP_SERVER_ERROR,
                                         GUPNP_SERVER_ERROR_OTHER,
                                         "No device protection service found.");
                g_warning("Error: %s", removerolesdata->error->message);
                return removerolesdata;
        }

        // create Identity XML fragment
        g_string_printf(removerolesdata->identity, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<Identity xmlns=\"urn:schemas-upnp-org:gw:DeviceProtection\"\
xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\
xsi:schemaLocation=\"urn:schemas-upnp-org:gw:DeviceProtection\
http://www.upnp.org/schemas/gw/DeviceProtection.xsd\">\
<User>\
<Name>%s</Name>\
</User>\
</Identity>", username);

        // escape identity xml
        GString *escId = g_string_new("");
        xml_util_add_content_wo_escape(escId, removerolesdata->identity->str);

        gupnp_service_proxy_begin_action(removerolesdata->device_prot_service,
                                         "RemoveRolesForIdentity",
                                         remove_roles_response,
                                         removerolesdata,
                                         "Identity",
                                         G_TYPE_STRING,
                                         escId->str,
                                         "RoleList",
                                         G_TYPE_STRING,
                                         rolelist,
                                         NULL);

        return removerolesdata;
}


gboolean
gupnp_device_proxy_end_remove_roles (GUPnPDeviceProxySetRoles *removerolesdata)
{
        gboolean done = removerolesdata->done;

        g_object_unref(removerolesdata->proxy);
        
        g_string_free(removerolesdata->username,TRUE);
        g_string_free(removerolesdata->identity,TRUE);
        g_string_free(removerolesdata->rolelist,TRUE);

        return done;
}


// this is called when library receives response for GetACLData-action
static void
get_ACL_data_response (GUPnPServiceProxy       *proxy,
                       GUPnPServiceProxyAction *action,
                       gpointer                 user_data)
{    
        GUPnPDeviceProxyGetACLData *ACLData = user_data;
        GHashTable *users = ACLData->user_data;
            
        GError *error = NULL;
        char *acl, *acl_unescaped;

        if (!gupnp_service_proxy_end_action (proxy,
                                             action,
                                            &error,
                                             "ACL",
                                             G_TYPE_STRING,
                                             &acl,
                                             NULL))
        {
                ACLData->error = error;
                g_warning("Error: %s", ACLData->error->message);
        }
        else
        {
            ACLData->done = TRUE;
        
        
            // create hashtable from usernames in ACL. Only <User><Name> is accepted, not <CP><Name>.
            // Name is key, rolelist is value
            xmlDoc *xml_doc;
            xmlNode *element;
            xmlChar *name;
            xmlChar *rolelist;
          
            // first unescape string
            xml_util_unescape(acl, &acl_unescaped);
            
            xml_doc = xmlRecoverMemory(acl_unescaped, strlen(acl_unescaped));            
            ACLData->ACL = xml_doc_wrapper_new (xml_doc);                    
            element = xml_util_get_element ((xmlNode *) ACLData->ACL->doc,
                                            "ACL",
                                            NULL);
            if (element)
            {
                for (element = element->children; element; element = element->next) {
                    if (strcmp ((char *) element->name, "Identities") == 0)
                        break;
                }
                
                for (element = element->children; element; element = element->next) {
                    if (strcmp ((char *) element->name, "User") == 0)
                    {
                        name = xml_util_get_child_element_content (element, "Name");
                        if (!name)
                            continue;
                        rolelist = xml_util_get_child_element_content (element, "RoleList");
                        
                        g_warning("Name: %s RoleList:%s",name,rolelist);
                        
                        // insert to hashtable name-rolelist pairs. Name is the key
                        g_hash_table_insert(users, g_strdup((char *)name), g_strdup((char *)rolelist));
                    }         
                }                           
            }                                   
        }
        
        g_free(acl_unescaped);
        ACLData->callback(ACLData->proxy, ACLData, &ACLData->error, ACLData->user_data);
}

GUPnPDeviceProxyGetACLData *
gupnp_device_proxy_get_ACL_data (GUPnPDeviceProxy           *proxy,
                             GUPnPDeviceProxyGetACLDataCallback callback,
                             gpointer                    user_data)
{
        GUPnPDeviceProxyGetACLData *ACLData;

        g_return_val_if_fail (GUPNP_IS_DEVICE_PROXY (proxy), NULL);

        ACLData = g_slice_new (GUPnPDeviceProxyGetACLData);
        ACLData->proxy = proxy;
        ACLData->callback = callback;
        ACLData->user_data = user_data;
        ACLData->error = NULL;
        ACLData->device_prot_service = find_device_protection_service (proxy);
        ACLData->ACL = NULL;
        ACLData->done = FALSE;

        if (ACLData->device_prot_service == NULL)
        {
                ACLData->error = g_error_new(GUPNP_SERVER_ERROR,
                                         GUPNP_SERVER_ERROR_OTHER,
                                         "No device protection service found.");
                g_warning("Error: %s", ACLData->error->message);
                return ACLData;
        }

        gupnp_service_proxy_begin_action(ACLData->device_prot_service,
                                         "GetACLData",
                                         get_ACL_data_response,
                                         ACLData,
                                         NULL);

        return ACLData;
}


gboolean
gupnp_device_proxy_end_get_ACL_data (GUPnPDeviceProxyGetACLData *ACLData)
{      
        gboolean done = ACLData->done;       

        g_object_unref(ACLData->proxy);

        g_slice_free(GUPnPDeviceProxyGetACLData, ACLData);

        return done;
}
