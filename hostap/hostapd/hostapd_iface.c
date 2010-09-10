//##041 update this text
/*
 * hostapd / main()
 * Copyright (c) 2002-2010, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "utils/includes.h"
#ifndef CONFIG_NATIVE_WINDOWS
#include <syslog.h>
#endif /* CONFIG_NATIVE_WINDOWS */

#include "utils/common.h"
#include "utils/eloop.h"
#include "crypto/tls.h"
#include "common/version.h"
#include "drivers/driver.h"
#include "eap_server/eap.h"
#include "eap_server/tncs.h"
#include "ap/hostapd.h"
#include "ap/ap_config.h"
#include "wps/wps.h"
#include "config_file.h"
#include "eap_register.h"
#include "dump_state.h"
#include "ctrl_iface.h"


extern int wpa_debug_level;
extern int wpa_debug_show_keys;
extern int wpa_debug_timestamp;

//in eloop.c
int eloop_running_part1(void);
int eloop_running_part2(const u8 *data,
		       size_t data_len);
void *eloop_drv_get(void);

//in driver_test.c
void wpa_driver_test_eapol_inject(void *drv, const u8 *data, size_t data_len);
void wpa_driver_test_assoc_inject(void *drv, char *data);
void test_driver_set_send_eapol_cb( int (*send_eapol_cb)(void *drv, const u8 *data, size_t) );


int hostapd_iface_delete(void);

static void send_to_test_driver(void *drv, const u8 *data, size_t data_len);
static void associate_sta(void);
static void eapol_start_from_sta();
static void eapol_nnnn_from_sta();

struct hapd_interfaces {
	size_t count;
	struct hostapd_iface **iface;
};


static int hostapd_for_each_interface(struct hapd_interfaces *interfaces,
				      int (*cb)(struct hostapd_iface *iface,
						void *ctx), void *ctx)
{
	size_t i;
	int ret;

	for (i = 0; i < interfaces->count; i++) {
		ret = cb(interfaces->iface[i], ctx);
		if (ret)
			return ret;
	}

	return 0;
}


#ifndef CONFIG_NO_HOSTAPD_LOGGER
static void hostapd_logger_cb(void *ctx, const u8 *addr, unsigned int module,
			      int level, const char *txt, size_t len)
{
	struct hostapd_data *hapd = ctx;
	char *format, *module_str;
	int maxlen;
	int conf_syslog_level, conf_stdout_level;
	unsigned int conf_syslog, conf_stdout;

	maxlen = len + 100;
	format = os_malloc(maxlen);
	if (!format)
		return;

	if (hapd && hapd->conf) {
		conf_syslog_level = hapd->conf->logger_syslog_level;
		conf_stdout_level = hapd->conf->logger_stdout_level;
		conf_syslog = hapd->conf->logger_syslog;
		conf_stdout = hapd->conf->logger_stdout;
	} else {
		conf_syslog_level = conf_stdout_level = 0;
		conf_syslog = conf_stdout = (unsigned int) -1;
	}

	switch (module) {
	case HOSTAPD_MODULE_IEEE80211:
		module_str = "IEEE 802.11";
		break;
	case HOSTAPD_MODULE_IEEE8021X:
		module_str = "IEEE 802.1X";
		break;
	case HOSTAPD_MODULE_RADIUS:
		module_str = "RADIUS";
		break;
	case HOSTAPD_MODULE_WPA:
		module_str = "WPA";
		break;
	case HOSTAPD_MODULE_DRIVER:
		module_str = "DRIVER";
		break;
	case HOSTAPD_MODULE_IAPP:
		module_str = "IAPP";
		break;
	case HOSTAPD_MODULE_MLME:
		module_str = "MLME";
		break;
	default:
		module_str = NULL;
		break;
	}

	if (hapd && hapd->conf && addr)
		os_snprintf(format, maxlen, "%s: STA " MACSTR "%s%s: %s",
			    hapd->conf->iface, MAC2STR(addr),
			    module_str ? " " : "", module_str, txt);
	else if (hapd && hapd->conf)
		os_snprintf(format, maxlen, "%s:%s%s %s",
			    hapd->conf->iface, module_str ? " " : "",
			    module_str, txt);
	else if (addr)
		os_snprintf(format, maxlen, "STA " MACSTR "%s%s: %s",
			    MAC2STR(addr), module_str ? " " : "",
			    module_str, txt);
	else
		os_snprintf(format, maxlen, "%s%s%s",
			    module_str, module_str ? ": " : "", txt);

	if ((conf_stdout & module) && level >= conf_stdout_level) {
		wpa_debug_print_timestamp();
		printf("%s\n", format);
	}

#ifndef CONFIG_NATIVE_WINDOWS
	if ((conf_syslog & module) && level >= conf_syslog_level) {
		int priority;
		switch (level) {
		case HOSTAPD_LEVEL_DEBUG_VERBOSE:
		case HOSTAPD_LEVEL_DEBUG:
			priority = LOG_DEBUG;
			break;
		case HOSTAPD_LEVEL_INFO:
			priority = LOG_INFO;
			break;
		case HOSTAPD_LEVEL_NOTICE:
			priority = LOG_NOTICE;
			break;
		case HOSTAPD_LEVEL_WARNING:
			priority = LOG_WARNING;
			break;
		default:
			priority = LOG_INFO;
			break;
		}
		syslog(priority, "%s", format);
	}
#endif /* CONFIG_NATIVE_WINDOWS */

	os_free(format);
}
#endif /* CONFIG_NO_HOSTAPD_LOGGER */


/**
 * hostapd_init - Allocate and initialize per-interface data
 * @config_file: Path to the configuration file
 * Returns: Pointer to the allocated interface data or %NULL on failure
 *
 * This function is used to allocate main data structures for per-interface
 * data. The allocated data buffer will be freed by calling
 * hostapd_cleanup_iface().
 */
static struct hostapd_iface * hostapd_init(const char *config_file)
{
	struct hostapd_iface *hapd_iface = NULL;
	struct hostapd_config *conf = NULL;
	struct hostapd_data *hapd;
	size_t i;

	hapd_iface = os_zalloc(sizeof(*hapd_iface));
	if (hapd_iface == NULL)
		goto fail;

	hapd_iface->reload_config = hostapd_reload_config;
	hapd_iface->config_read_cb = hostapd_config_read;
	hapd_iface->config_fname = os_strdup(config_file);
	if (hapd_iface->config_fname == NULL)
		goto fail;
	hapd_iface->ctrl_iface_init = hostapd_ctrl_iface_init;
	hapd_iface->ctrl_iface_deinit = hostapd_ctrl_iface_deinit;
	hapd_iface->for_each_interface = hostapd_for_each_interface;

	conf = hostapd_config_read(hapd_iface->config_fname);
	if (conf == NULL)
		goto fail;
	hapd_iface->conf = conf;

	hapd_iface->num_bss = conf->num_bss;
	hapd_iface->bss = os_zalloc(conf->num_bss *
				    sizeof(struct hostapd_data *));
	if (hapd_iface->bss == NULL)
		goto fail;

	for (i = 0; i < conf->num_bss; i++) {
		hapd = hapd_iface->bss[i] =
			hostapd_alloc_bss_data(hapd_iface, conf,
					       &conf->bss[i]);
		if (hapd == NULL)
			goto fail;
		hapd->msg_ctx = hapd;
	}

	return hapd_iface;

fail:
	if (conf)
		hostapd_config_free(conf);
	if (hapd_iface) {
		os_free(hapd_iface->config_fname);
		os_free(hapd_iface->bss);
		os_free(hapd_iface);
	}
	return NULL;
}


static int hostapd_driver_init(struct hostapd_iface *iface)
{
	struct wpa_init_params params;
	size_t i;
	struct hostapd_data *hapd = iface->bss[0];
	struct hostapd_bss_config *conf = hapd->conf;
	u8 *b = conf->bssid;

	if (hapd->driver == NULL || hapd->driver->hapd_init == NULL) {
		wpa_printf(MSG_ERROR, "No hostapd driver wrapper available");
		return -1;
	}

	/* Initialize the driver interface */
	if (!(b[0] | b[1] | b[2] | b[3] | b[4] | b[5]))
		b = NULL;

	os_memset(&params, 0, sizeof(params));
	params.bssid = b;
	params.ifname = hapd->conf->iface;
	params.ssid = (const u8 *) hapd->conf->ssid.ssid;
	params.ssid_len = hapd->conf->ssid.ssid_len;
	params.test_socket = hapd->conf->test_socket;
	params.use_pae_group_addr = hapd->conf->use_pae_group_addr;

	params.num_bridge = hapd->iface->num_bss;
	params.bridge = os_zalloc(hapd->iface->num_bss * sizeof(char *));
	if (params.bridge == NULL)
		return -1;
	for (i = 0; i < hapd->iface->num_bss; i++) {
		struct hostapd_data *bss = hapd->iface->bss[i];
		if (bss->conf->bridge[0])
			params.bridge[i] = bss->conf->bridge;
	}

	params.own_addr = hapd->own_addr;

	hapd->drv_priv = hapd->driver->hapd_init(hapd, &params);
	os_free(params.bridge);
	if (hapd->drv_priv == NULL) {
		wpa_printf(MSG_ERROR, "%s driver initialization failed.",
			   hapd->driver->name);
		hapd->driver = NULL;
		return -1;
	}

	return 0;
}


static void hostapd_interface_deinit_free(struct hostapd_iface *iface)
{
	const struct wpa_driver_ops *driver;
	void *drv_priv;
	if (iface == NULL)
		return;
	driver = iface->bss[0]->driver;
	drv_priv = iface->bss[0]->drv_priv;
	hostapd_interface_deinit(iface);
	if (driver && driver->hapd_deinit)
		driver->hapd_deinit(drv_priv);
	hostapd_interface_free(iface);
}


static struct hostapd_iface *
hostapd_interface_init(struct hapd_interfaces *interfaces,
		       const char *config_fname, int debug)
{
	struct hostapd_iface *iface;
	int k;

	wpa_printf(MSG_ERROR, "Configuration file: %s", config_fname);
	iface = hostapd_init(config_fname);
	if (!iface)
		return NULL;
	iface->interfaces = interfaces;

	for (k = 0; k < debug; k++) {
		if (iface->bss[0]->conf->logger_stdout_level > 0)
			iface->bss[0]->conf->logger_stdout_level--;
	}

	if (hostapd_driver_init(iface) ||
	    hostapd_setup_interface(iface)) {
		hostapd_interface_deinit_free(iface);
		return NULL;
	}

	return iface;
}


/**
 * handle_term - SIGINT and SIGTERM handler to terminate hostapd process
 */
static void handle_term(int sig, void *signal_ctx)
{
	wpa_printf(MSG_DEBUG, "Signal %d received - terminating", sig);
	eloop_terminate();
}


#ifndef CONFIG_NATIVE_WINDOWS

static int handle_reload_iface(struct hostapd_iface *iface, void *ctx)
{
	if (hostapd_reload_config(iface) < 0) {
		wpa_printf(MSG_WARNING, "Failed to read new configuration "
			   "file - continuing with old.");
	}
	return 0;
}


/**
 * handle_reload - SIGHUP handler to reload configuration
 */
static void handle_reload(int sig, void *signal_ctx)
{
	struct hapd_interfaces *interfaces = signal_ctx;
	wpa_printf(MSG_DEBUG, "Signal %d received - reloading configuration",
		   sig);
	hostapd_for_each_interface(interfaces, handle_reload_iface, NULL);
}


static void handle_dump_state(int sig, void *signal_ctx)
{
#ifdef HOSTAPD_DUMP_STATE
	struct hapd_interfaces *interfaces = signal_ctx;
	hostapd_for_each_interface(interfaces, handle_dump_state_iface, NULL);
#endif /* HOSTAPD_DUMP_STATE */
}
#endif /* CONFIG_NATIVE_WINDOWS */


static int hostapd_global_init(struct hapd_interfaces *interfaces)
{
	hostapd_logger_register_cb(hostapd_logger_cb);

	if (eap_server_register_methods()) {
		wpa_printf(MSG_ERROR, "Failed to register EAP methods");
		return -1;
	}

	if (eloop_init()) {
		wpa_printf(MSG_ERROR, "Failed to initialize event loop");
		return -1;
	}

#ifndef CONFIG_NATIVE_WINDOWS
	eloop_register_signal(SIGHUP, handle_reload, interfaces);
	eloop_register_signal(SIGUSR1, handle_dump_state, interfaces);
#endif /* CONFIG_NATIVE_WINDOWS */
	eloop_register_signal_terminate(handle_term, interfaces);

#ifndef CONFIG_NATIVE_WINDOWS
	//openlog("hostapd", 0, LOG_DAEMON); //##042 not needed
#endif /* CONFIG_NATIVE_WINDOWS */

	return 0;
}


static void hostapd_global_deinit(const char *pid_file)
{
#ifdef EAP_SERVER_TNC
	tncs_global_deinit();
#endif /* EAP_SERVER_TNC */

	eloop_destroy();

#ifndef CONFIG_NATIVE_WINDOWS
	closelog();
#endif /* CONFIG_NATIVE_WINDOWS */

	eap_server_unregister_methods();
}


struct hapd_interfaces interfaces;
char *pid_file = NULL;

int hostapd_iface_init(void)
{
	int debug = 0;

	if (os_program_init())
		return -1;

	//enable debug output: "-K -t -d"
	wpa_debug_timestamp++;
	wpa_debug_show_keys++;

	//note: do these twice to get more debug
	debug++;
	if (wpa_debug_level > 0)
		wpa_debug_level--;

	interfaces.count = 1;
	interfaces.iface = os_malloc(interfaces.count *
				     sizeof(struct hostapd_iface *));
	if (interfaces.iface == NULL) {
		wpa_printf(MSG_ERROR, "malloc failed\n");
		return -1;
	}

	if (hostapd_global_init(&interfaces))
		return -1;

	/* Initialize interfaces */
	interfaces.iface[0] = hostapd_interface_init(&interfaces,
						     "hostapd.conf.003",
						     debug);
	if (!interfaces.iface[0]) {
		hostapd_iface_delete();
		return -1;
	}

//##019	if (eloop_running_part1() == 0) {
	eloop_running_part1();
	{
		{
			//##020 run eloop some rounds to get the state machines to correct states
			// TODO handle this with timer
			int ii = 0;
			while (ii < 5) {
				usleep(500000);
				eloop_running_part2(NULL, 0);
				wpa_printf(MSG_DEBUG, "XXXX first steps %d", ii);
				ii++;
			}
		}
//		while (eloop_running_part2(NULL, 0) == 0) {
//			wpa_printf(MSG_DEBUG, "XXXX timer timeout");
//		}
	}

	return 0;
}

int hostapd_iface_delete(void)
{
	/* Deinitialize all interfaces */
	hostapd_interface_deinit_free(interfaces.iface[0]);
	os_free(interfaces.iface);

	hostapd_global_deinit(pid_file);
	os_free(pid_file);

	os_program_deinit();

	return 0;
}


int hostapd_create_registrar_state_machine(void **rsm)
{
	rsm = NULL;
	return 0;
}

int hostapd_start_registrar_state_machine(void *rsm,
					  unsigned char* received_message,
					  int received_message_len)
{
	wpa_printf(MSG_DEBUG, "hostapd_start_registrar_state_machine");

#define NO_TIMEOUT   0
#define ANY_ENROLLEE 0
	const char *pin_code = "49226874";

/* if ( wps_registrar_add_pin(hapd->wps->registrar, ANY_ENROLLEE,
      (const u8 *) pin_code, os_strlen(pin_code),
      NO_TIMEOUT)) != 0 ) */
	if ( wps_registrar_add_pin(interfaces.iface[0]->bss[0]->wps->registrar, ANY_ENROLLEE,
				   (const u8 *) pin_code, os_strlen(pin_code),
				   NO_TIMEOUT) != 0 ) {
	}

#if 0
	// Generate cli command: "wpa_supplicant WPS_PIN any 1111"
	size_t resp_len;
	char *cli_req = strdup("WPS_PIN any 49226874"); //##037 release mem
	wpa_supplicant_ctrl_iface_process((struct wpa_supplicant *)global->ifaces,
					  cli_req, &resp_len);
#endif
        associate_sta();
	{
		//##020 run eloop some rounds to get the state machines to correct states
		// TODO handle this with timer
		int ii = 0;
		while (ii < 3) {
			usleep(200000);
			eloop_running_part2(NULL, 0);
			wpa_printf(MSG_DEBUG, "stepping eloop %d", ii);
			ii++;
		}
	}
        eapol_start_from_sta();
	{
		//##020 run eloop some rounds to get the state machines to correct states
		// TODO handle this with timer
		int ii = 0;
		while (ii < 3) {
			usleep(200000);
			eloop_running_part2(NULL, 0);
			wpa_printf(MSG_DEBUG, "stepping eloop %d", ii);
			ii++;
		}
	}
        eapol_nnnn_from_sta();
	{
		//##020 run eloop some rounds to get the state machines to correct states
		// TODO handle this with timer
		int ii = 0;
		while (ii < 3) {
			usleep(200000);
			eloop_running_part2(NULL, 0);
			wpa_printf(MSG_DEBUG, "stepping eloop %d", ii);
			ii++;
		}
	}

	//((struct wpa_supplicant *)global->ifaces)->drv_priv,
        //send_to_test_driver(send_resp_drv, received_message, received_message_len);
        send_to_test_driver(eloop_drv_get(), received_message, received_message_len);
	{
		//##020 run eloop some rounds to get the state machines to correct states
		// TODO handle this with timer
		int ii = 0;
		while (ii < 10) {
			usleep(200000);
			eloop_running_part2(NULL, 0);
			wpa_printf(MSG_DEBUG, "stepping eloop %d", ii);
			ii++;
		}
	}
#if 0
	if (send_eapol_data != NULL) {
		wpa_printf(MSG_DEBUG, "start enrollee sm, out msg available, len:%d", send_eapol_data_len);
		*next_message_len = send_eapol_data_len;
		*next_message = send_eapol_data; //##034 who will release this memory?
		send_eapol_data = NULL;
		send_eapol_data_len = 0;
	}
	//##25 TODO: handle error case here
#endif
	return 0;
}

int hostapd_stop_registrar_state_machine(void *rsm)
{
	return 0;
}

//status values directly from wpsutil ##003
typedef enum {WPSU_SM_E_PROCESS,WPSU_SM_E_SUCCESS,WPSU_SM_E_SUCCESSINFO,WPSU_SM_E_FAILURE,WPSU_SM_E_FAILUREEXIT} wpsu_enrollee_sm_status;
int hostapd_update_registrar_state_machine(void* rsm,
						 unsigned char* received_message,
						 int received_message_len,
						 unsigned char** next_message,
						 int* next_message_len,
						 int* ready)
{
#if 0
        send_to_test_driver(send_resp_drv, received_message, received_message_len);
	wpa_printf(MSG_DEBUG, "hostapd_update_registrar_state_machine");
	eloop_running_part2(NULL, 0);
	if (send_eapol_data != NULL) {
		wpa_printf(MSG_DEBUG, "update enrollee sm, out msg available, len:%d", send_eapol_data_len);
		wpa_hexdump(MSG_MSGDUMP, "data: ", send_eapol_data, send_eapol_data_len);
		*next_message_len = send_eapol_data_len;
		*next_message = send_eapol_data; //##034 who will release this memory?
		send_eapol_data = NULL;
		send_eapol_data_len = 0;
	}
	//##25 TODO: handle error case here
	//TODO struct eapol_sm *sm = ((struct wpa_supplicant *)global->ifaces)->eapol; //##041
	//TODO struct eap_sm *sm2 = sm->eap;
	//TODO then check eap state from sm somehow
#endif
	return 0;
}

static void send_to_test_driver(void *drv, const u8 *data, size_t data_len)
{
	const u8 msg_header[] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //??
				 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, //addr
				 0xbb, 0xbb, //??
				 0x02, 0x00, 0x00, 0x00,   //struct ieee802_1x_hdr
				 0x02, 0x68, 0x01, 0x84,   //eap_hdr handled in eap_sm_parseEapReq()
				 0xfe, 0x00, 0x37, 0x2a, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00};  //??, handled in eap_sm_parseEapReq()

	u8 *whole_msg;
	size_t whole_msg_len;
//	struct ieee802_1x_hdr *hdr;

	whole_msg_len = 32 + data_len;
	whole_msg = os_malloc(whole_msg_len);
	memcpy(whole_msg, msg_header, 32);
	memcpy(&whole_msg[32], data, data_len);
	//##027 release *data memory??

//	hdr = (struct ieee802_1x_hdr *)&whole_msg[14];
//	hdr->length = 0x01;//host_to_be16(data_len);
	whole_msg[16] = whole_msg[20] = (data_len + 14) / 256; //##029
	whole_msg[17] = whole_msg[21] = (data_len + 14) % 256; //##029

	wpa_driver_test_eapol_inject(drv, whole_msg, whole_msg_len);
}

static void associate_sta(void)
{
//	char *assoc_msg = "02:00:9a:f2:d6:0e 74657374 dd0e0050f204104a000110103a000101";
	char *assoc_msg = "02:00:00:00:00:01 74657374 dd0e0050f204104a000110103a000101";
	wpa_driver_test_assoc_inject(eloop_drv_get(), assoc_msg);
}

static void eapol_start_from_sta()
{
	u8 msg[] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //??
		    0x02, 0x00, 0x00, 0x00, 0x00, 0x01, //addr
		    0xbb, 0xbb, //??
		    0x01, 0x01, 0x00, 0x00}; //EAPOL start
	size_t msg_len = 14 + 4;

	wpa_driver_test_eapol_inject(eloop_drv_get(), msg, msg_len);
}

static void eapol_nnnn_from_sta()
{
	u8 msg[] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //??
		    0x02, 0x00, 0x00, 0x00, 0x00, 0x01, //addr
		    0xbb, 0xbb, //??
		    0x01, 0x00, 0x00, 0x22, 0x02, 0x67, 0x00, 0x22,
		    0x01, 0x57, 0x46, 0x41, 0x2d, 0x53, 0x69, 0x6d,
		    0x70, 0x6c, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69,
		    0x67, 0x2d, 0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c,
		    0x65, 0x65, 0x2d, 0x31, 0x2d, 0x30};
	size_t msg_len = 14 + 38;

	wpa_driver_test_eapol_inject(eloop_drv_get(), msg, msg_len);
}
