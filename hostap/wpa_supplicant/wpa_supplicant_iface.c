/**
 * This file is part of Nokia InternetGatewayDevice v2 reference implementation
 * Copyright © 2010 Nokia Corporation and/or its subsidiary(-ies).
 * Contact: mika.saaranen@nokia.com
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

#include "includes.h"
#ifdef __linux__
#include <fcntl.h>
#endif /* __linux__ */

#include "common.h"
#include "wpa_supplicant_i.h"
#include "wps/wps_i.h"
#include "utils/wpabuf.h"
#include "driver_i.h"
#include "ctrl_iface.h"
#include "base64.h"
#include "crypto/sha256.h"
#include "wpa_supplicant_iface.h"
#include "config.h"

extern struct wpa_driver_ops *wpa_drivers[];

//in eloop.c
int eloop_running_part1(void);
int eloop_running_part2(const u8 *data,
			size_t data_len);
//in driver_test.c
void wpa_driver_test_eapol_inject(void *drv, const u8 *data, size_t data_len);
void test_driver_set_send_eapol_cb( int (*send_eapol_cb)(void *drv, const u8 *data, size_t) );

//in wps_supplicant.c
int wpas_wps_status_get(void);

static int inject_cli_command(void);
static void send_to_wpa_driver(void *drv, const u8 *data, size_t data_len);
static int handle_eapol_req_immediately(void *drv, const u8 *data, size_t data_len);
static void generate_and_inject_eapol_resp(void *drv);

struct wpa_params params;
struct wpa_interface *g_iface;
struct wpa_global *global;
char *g_pin_code = NULL;
int g_pbc_method_in_use = 0; //Flag which tells if we are using WPS Push Button Config

//TODO: combine to struct
u8 *send_eapol_data = NULL;
size_t send_eapol_data_len = 0;

// When this var is not 0, req is being handled internally in this module.
int internally_handled_msg_id = 0;

// driver handle for response message sending
void *send_resp_drv = NULL;

static int wpa_supplicant_iface_send_eapol_cb(void *drv, const u8 *data, size_t data_len)
{
	// First check if we must handle this message internally in this module
	if (handle_eapol_req_immediately(drv, data, data_len) == 0) {
		return 0;
	}

	// Save the message to be delivered out of interface
	wpa_printf(MSG_DEBUG, "wpa_supplicant_iface_send_eapol_cb, check the data structure in code");
	send_eapol_data_len = data_len - 18;  //TODO: check this
	send_eapol_data = malloc(send_eapol_data_len); //TODO: who will release this memory?
	memcpy(send_eapol_data, data + 18, send_eapol_data_len);
	return 0;
}


//modified from main() (in wpa_supplicant/main.c)
int wpa_supplicant_iface_init(wpa_supplicant_wps_enrollee_config *config_in)
{
	int exitcode = -1;

	test_driver_set_send_eapol_cb(wpa_supplicant_iface_send_eapol_cb);

	if (os_program_init())
		return -1;

	os_memset(&params, 0, sizeof(params));
	//hardcoded args, see main()
	params.wpa_debug_level = MSG_EXCESSIVE;
	params.wpa_debug_timestamp++;
	params.wpa_debug_show_keys++;

	exitcode = 0;

	g_pin_code = os_strdup(config_in->device_pin);
	if (strcmp(config_in->config_methods, "push_button") == 0) {
		g_pbc_method_in_use = 1;
	}
	else
	{
		g_pbc_method_in_use = 0;
	}

	struct wpa_config *conf1 = os_zalloc(sizeof(struct wpa_config));
	conf1->ssid = NULL;
	conf1->pssid = NULL;
	conf1->num_prio = 0;
	conf1->eapol_version = 1;
	conf1->ap_scan = 0;
	conf1->ctrl_interface = NULL;
	conf1->ctrl_interface_group = NULL;
	conf1->fast_reauth = 1;
	conf1->opensc_engine_path = NULL;
	conf1->pkcs11_engine_path = NULL;
	conf1->pkcs11_module_path = NULL;
	conf1->driver_param = NULL;
	conf1->dot11RSNAConfigPMKLifetime = 0;
	conf1->dot11RSNAConfigPMKReauthThreshold = 0;
	conf1->dot11RSNAConfigSATimeout = 0;
	conf1->update_config = 0;
	conf1->blobs = NULL;
	memcpy(conf1->uuid, config_in->uuid, sizeof(conf1->uuid));
	conf1->device_name = os_strdup(config_in->device_name);
	conf1->manufacturer = os_strdup(config_in->manufacturer);
	conf1->model_name = os_strdup(config_in->model_name);
	conf1->model_number = os_strdup(config_in->model_number);
	conf1->serial_number = os_strdup(config_in->serial_number);
	conf1->device_type = os_strdup(config_in->device_type);
	conf1->config_methods = os_strdup(config_in->config_methods);
	//u8 os_version[4];
	//char country[2];
	conf1->wps_cred_processing = 0;
	conf1->bss_max_count = 200;
	conf1->filter_ssids = 0;

	wpa_supplicant_set_config(conf1);

	return exitcode;
}

int wpa_supplicant_iface_delete(void)
{
	os_free(g_pin_code);
	g_pin_code = NULL;

	os_program_deinit();

	return 0;
}

int wpa_supplicant_create_enrollee_state_machine(void **esm)
{
	int exitcode = 0;

	wpa_printf(MSG_DEBUG, "create_enrollee_state_machine");

	g_iface = os_zalloc(sizeof(struct wpa_interface));
	if (g_iface == NULL)
		return -1;

	g_iface->driver = "test";
	g_iface->ifname = "test_if";
	g_iface->confname = NULL;

	global = wpa_supplicant_init(&params);
	if (global == NULL) {
		wpa_printf(MSG_ERROR, "Failed to initialize wpa_supplicant");
		return -1;
	}

	if (wpa_supplicant_add_iface(global, g_iface) == NULL)
		exitcode = -1;

	if (exitcode == 0) {
#if 1 //TODO: check this
		eloop_running_part1();
		eloop_running_part2(NULL, 0);
#else
		if (eloop_running_part1() == 0) {
			while (eloop_running_part2(NULL, 0) == 0) {
				wpa_printf(MSG_DEBUG, "XXXX timer timeout");
			}
		}
#endif
	}

	esm = NULL;
	return 0;
}

int wpa_supplicant_start_enrollee_state_machine(void *esm,
						unsigned char** next_message,
						int* next_message_len)
{
	int ret;
	ret = inject_cli_command();
	if (ret != 0) {
		return ret;
	}

	{
		// Run eloop some rounds to get the state machines to correct states
		// TODO: handle this with timer
		int ii = 0;
		while (ii < 10) {
			usleep(200000);
			eloop_running_part2(NULL, 0);
			generate_and_inject_eapol_resp(send_resp_drv);
			wpa_printf(MSG_DEBUG, "stepping eloop %d", ii);
			ii++;
		}
	}
	if (send_eapol_data != NULL) {
		wpa_printf(MSG_DEBUG, "start enrollee sm, out msg available, len:%d", send_eapol_data_len);
		*next_message_len = send_eapol_data_len;
		*next_message = send_eapol_data; //TODO: who will release this memory?
		send_eapol_data = NULL;
		send_eapol_data_len = 0;
	}
	// TODO: handle error case here
	return 0;
}

int wpa_supplicant_stop_enrollee_state_machine(void *esm)
{
	wpa_supplicant_deinit(global);
	global = NULL;

	if (g_iface != NULL)
		os_free(g_iface);
	g_iface = NULL;

	return 0;
}

int wpa_supplicant_update_enrollee_state_machine(void* esm,
						 unsigned char* received_message,
						 int received_message_len,
						 unsigned char** next_message,
						 int* next_message_len,
						 int* ready)
{
	send_to_wpa_driver(send_resp_drv, received_message, received_message_len);
	wpa_printf(MSG_DEBUG, "wpa_supplicant_update_enrollee_state_machine");
	eloop_running_part2(NULL, 0);
	if (send_eapol_data != NULL) {
		wpa_printf(MSG_DEBUG, "update enrollee sm, out msg available, len:%d", send_eapol_data_len);
		wpa_hexdump(MSG_MSGDUMP, "data: ", send_eapol_data, send_eapol_data_len);
		*next_message_len = send_eapol_data_len;
		*next_message = send_eapol_data; //TODO: who will release this memory?
		send_eapol_data = NULL;
		send_eapol_data_len = 0;
	}
	//TODO: handle error case here
	//TODO: check if there is a better way to find out the state
	*ready = wpas_wps_status_get();
	return 0;
}


struct wpabuf * wps_build_wsc_nack1(void);

unsigned char *wpa_supplicant_generate_nack(int* len)
{
//	wps_build_wsc_nack( ((struct wpa_supplicant *)global->ifaces)->eapol->eap->eap_method_priv->wps );
	struct wpabuf *tmp_buf = wps_build_wsc_nack1();
	unsigned char *ret_buf = NULL;
	*len = 0;
	if (tmp_buf != NULL) {
		ret_buf = malloc(wpabuf_len(tmp_buf));
		if (ret_buf != NULL) {
			*len = wpabuf_len(tmp_buf);
			memcpy(ret_buf, wpabuf_head_u8(tmp_buf), *len);
		}
	}
	wpabuf_free(tmp_buf);
	return ret_buf;
}

char *wpa_supplicant_get_pin(void)
{
	char *tmp_pin;
	char *ret_pin;
	
	// Dig up the PIN. Hmm, can not really understand why PIN is in variable "phase1"???
	tmp_pin = wpa_config_get(((struct wpa_supplicant *)global->ifaces)->conf->ssid, "phase1");

	// Do not return memory blocks reserved with os_*alloc(), because they must be freed with os_free().
	// Drop unnecessary characters before and after the PIN.
	tmp_pin[13] = '\0';
	ret_pin = strdup(&tmp_pin[5]);
	os_free(tmp_pin);

	return ret_pin;
}

unsigned char *wpa_supplicant_base64_encode(const unsigned char *src,
					    size_t len,
					    size_t *out_len)
{
	unsigned char *wpa_trace_alloc = base64_encode(src, len, out_len);

	// Note! do not use os_malloc, because if WPA_TRACE is defined, os_free() is not the same as free()
	unsigned char *correct_alloc = malloc(*out_len + 1);
	memcpy(correct_alloc, wpa_trace_alloc, *out_len);

	os_free(wpa_trace_alloc);

	(*out_len) --; //exclude trailing 0x0a from the length
	correct_alloc[*out_len] = '\0'; // overwrite 0x0a with a NUL
	return correct_alloc;
}

unsigned char *wpa_supplicant_base64_decode(const unsigned char *src,
					    size_t len,
					    size_t *out_len)
{
	unsigned char *wpa_trace_alloc = base64_decode(src, len, out_len);

	// Note! do not use os_malloc, because if WPA_TRACE is defined, os_free() is not the same as free()
	unsigned char *correct_alloc = malloc(*out_len + 1);
	memcpy(correct_alloc, wpa_trace_alloc, *out_len);

	// Have to add trailing NUL to the decoded block
	correct_alloc[*out_len] = '\0';
	os_free(wpa_trace_alloc);
	return correct_alloc;
}

/**
 * Returns 0 on success, -1 on failure
 */
static int inject_cli_command(void)
{
	char *cli_resp;
	size_t resp_len;
	const int cli_req_max_len = 100;
	char *cli_req = os_malloc(cli_req_max_len + 1);

	if (g_pbc_method_in_use != 0) {
		// Tell wpa_supplicant to use PBC method
		const char *cli_cmd = "WPS_PBC any";
		snprintf(cli_req, cli_req_max_len, "%s", cli_cmd);
	}
	else {
		// Tell wpa_supplicant to use PIN method
		const char *cli_cmd = "WPS_PIN any";

		if (strlen(g_pin_code) == 0) {
			// Empty PIN => wpa_supplicant generates a new PIN
			snprintf(cli_req, cli_req_max_len, "%s", cli_cmd);
		} else {
			// Use "label" PIN
			snprintf(cli_req, cli_req_max_len, "%s %s", cli_cmd, g_pin_code);
		}
	}

	wpa_printf(MSG_DEBUG, "Request to wpa_supplicant_ctrl_iface_process():'%s'", cli_req);
	cli_resp = wpa_supplicant_ctrl_iface_process((struct wpa_supplicant *)global->ifaces,
							 cli_req, &resp_len);
	wpa_printf(MSG_DEBUG, "Response from wpa_supplicant_ctrl_iface_process():'%s'", cli_resp);

	os_free(cli_resp);
	os_free(cli_req);
	return 0;
}

static void send_to_wpa_driver(void *drv, const u8 *data, size_t data_len)
{
	const u8 msg_header[] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //?? TODO: add comment
				 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, //addr
				 0xbb, 0xbb, //?? TODO: add comment
				 0x02, 0x00, 0x00, 0x00,   //struct ieee802_1x_hdr
				 0x01, 0x2b, 0x00, 0x00,   //eap_hdr handled in eap_sm_parseEapReq()
				 0xfe, 0x00, 0x37, 0x2a, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00};  //??, handled in eap_sm_parseEapReq()

	u8 *whole_msg;
	size_t whole_msg_len;

	whole_msg_len = 32 + data_len;
	whole_msg = os_malloc(whole_msg_len);
	memcpy(whole_msg, msg_header, 32);
	memcpy(&whole_msg[32], data, data_len);
	//TODO: release *data memory??

	//TODO: replace with something like this:
	//	struct ieee802_1x_hdr *hdr;
	//	hdr = (struct ieee802_1x_hdr *)&whole_msg[14];
	//	hdr->length = 0x01;//host_to_be16(data_len);
	whole_msg[16] = whole_msg[20] = (data_len + 14) / 256;
	whole_msg[17] = whole_msg[21] = (data_len + 14) % 256;

	wpa_driver_test_eapol_inject(drv, whole_msg, whole_msg_len);
}

static void generate_and_inject_eapol_resp(void *drv)
{
	const u8 msg1_resp[] = {0x02, 0x00, 0x00, 0x05, 0x01, 0x67, 0x00, 0x05, 0x01}; // TODO: add comment
	const int msg1_resp_len = 9;

	const u8 msg2_resp[] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //?? TODO: add comment
				0x02, 0x00, 0x00, 0x00, 0x00, 0x01, //addr
				0xbb, 0xbb, //??
				0x02, 0x00, 0x00, 0x0e, 0x01, 0x68, 0x00, 0x0e, 0xfe, 0x00, 0x37, 0x2a, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00};
	const int msg2_resp_len = 14 + 18; //TODO: add comment

	if (internally_handled_msg_id == 1) {
		internally_handled_msg_id = 0;
		wpa_printf(MSG_DEBUG, "generate_and_inject_eapol_resp, response to msg1");
		wpa_driver_test_eapol_inject(drv, msg1_resp, msg1_resp_len);
	} else if (internally_handled_msg_id == 2) {
		internally_handled_msg_id = 0;
		wpa_printf(MSG_DEBUG, "generate_and_inject_eapol_resp, response to msg2");
		wpa_driver_test_eapol_inject(drv, msg2_resp, msg2_resp_len);
	}
}

static int handle_eapol_req_immediately(void *drv, const u8 *data, size_t data_len)
{
	const u8 msg1[] = {0x01, 0x01, 0x00, 0x00};
	const int msg1_len = 4;

	const u8 msg2[] = {0x01, 0x00, 0x00, 0x22, 0x02, 0x67, 0x00, 0x22, 0x01, 0x57, 0x46, 0x41, 0x2d, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2d, 0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x65, 0x2d, 0x31, 0x2d, 0x30};
	const int msg2_len = 38; //TODO: add comment

	send_resp_drv = drv; // store for later usage
	if (msg1_len == data_len &&
	    memcmp(msg1, data, data_len) == 0) {
		internally_handled_msg_id = 1;
		wpa_printf(MSG_DEBUG, "handle_eapol_req_immediately msg1 req");
		return 0;
	} else if (msg2_len == data_len &&
		   memcmp(msg2, data, data_len) == 0) {
		internally_handled_msg_id = 2;
		wpa_printf(MSG_DEBUG, "handle_eapol_req_immediately msg2 req");
		return 0;
	}
	return -1;
}

//Just a wrapper to hide the internal crypto method
void wpa_supplicant_hmac_sha256(const unsigned char *key, size_t key_len,
				const unsigned char *data, size_t data_len,
				unsigned char *mac)
{
	hmac_sha256(key, key_len, data, data_len, mac);
}
