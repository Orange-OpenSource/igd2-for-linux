//##008 update this text
/*
 * WPA Supplicant / main() function for UNIX like OSes and MinGW
 * Copyright (c) 2003-2007, Jouni Malinen <j@w1.fi>
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

#include "includes.h"
#ifdef __linux__
#include <fcntl.h>
#endif /* __linux__ */

#include "common.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "ctrl_iface.h"
#include "base64.h"

extern struct wpa_driver_ops *wpa_drivers[];

//in eloop.c
int eloop_running_start(void);
int eloop_running_step(const u8 *data,
		       size_t data_len);
//in driver_test.c
void wpa_driver_test_eapol_inject(void *drv, const u8 *data, size_t data_len);
void test_driver_set_send_eapol_cb( int (*send_eapol_cb)(void *drv, const u8 *data, size_t) );

void send_to_wpa_driver(void *drv, const u8 *data, size_t data_len);
int xxx_test_handle_req(void *drv, const u8 *data, size_t data_len);
void xxx_test_send_resp(void *drv);

static void license(void)
{
#ifndef CONFIG_NO_STDOUT_DEBUG
	printf("%s\n\n%s%s%s%s%s\n",
	       wpa_supplicant_version,
	       wpa_supplicant_full_license1,
	       wpa_supplicant_full_license2,
	       wpa_supplicant_full_license3,
	       wpa_supplicant_full_license4,
	       wpa_supplicant_full_license5);
#endif /* CONFIG_NO_STDOUT_DEBUG */
}

struct wpa_interface *ifaces;
struct wpa_global *global;

//##040 combine to struct
u8 *send_eapol_data = NULL;
size_t send_eapol_data_len = 0;

//##001
int test_msg_id = 0;
void *send_resp_drv = NULL; //##028

static int wpa_supplicant_iface_send_eapol_cb(void *drv, const u8 *data, size_t data_len)
{
	//##001
	if (xxx_test_handle_req(drv, data, data_len) == 0) {
		return 0;
	}

	wpa_printf(MSG_DEBUG, "XXXX send_eapol_cb, check the data structure in code");
	send_eapol_data_len = data_len - 18;  //##024 check this
	send_eapol_data = malloc(send_eapol_data_len); //##034 who will release this memory?
	memcpy(send_eapol_data, data + 18, send_eapol_data_len);
	return 0;
}


//modified from main() (in wpa_supplicant/main.c)
int wpa_supplicant_iface_init(void)
{
	int i;
	struct wpa_interface *iface;
	int iface_count, exitcode = -1;
	struct wpa_params params;

	test_driver_set_send_eapol_cb(wpa_supplicant_iface_send_eapol_cb);

	if (os_program_init())
		return -1;

	os_memset(&params, 0, sizeof(params));
	params.wpa_debug_level = MSG_INFO;

	iface = ifaces = os_zalloc(sizeof(struct wpa_interface));
	if (ifaces == NULL)
		return -1;
	iface_count = 1;

	//##002 hardcoded args for now
	iface->driver = "test";
	iface->ifname = "joo1";
	params.wpa_debug_level = 1; //"-dd" = 1 (more debugging), "-d" = 2
	iface->confname = "wpa_supplicant.conf.004";

	exitcode = 0;
	global = wpa_supplicant_init(&params);
	if (global == NULL) {
		wpa_printf(MSG_ERROR, "Failed to initialize wpa_supplicant");
		os_free(ifaces);
		os_free(params.pid_file);

		os_program_deinit();

		return -1;
	}

	for (i = 0; exitcode == 0 && i < iface_count; i++) {
		if ((ifaces[i].confname == NULL &&
		     ifaces[i].ctrl_interface == NULL) ||
		    ifaces[i].ifname == NULL) {
			if (iface_count == 1 && (params.ctrl_interface ||
						 params.dbus_ctrl_interface))
				break;
			exitcode = -1;
			break;
		}
		if (wpa_supplicant_add_iface(global, &ifaces[i]) == NULL)
			exitcode = -1;
	}

	if (exitcode == 0) {
//##019		if (eloop_running_start() == 0) {
		eloop_running_start();
		{
			{
				//##020 run eloop some rounds to get the state machines to correct states
				// TODO handle this with timer
				int ii = 0;
				while (ii < 5) {
					usleep(500000);
					eloop_running_step(NULL, 0);
					wpa_printf(MSG_DEBUG, "XXXX first steps %d", ii);
					ii++;
				}
			}
//			while (eloop_running_step(NULL, 0) == 0) {
//				wpa_printf(MSG_DEBUG, "XXXX timer timeout");
//			}
		}
	}

	return exitcode;
}

int wpa_supplicant_iface_delete(void)
{
	wpa_supplicant_deinit(global);

	os_free(ifaces);
//##1 needed?	os_free(params.pid_file);

	os_program_deinit();

	return 0;
}

int wpa_supplicant_create_enrollee_state_machine(void **esm)
{
	esm = NULL;
	return 0;
}

int wpa_supplicant_start_enrollee_state_machine(void *esm,
						unsigned char** next_message,
						int* next_message_len)
{
	//generate cli command: "wpa_supplicant wps_pin any 1111"
	size_t resp_len;
//	char *cli_req = strdup("WPS_PIN any 1111"); //##011 release mem
	char *cli_req = strdup("WPS_PIN any 49226874"); //##037 release mem
	wpa_supplicant_ctrl_iface_process((struct wpa_supplicant *)global->ifaces,
					  cli_req, &resp_len);
	{
		//##020 run eloop some rounds to get the state machines to correct states
		// TODO handle this with timer
		int ii = 0;
		while (ii < 10) {
			usleep(500000);
			eloop_running_step(NULL, 0);
			xxx_test_send_resp(send_resp_drv);
			wpa_printf(MSG_DEBUG, "XXXX second steps %d", ii);
			ii++;
		}
	}
	if (send_eapol_data != NULL) {
		wpa_printf(MSG_DEBUG, "XXXX data available in start, len:%d", send_eapol_data_len);
		*next_message_len = send_eapol_data_len;
		*next_message = send_eapol_data; //##034 who will release this memory?
		send_eapol_data = NULL;
		send_eapol_data_len = 0;
	}
	//##25 TODO: handle error case here
	return 0;
}

int wpa_supplicant_stop_enrollee_state_machine(void *esm)
{
	return 0;
}

//status values directly from wpsutil ##003
typedef enum {WPSU_SM_E_PROCESS,WPSU_SM_E_SUCCESS,WPSU_SM_E_SUCCESSINFO,WPSU_SM_E_FAILURE,WPSU_SM_E_FAILUREEXIT} wpsu_enrollee_sm_status;
int wpa_supplicant_update_enrollee_state_machine(void* esm,
						 unsigned char* received_message,
						 int received_message_len,
						 unsigned char** next_message,
						 int* next_message_len,
						 int* ready)
{
        send_to_wpa_driver(((struct wpa_supplicant *)global->ifaces)->drv_priv, //##041 replace with send_resp_drv?
			   received_message, received_message_len);
	{
		//##020 run eloop some rounds to get the state machines to correct states
		// TODO handle this with timer
		int ii = 0;
		while (ii < 3) {
			usleep(300000);
			eloop_running_step(NULL, 0);
			wpa_printf(MSG_DEBUG, "XXXX next steps %d", ii);
			ii++;
		}
	}
	if (send_eapol_data != NULL) {
		wpa_printf(MSG_DEBUG, "XXXX data available in update, len:%d", send_eapol_data_len);
		wpa_hexdump(MSG_MSGDUMP, "YYYY ", send_eapol_data, send_eapol_data_len); //##030
		*next_message_len = send_eapol_data_len;
		*next_message = send_eapol_data; //##034 who will release this memory?
		send_eapol_data = NULL;
		send_eapol_data_len = 0;
	}
	//##25 TODO: handle error case here
	return 0;
}

inline unsigned char *wpa_supplicant_base64_encode(const unsigned char *src,
						   size_t len,
						   size_t *out_len)
{
#ifdef WPA_TRACE
	unsigned char *wpa_trace_alloc = base64_encode(src, len, out_len);
	unsigned char *correct_alloc = malloc(*out_len);
	memcpy(correct_alloc, wpa_trace_alloc, *out_len);
	os_free(wpa_trace_alloc);
	return correct_alloc;
#else /* WPA_TRACE */
	return base64_encode(src, len, out_len);
#endif /* WPA_TRACE */
}

inline unsigned char *wpa_supplicant_base64_decode(const unsigned char *src,
						   size_t len,
						   size_t *out_len)
{
#ifdef WPA_TRACE
	unsigned char *wpa_trace_alloc = base64_decode(src, len, out_len);
	unsigned char *correct_alloc = malloc(*out_len);
	memcpy(correct_alloc, wpa_trace_alloc, *out_len);
	os_free(wpa_trace_alloc);
	return correct_alloc;
#else /* WPA_TRACE */
	return base64_decode(src, len, out_len);
#endif /* WPA_TRACE */
}


//##026
void send_to_wpa_driver(void *drv, const u8 *data, size_t data_len)
{
	const u8 msg_header[] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //??
				 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, //addr
				 0xbb, 0xbb, //??
				 0x02, 0x00, 0x00, 0x00,   //struct ieee802_1x_hdr
				 0x01, 0x2b, 0x00, 0x00,   //eap_hdr handled in eap_sm_parseEapReq()
				 0xfe, 0x00, 0x37, 0x2a, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00};  //??, handled in eap_sm_parseEapReq()

	u8 *whole_msg;
	size_t whole_msg_len;
//	struct ieee802_1x_hdr *hdr;

	wpa_printf(MSG_DEBUG, "wpa_driver_test_eapol_send drv:%08x", (unsigned)drv);
	whole_msg_len = 32 + data_len;
	whole_msg = os_malloc(whole_msg_len);
	memcpy(whole_msg, msg_header, 32);
	memcpy(&whole_msg[32], data, data_len);
	//##027 release *data memory??

//	hdr = (struct ieee802_1x_hdr *)&whole_msg[14];
//	hdr->length = 0x01;//host_to_be16(data_len);
	whole_msg[16] = whole_msg[20] = (data_len + 14) / 256; //##029
	whole_msg[17] = whole_msg[21] = (data_len + 14) % 256; //##029

	wpa_driver_test_eapol_inject(
		send_resp_drv, //##028
		whole_msg, whole_msg_len);
}

void xxx_test_send_resp(void *drv)
{
	const u8 msg1_resp[] = {0x02, 0x00, 0x00, 0x05, 0x01, 0x67, 0x00, 0x05, 0x01};
	const int msg1_resp_len = 9;

	wpa_printf(MSG_DEBUG, "xxx_test_send_resp drv:%08x", (unsigned)drv);
	const u8 msg2_resp[] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, //??
				0x02, 0x00, 0x00, 0x00, 0x00, 0x01, //addr
				0xbb, 0xbb, //??
				0x02, 0x00, 0x00, 0x0e, 0x01, 0x68, 0x00, 0x0e, 0xfe, 0x00, 0x37, 0x2a, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00};
	const int msg2_resp_len = 14 + 18;

	if (test_msg_id == 1) {
		test_msg_id = 0;
		wpa_printf(MSG_DEBUG, "xxx response to msg1");
		wpa_driver_test_eapol_inject(drv, msg1_resp, msg1_resp_len);
	} else if (test_msg_id == 2) {
		test_msg_id = 0;
		wpa_printf(MSG_DEBUG, "xxx response to msg2");
		wpa_driver_test_eapol_inject(drv, msg2_resp, msg2_resp_len);
	}
}

//##001
int xxx_test_handle_req(void *drv, const u8 *data, size_t data_len)
{
	const u8 msg1[] = {0x01, 0x01, 0x00, 0x00};
	const int msg1_len = 4;

	const u8 msg2[] = {0x01, 0x00, 0x00, 0x22, 0x02, 0x67, 0x00, 0x22, 0x01, 0x57, 0x46, 0x41, 0x2d, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2d, 0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x65, 0x2d, 0x31, 0x2d, 0x30};
	const int msg2_len = 38;

	wpa_printf(MSG_DEBUG, "xxx_test_handle_req drv:%08x", (unsigned)drv);
	send_resp_drv = drv; //##028 store for later usage
	if (msg1_len == data_len &&
	    memcmp(msg1, data, data_len) == 0) {
		test_msg_id = 1;
		wpa_printf(MSG_DEBUG, "xxx msg1 req");
		return 0;
	} else if (msg2_len == data_len &&
		   memcmp(msg2, data, data_len) == 0) {
		test_msg_id = 2;
		wpa_printf(MSG_DEBUG, "xxx msg2 req");
		return 0;
	}
	return -1;
}
