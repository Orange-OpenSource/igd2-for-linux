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

extern struct wpa_driver_ops *wpa_drivers[];

int eloop_running_start(void);
int eloop_running_step(const u8 *data,
		       size_t data_len);

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

const u8 *sendto_data = NULL;
size_t sendto_data_len = 0;

void test_driver_set_sendto( int (*sendto_cb)(const u8 *data, size_t) );

static int wpa_supplicant_iface_sendto_cb(const u8 *data, size_t data_len)
{
	wpa_printf(MSG_DEBUG, "XXXX sendto cb");
	sendto_data = data + 18;
	sendto_data_len = data_len - 18;
	return 0;
}


//modified from main() (in wpa_supplicant/main.c)
int wpa_supplicant_iface_init(void)
{
	int i;
	struct wpa_interface *iface;
	int iface_count, exitcode = -1;
	struct wpa_params params;

	test_driver_set_sendto(wpa_supplicant_iface_sendto_cb);

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
	char *cli_req = strdup("WPS_PIN any 1111"); //##011 release mem
	wpa_supplicant_ctrl_iface_process((struct wpa_supplicant *)global->ifaces,
					  cli_req, &resp_len);
	{
		//##020 run eloop some rounds to get the state machines to correct states
		// TODO handle this with timer
		int ii = 0;
		while (ii < 10) {
			usleep(500000);
			//sleep(1);
			eloop_running_step(NULL, 0);
			wpa_printf(MSG_DEBUG, "XXXX second steps %d", ii);
			ii++;
		}
	}
	if (sendto_data != NULL) {
		wpa_printf(MSG_DEBUG, "XXXX data available, len:%d", sendto_data_len);
		*next_message = (unsigned char*)sendto_data;
		*next_message_len = sendto_data_len;
		sendto_data = NULL;
		sendto_data_len = 0;
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
	return 0;
}
