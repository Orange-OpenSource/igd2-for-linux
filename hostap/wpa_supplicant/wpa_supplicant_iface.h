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

#ifndef WPA_SUPPLICANT_IFACE_H
#define WPA_SUPPLICANT_IFACE_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * wpa_supplicant_iface configuration data
 *
 * This data structure is a subset of internal wpa_config structure,
 * plus device_pin
 */
typedef struct {
	char *device_pin;
	unsigned char uuid[16];
	char *device_name;
	char *manufacturer;
	char *model_name;
	char *model_number;
	char *serial_number;
	char *device_type;
	char *config_methods;
} wpa_supplicant_wps_enrollee_config;


int wpa_supplicant_iface_init(wpa_supplicant_wps_enrollee_config *config);
int wpa_supplicant_iface_delete(void);

int wpa_supplicant_create_enrollee_state_machine(void **esm);
int wpa_supplicant_start_enrollee_state_machine(void *esm,
						unsigned char** next_message,
						int* next_message_len);
int wpa_supplicant_stop_enrollee_state_machine(void *esm);

//status values for 'int *ready' output parameter
typedef enum {WPASUPP_SM_E_PROCESS,
	      WPASUPP_SM_E_SUCCESS,
	      WPASUPP_SM_E_SUCCESSINFO,
	      WPASUPP_SM_E_FAILURE,
	      WPASUPP_SM_E_FAILUREEXIT} wpasupp_enrollee_sm_status;
int wpa_supplicant_update_enrollee_state_machine(void* esm,
						 unsigned char* received_message,
						 int received_message_len,
						 unsigned char** next_message,
						 int* next_message_len,
						 int* ready);

  char *wpa_supplicant_get_pin(void);

unsigned char *wpa_supplicant_base64_encode(const unsigned char *src,
						   size_t len,
						   size_t *out_len);

unsigned char *wpa_supplicant_base64_decode(const unsigned char *src,
						   size_t len,
						   size_t *out_len);

void wpa_supplicant_hmac_sha256(const unsigned char *key, size_t key_len,
				const unsigned char *data, size_t data_len,
				unsigned char *mac);
#ifdef __cplusplus
}
#endif

#endif //WPA_SUPPLICANT_IFACE_H
