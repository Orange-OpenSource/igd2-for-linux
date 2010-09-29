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


/**
 * wpa_supplicant_iface_init - Initialize WPA supplicant library
 * @config: Configuration parameters
 * Returns: 0 on success, -1 on failure
 */
int wpa_supplicant_iface_init(wpa_supplicant_wps_enrollee_config *config);

/**
 * wpa_supplicant_iface_delete - Destructs WPA supplicant library.
 * Releases resources reserved in wpa_supplicant_iface_init().
 * @config: Configuration parameters
 * Returns: 0 on success, -1 on failure
 */
int wpa_supplicant_iface_delete(void);

/**
 * wpa_supplicant_create_enrollee_state_machine - Start WPS enrollee state machine
 * @esm: OUT Handle to enrollee state machine
 * Returns: 0 on success, -1 on failure
 */
int wpa_supplicant_create_enrollee_state_machine(void **esm);

/**
 * wpa_supplicant_start_enrollee_state_machine - Stop WPS enrollee state machine
 * @esm: Handle to enrollee state machine
 * @next_message: OUT new message going to registrar, typically M1
 * @next_message_len: OUT length
 * Returns: 0 on success, -1 on failure
 */
int wpa_supplicant_start_enrollee_state_machine(void *esm,
						unsigned char** next_message,
						int* next_message_len);

/**
 * wpa_supplicant_stop_enrollee_state_machine - Stop WPS enrollee state machine
 * @esm: Handle to enrollee state machine
 * Returns: 0 on success, -1 on failure
 */
int wpa_supplicant_stop_enrollee_state_machine(void *esm);

/**
 * Status values for 'int *ready' output parameter in wpa_supplicant_update_enrollee_state_machine()
 */
typedef enum {WPASUPP_SM_E_PROCESS,
	      WPASUPP_SM_E_SUCCESS,
	      WPASUPP_SM_E_SUCCESSINFO,
	      WPASUPP_SM_E_FAILURE,
	      WPASUPP_SM_E_FAILUREEXIT} wpasupp_enrollee_sm_status;

/**
 * wpa_supplicant_update_enrollee_state_machine - Update WPS enrollee state machine
 * @esm: Handle to enrollee state machine
 * @received_message: message coming from registrar, typically one of these: M2, M2D, M4, M6, M8
 * @received_message_len: length
 * @next_message: OUT new message going to registrar, typically one of these: M1, M3, M5, M7
 * @next_message_len: OUT length
 * @ready: OUT new state
 * Returns: 0 on success, -1 on failure
 */
int wpa_supplicant_update_enrollee_state_machine(void* esm,
						 unsigned char* received_message,
						 int received_message_len,
						 unsigned char** next_message,
						 int* next_message_len,
						 int* ready);

/**
 * wpa_supplicant_get_pin - get WPS PIN
 * Returns: Pointer to PIN on success, NULL on failure
 * Note! Caller must release the reserved memory area with free()
 */
char *wpa_supplicant_get_pin(void);

/**
 * wpa_supplicant_base64_encode - encode binary data block into base64
 * @src: source data block
 * @len: source data block length
 * @out_len: OUT encoded data block length
 * Returns: Pointer to encoded data block on success, NULL on failure
 * Note! Caller must release the reserved memory area with free()
 */
unsigned char *wpa_supplicant_base64_encode(const unsigned char *src,
					    size_t len,
					    size_t *out_len);

/**
 * wpa_supplicant_base64_decode - decode base64 data block into binary
 * @src: source data block
 * @len: source data block length
 * @out_len: OUT decoded data block length
 * Returns: Pointer to decoded data block on success, NULL on failure
 * Note! Caller must release the reserved memory area with free()
 */
unsigned char *wpa_supplicant_base64_decode(const unsigned char *src,
					    size_t len,
					    size_t *out_len);

/**
 * wpa_supplicant_hmac_sha256 - HMAC-SHA256 over data buffer (RFC 2104)
 * @key: Key for HMAC operations
 * @key_len: Length of the key in bytes
 * @data: Pointers to the data area
 * @data_len: Length of the data area
 * @mac: Buffer for the hash (20 bytes)
 */
void wpa_supplicant_hmac_sha256(const unsigned char *key, size_t key_len,
				const unsigned char *data, size_t data_len,
				unsigned char *mac);
#ifdef __cplusplus
}
#endif

#endif //WPA_SUPPLICANT_IFACE_H
