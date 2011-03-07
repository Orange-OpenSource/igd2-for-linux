/**
 * This file is part of Nokia InternetGatewayDevice v2 reference implementation
 * Copyright © 2010 Nokia Corporation and/or its subsidiary(-ies).
 * Contact: mika.saaranen@nokia.com
 * Developer(s): opensource@tieto.com, niilona@gmail.com
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
#ifndef HOSTAPD_IFACE_H
#define HOSTAPD_IFACE_H

#define	WPA_ADDITIONAL_DEBUG	1
#define	NEW_CONFIG_SPEC	// Configuration expects the M2D sent instead of M2 and so on ...

#ifdef __cplusplus
extern "C" {
#endif

#ifdef NEW_CONFIG_SPEC

//#include "wps/wps_defs.h"d

#define	M2_SIZE 1024
#define WPS_NONCE_LEN 16
#define WPS_UUID_LEN 16

typedef struct {
	int				wsc_last_sent_message_type;			//	enum	wps_msg_type wsc_last_sent_message_type;
	int				wsc_last_received_message_type;		//	enum	wps_msg_type wsc_last_received_message_type;
	int				wsc_msg_tot_cnt;
	int				wsc_start_cnt;
	int				wsc_ack_cnt;
	int				wsc_nack_cnt;
	int				wsc_msg_cnt;
	int				wsc_frack_ack_cnt;
	int				wsc_done_cnt;
	int				wsc_unknown_cnt;
	int				wsc_m1_cnt;
	int				wsc_m2_cnt;
	int				wsc_m3_cnt;
	int				wsc_m4_cnt;
	int				wsc_m5_cnt;
	int				wsc_m6_cnt;
	int				wsc_m7_cnt;
	int				wsc_m8_cnt;
	char    		m2_msg_buf[ M2_SIZE ];
	int				m2_msg_len;
	char    		enrollee_nonce[ WPS_NONCE_LEN ];
	char    		registrar_nonce[ WPS_NONCE_LEN ];
	unsigned char   wps_uuid_e_buf[ WPS_UUID_LEN ];	/* hack: copy to buff, where it can be retrieved later */
	char			wps_handshaking_done;
	char			use_push_button_mode;
} wps_message_monitor;

#endif


 typedef struct {
  char *devicePIN;
  char *manufacturer;
  char *modelName; 
  char *modelNumber;
  char *serialNumber;
  char *deviceName;
  unsigned char *primaryDeviceType;
  int primaryDeviceType_len;
  unsigned char *macAddress;
  int macAddress_len;
  unsigned char *uuid;
  int uuid_len;
  unsigned char *OSVersion;
  int OSVersion_len;
  unsigned char *pubKey;
  int pubKey_len;
  int configMethods;
  int RFBands;
} hostapd_wps_registrar_info;

int hostapd_debug_print_timestamp(char * tbuff);
void hostapd_printf(const char *fmt, ...);
void hostapd_hexdump(const char *title, const unsigned char *buf, size_t len);

int hostapd_sleep( unsigned int amount_of_100msecs );
int hostapd_input_pin_to_wps( const char *pin_code );
//unsigned char *hostapd_base64_encode(const unsigned char *src,size_t len,size_t *out_len);
void hostapd_base64_encode(int	 				in_len,
						  const unsigned char	*in_ptr,
						  int 					*out_len,
						  unsigned char			*out_ptr,
						  int	 				max_out_len );
//unsigned char *hostapd_base64_decode(const unsigned char *src,size_t len,size_t *out_len);
void hostapd_base64_decode(	int					b64_msg_len,
							const unsigned char	*b64_msg,
							int 				*out_len,
							unsigned char		*bin_out_message,
							int		 			max_b64_len );
int hostapd_iface_init(hostapd_wps_registrar_info *info);
int hostapd_iface_delete(void);
void hostapd_create_registrar_state_machine(int *error);
int hostapd_start_registrar_state_machine(const char	*pin_code );
int hostapd_update_registrar_state_machine(
						 unsigned char* received_message,
						 int received_message_len,
						 unsigned char** next_message,
						 int* next_message_len,
						 int* ready);
wps_message_monitor * hostapd_get_wps_counters( void );
int hostapd_construct_ack_mesage( unsigned char * ack_buffer, int *msg_len );
int	hostapd_wsc_nack_received( void );
int	hostapd_wsc_ack_received( void );
int hostapd_is_this_wps_nack_message( unsigned char *binary_message, int outlen );
int hostapd_is_this_wps_ack_message( unsigned char *binary_message, int outlen );
int hostapd_is_authentication_finished( void );
unsigned char *hostapd_get_uuid_e_ptr( void );
void hostapd_push_button_configuration( void );
void hostapd_hmac_sha256(const unsigned char *key, size_t key_len,
				const unsigned char *data, size_t data_len,
				unsigned char *mac);
#endif
