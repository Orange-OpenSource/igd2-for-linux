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
#ifndef HOSTAPD_IFACE_H
#define HOSTAPD_IFACE_H

#ifdef __cplusplus
extern "C" {
#endif

#include	"registrar_state_machine.h"

 typedef struct {
  WPSuRegistrarInput *wpsu_input;
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
  int configMethods; //##003 not needed??
  int RFBands; //##003 not needed??
} hostapd_wps_registrar_info;

int hostapd_debug_print_timestamp(char * tbuff);
void hostapd_printf(const char *fmt, ...);
void hostapd_hexdump(const char *title, const unsigned char *buf, size_t len);

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
WPSuRegistrarSM* hostapd_create_registrar_state_machine(int *error);
int hostapd_start_registrar_state_machine(void			*rsm,
										  const char	*pin_code );
int hostapd_update_registrar_state_machine(void* rsm,
						 unsigned char* received_message,
						 int received_message_len,
						 unsigned char** next_message,
						 int* next_message_len,
						 int* ready);
int hostapd_is_authentication_finished( void );
unsigned char *hostapd_get_uuid_e_ptr( void );
#endif
